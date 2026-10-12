/*
   OxiRush
   Copyright 2025-2026 Valentin D'Emmanuele

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

//! SNOW 3G and ZUC written with the vector operations of an architecture.
//!
//! [`algorithms!`] expands in the module of each architecture, with the
//! instruction sets that its functions are compiled for. The functions are
//! safe: they call the operations of that module, which are compiled for
//! the same instructions, and nothing else of the processor.
//!
//! What makes them faster than the scalar code, with the same property
//! that no branch and no address depends on a secret:
//!
//! - An S-box is read with shuffles, whose index is an operand. A table of
//!   256 octets is sixteen rows: the low nibble picks an octet of every
//!   row and the high nibble, compared with the number of each row, keeps
//!   one of them.
//! - S1 of SNOW 3G and the S-box of AES inside S1 of ZUC are the AES
//!   instruction.
//! - SNOW 3G is clocked three times at once. Its FSM registers of the next
//!   three clocks need S1 and S2 of words that the state already holds, or
//!   that one of them gives, so one pass over the rows of SQ serves three
//!   clocks; and the LFSR words of the next three clocks depend on stages
//!   that exist.

macro_rules! algorithms {
    ($features:literal) => {
        use crate::common::simd::tables::*;
        use crate::common::simd::{AesSchedule, Snow3g, Zuc};
        use crate::common::zuc::mod31;

        /// The low and the high nibble of each octet.
        #[inline]
        #[target_feature(enable = $features)]
        fn nibbles(octets: V) -> (V, V) {
            let low = splat8(0x0f);
            (and(octets, low), and(shr16::<4>(octets), low))
        }

        /// S2 of each word: SQ on its octets, then the MixColumn of
        /// SNOW 3G, as the scalar `s2` computes it.
        #[inline]
        #[target_feature(enable = $features)]
        fn snow3g_s2(words: V) -> V {
            // Of each row the octet that the low nibble picks, kept in the
            // row whose number is the high nibble, then the sixteen
            // gathered two by two
            let (low, high) = nibbles(words);
            let mut found = [zero(); 16];
            for (number, row) in SQ_ROWS.iter().enumerate() {
                let of_row = shuffle(from_octets(*row), low);
                found[number] = and(of_row, eq8(high, splat8(number as u8)));
            }
            let mut rows = 16;
            while rows > 1 {
                rows /= 2;
                for pair in 0..rows {
                    found[pair] = or(found[2 * pair], found[2 * pair + 1]);
                }
            }
            let r = found[0];
            // Each octet times x modulo x^8 + x^6 + x^5 + x^3 + 1
            let doubled = xor(double8(r), and(negative8(r), splat8(0x69)));
            let rotated = xor(
                shuffle(xor(doubled, r), from_octets(ROTATE_RIGHT_8)),
                xor(
                    shuffle(r, from_octets(ROTATE_LEFT_8)),
                    shuffle(r, from_octets(ROTATE_16)),
                ),
            );
            xor(doubled, rotated)
        }

        /// S1 of each word: the round of AES on the column that the word
        /// is, once ShiftRows has gathered its octets.
        #[inline]
        #[target_feature(enable = $features)]
        fn snow3g_s1(words: V) -> V {
            aes_round(shuffle(words, from_octets(INVERSE_SHIFT_ROWS)))
        }

        /// MULα or DIVα of the octet that fills each word of `octets`.
        #[inline]
        #[target_feature(enable = $features)]
        fn snow3g_alpha(octets: V, digits: &[[u8; 16]; 4]) -> V {
            // Four times a two-bit digit, plus the number of the octet
            // within the word, indexes the word of the digit
            let entry = |digit: V| or(and(digit, splat8(0x0c)), from_octets(OCTET_OF_WORD));
            let mut word = shuffle(from_octets(digits[0]), entry(shl16::<2>(octets)));
            word = xor(word, shuffle(from_octets(digits[1]), entry(octets)));
            word = xor(
                word,
                shuffle(from_octets(digits[2]), entry(shr16::<2>(octets))),
            );
            xor(
                word,
                shuffle(from_octets(digits[3]), entry(shr16::<4>(octets))),
            )
        }

        /// The S-boxes of ZUC on each word: S0 on its first and its third
        /// octet from the high one, S1 on the others.
        #[inline]
        #[target_feature(enable = $features)]
        fn zuc_sboxes(words: V) -> V {
            let (low, high) = nibbles(words);

            // S0: two rounds that each add to one nibble a four-bit S-box
            // of the other, and the two tables that end it
            let q1 = xor(high, shuffle(from_octets(ZUC_P1), low));
            let q2 = xor(low, shuffle(from_octets(ZUC_P2), q1));
            let s0 = xor(
                shuffle(from_octets(ZUC_S0_OF_Q1), q1),
                shuffle(from_octets(ZUC_S0_OF_Q2), q2),
            );

            // S1: the S-box of AES between two linear maps. The last round
            // of AES is its S-box and ShiftRows, which the shuffle undoes
            // beforehand.
            let inner = xor(
                shuffle(from_octets(ZUC_S1_IN.0), low),
                shuffle(from_octets(ZUC_S1_IN.1), high),
            );
            let inner = aes_last_round(shuffle(inner, from_octets(INVERSE_SHIFT_ROWS)));
            let (low, high) = nibbles(inner);
            let s1 = xor(
                shuffle(from_octets(ZUC_S1_OUT.0), low),
                shuffle(from_octets(ZUC_S1_OUT.1), high),
            );

            xor(s1, and(xor(s0, s1), from_octets(ZUC_S0_OCTETS)))
        }

        // ── SNOW 3G ───────────────────────────────────────────────────────────

        /// Three clocks of SNOW 3G. `feedback` is all ones for a clock of
        /// the initialization, whose FSM word goes into the LFSR, and zero
        /// for a clock that gives a keystream word. The three words are
        /// those of the keystream; that of an initialization clock means
        /// nothing.
        #[inline]
        #[target_feature(enable = $features)]
        fn snow3g_clock3(state: &mut Snow3g, feedback: [u32; 3]) -> [u32; 3] {
            // The sixteen stages are a window of the array, which moves by
            // three: it starts over when the next three would not fit
            if state.at > 13 {
                state.lfsr.copy_within(state.at..state.at + 16, 0);
                state.at = 0;
            }
            let at = state.at;
            let s = &state.lfsr[at..at + 16];

            // The LFSR words of four clocks: α s0 + s2 + α^-1 s11, with
            // s1, s3 and s12 for the second clock, and so on. None of
            // these stages is a word of these clocks.
            let low = from_words([s[0], s[1], s[2], s[3]]);
            let high = from_words([s[11], s[12], s[13], s[14]]);
            let v = xor(
                xor(shl32::<8>(low), shr32::<8>(high)),
                from_words([s[2], s[3], s[4], s[5]]),
            );
            let v = xor(
                v,
                snow3g_alpha(shuffle(low, from_octets(HIGH_OCTETS)), &MUL_ALPHA),
            );
            let v = xor(
                v,
                snow3g_alpha(shuffle(high, from_octets(LOW_OCTETS)), &DIV_ALPHA),
            );
            let v = to_words(v);

            // The FSM: R1, R2 and R3 at the three clocks and after them.
            // R2 is S1 of the R1 before it and R3 is S2 of the R2 before
            // it; R1 takes R2, R3 and s5 of the clock before.
            let [r1_0, r2_0, r3_0] = state.r;
            let r1_1 = r2_0.wrapping_add(r3_0 ^ s[5]);
            let [r2_1, r2_2, ..] = to_words(snow3g_s1(from_words([r1_0, r1_1, 0, 0])));
            let [r3_1, r3_2, r3_3, _] = to_words(snow3g_s2(from_words([r2_0, r2_1, r2_2, 0])));
            let r1_2 = r2_1.wrapping_add(r3_1 ^ s[6]);
            let r1_3 = r2_2.wrapping_add(r3_2 ^ s[7]);
            let [r2_3, ..] = to_words(snow3g_s1(from_words([r1_2, 0, 0, 0])));

            // The FSM word of each clock takes s15, which after the first
            // clock is the stage that the clock before made
            let f0 = s[15].wrapping_add(r1_0) ^ r2_0;
            let s16 = v[0] ^ (f0 & feedback[0]);
            let f1 = s16.wrapping_add(r1_1) ^ r2_1;
            let s17 = v[1] ^ (f1 & feedback[1]);
            let f2 = s17.wrapping_add(r1_2) ^ r2_2;
            let s18 = v[2] ^ (f2 & feedback[2]);
            let words = [f0 ^ s[0], f1 ^ s[1], f2 ^ s[2]];

            state.lfsr[at + 16..at + 19].copy_from_slice(&[s16, s17, s18]);
            state.at = at + 3;
            state.r = [r1_3, r2_3, r3_3];
            words
        }

        /// SNOW 3G from its sixteen stages after the key and the IV are
        /// loaded: the 32 clocks of the initialization, and the clock
        /// whose word TS 35.216 discards.
        #[target_feature(enable = $features)]
        pub(super) fn snow3g_new(stages: [u32; 16]) -> Snow3g {
            let mut state = Snow3g {
                lfsr: [0; 32],
                at: 0,
                r: [0; 3],
                ready: [0; 3],
                pending: 0,
            };
            state.lfsr[..16].copy_from_slice(&stages);
            for _ in 0..10 {
                snow3g_clock3(&mut state, [u32::MAX; 3]);
            }
            snow3g_clock3(&mut state, [u32::MAX, u32::MAX, 0]);
            state
        }

        /// The next keystream words of SNOW 3G.
        #[target_feature(enable = $features)]
        pub(super) fn snow3g_fill(state: &mut Snow3g, mut words: &mut [u32]) {
            // The words that the last call made and did not give
            while state.pending > 0 {
                let Some((word, rest)) = words.split_first_mut() else {
                    return;
                };
                *word = state.ready[3 - state.pending];
                state.pending -= 1;
                words = rest;
            }
            let (triples, rest) = words.as_chunks_mut::<3>();
            for triple in triples {
                *triple = snow3g_clock3(state, [0; 3]);
            }
            if !rest.is_empty() {
                state.ready = snow3g_clock3(state, [0; 3]);
                rest.copy_from_slice(&state.ready[..rest.len()]);
                state.pending = 3 - rest.len();
            }
        }

        // ── ZUC ───────────────────────────────────────────────────────────────

        /// R1 and R2 of ZUC after a clock, from R1 and R2, in the first
        /// two words of `r`, and from X1 and X2: S(L1(W1L || W2H)) and
        /// S(L2(W2L || W1H)), with W1 = R1 + X1 and W2 = R2 xor X2.
        ///
        /// It stays in a vector register from R to R, which is what every
        /// clock waits for.
        #[inline]
        #[target_feature(enable = $features)]
        fn zuc_registers(r: V, x1: u32, x2: u32) -> V {
            let w = xor(
                add32(r, from_words([x1, 0, 0, 0])),
                from_words([0, x2, 0, 0]),
            );
            let halves = shuffle(w, from_octets(ZUC_HALVES));
            // L1 rotates by 2, 10, 18 and 24 bits and L2 by 8, 14, 22 and
            // 30: the first word rotated by 2 and the second by 6, then
            // whole octets, which are shuffles
            let by_2 = or(shl32::<2>(halves), shr32::<30>(halves));
            let by_6 = or(shl32::<6>(halves), shr32::<26>(halves));
            let bits = xor(by_2, and(xor(by_2, by_6), from_octets(SECOND_WORD)));
            let linear = xor(
                xor(halves, shuffle(halves, from_octets(ZUC_L_OF_WORD))),
                xor(
                    shuffle(bits, from_octets(ZUC_L_OF_BITS[0])),
                    xor(
                        shuffle(bits, from_octets(ZUC_L_OF_BITS[1])),
                        shuffle(bits, from_octets(ZUC_L_OF_BITS[2])),
                    ),
                ),
            );
            zuc_sboxes(linear)
        }

        /// One clock of ZUC: the word of the nonlinear function, added to
        /// X3, and R1 and R2 after it. In the initialization the word goes
        /// into the LFSR.
        #[inline]
        #[target_feature(enable = $features)]
        fn zuc_clock(state: &mut Zuc, r: V, initialization: bool) -> (u32, V) {
            // The sixteen stages are a window of the array, which moves by
            // one: it starts over at the end
            if state.at == 16 {
                state.lfsr.copy_within(16.., 0);
                state.at = 0;
            }
            let at = state.at;
            let s = &state.lfsr[at..at + 16];

            // Bit reorganization
            let x0 = ((s[15] & 0x7fff_8000) << 1) | (s[14] & 0xffff);
            let x1 = ((s[11] & 0xffff) << 16) | (s[9] >> 15);
            let x2 = ((s[7] & 0xffff) << 16) | (s[5] >> 15);
            let x3 = ((s[2] & 0xffff) << 16) | (s[0] >> 15);

            // The nonlinear function
            let [r1, r2, ..] = to_words(r);
            let w = (x0 ^ r1).wrapping_add(r2);
            let r = zuc_registers(r, x1, x2);

            // The LFSR: 2^15 s15 + 2^17 s13 + 2^21 s10 + 2^20 s4 +
            // (1 + 2^8) s0 modulo 2^31 - 1
            let stage = |index: usize, shift: u32| u64::from(s[index]) << shift;
            let mut sum = stage(15, 15)
                + stage(13, 17)
                + stage(10, 21)
                + stage(4, 20)
                + stage(0, 8)
                + stage(0, 0);
            if initialization {
                sum += u64::from(w >> 1);
            }

            state.lfsr[at + 16] = mod31(sum);
            state.at = at + 1;
            (w ^ x3, r)
        }

        /// ZUC from its sixteen stages after the key and the IV are
        /// loaded: the 32 clocks of the initialization, and the clock
        /// whose word TS 35.222 discards.
        #[target_feature(enable = $features)]
        pub(super) fn zuc_new(stages: [u32; 16]) -> Zuc {
            let mut state = Zuc {
                lfsr: [0; 32],
                at: 0,
                r: [0; 2],
            };
            state.lfsr[..16].copy_from_slice(&stages);
            let mut r = zero();
            // The number of clocks goes through `black_box` so that the
            // compiler keeps the loop: unrolled, it is 17 kilobytes of code
            for _ in 0..core::hint::black_box(32) {
                (_, r) = zuc_clock(&mut state, r, true);
            }
            (_, r) = zuc_clock(&mut state, r, false);
            let [r1, r2, ..] = to_words(r);
            state.r = [r1, r2];
            state
        }

        /// The next keystream words of ZUC.
        #[target_feature(enable = $features)]
        pub(super) fn zuc_fill(state: &mut Zuc, words: &mut [u32]) {
            let mut r = from_words([state.r[0], state.r[1], 0, 0]);
            for word in words {
                (*word, r) = zuc_clock(state, r, false);
            }
            let [r1, r2, ..] = to_words(r);
            state.r = [r1, r2];
        }

        // ── The two MACs over a keystream ─────────────────────────────────────

        /// The carry-less product of two words, low word then high word.
        #[inline]
        #[target_feature(enable = $features)]
        fn clmul(x: u64, y: u64) -> (u64, u64) {
            to_u64s(clmul_low(from_u64(x), from_u64(y)))
        }

        /// 128-EIA3 over groups of 32 bits of a message that are whole:
        /// for each, the next keystream word comes into the window, and
        /// the set bits of the group take the keystream words at their
        /// positions, which add up to one carry-less product.
        ///
        /// Four groups are sixteen octets of the message. With the bits
        /// of each octet reversed, a word of them with its low octet first
        /// is a group with its bits reversed; and the windows of the four
        /// are the five keystream words around them, two by two. The four
        /// products are added as they are, and the tag takes the sum.
        #[target_feature(enable = $features)]
        pub(super) fn eia3_groups(
            mut tag: u32,
            mut window: u64,
            groups: &[[u8; 4]],
            words: &[u32],
        ) -> (u32, u64) {
            let one = |tag: u32, window: u64, group: &[u8; 4], word: u32| {
                let window = (window << 32) | u64::from(word);
                let bits = u64::from(u32::from_be_bytes(*group).reverse_bits());
                (tag ^ (clmul(bits, window).0 >> 32) as u32, window)
            };
            let count = groups.len().min(words.len());
            let (groups, words) = (&groups[..count], &words[..count]);
            // The first group: its window has a word from before `words`
            let Some((first, groups)) = groups.split_first() else {
                return (tag, window);
            };
            (tag, window) = one(tag, window, first, words[0]);

            let (fours, last) = groups.as_chunks::<4>();
            let mut sum = zero();
            for (four, z) in fours.iter().zip(words.windows(5).step_by(4)) {
                // The windows of the first and of the third group, then
                // those of the second and of the fourth
                let exchanged = from_octets(EXCHANGED_WORDS);
                let odd = shuffle(from_words([z[0], z[1], z[2], z[3]]), exchanged);
                let even = shuffle(from_words([z[1], z[2], z[3], z[4]]), exchanged);

                let (low, high) = nibbles(from_words(four.map(u32::from_le_bytes)));
                let bits = or(
                    shuffle(from_octets(REVERSED_BITS.0), low),
                    shuffle(from_octets(REVERSED_BITS.1), high),
                );
                let group = |index: usize| shuffle(bits, from_octets(WORD_ALONE[index]));
                sum = xor(
                    xor(
                        sum,
                        xor(clmul_low(odd, group(0)), clmul_low(even, group(1))),
                    ),
                    xor(
                        clmul_high_low(odd, group(2)),
                        clmul_high_low(even, group(3)),
                    ),
                );
            }
            tag ^= (to_u64s(sum).0 >> 32) as u32;
            let done = 1 + 4 * fours.len();
            if !fours.is_empty() {
                window = (u64::from(words[done - 2]) << 32) | u64::from(words[done - 1]);
            }
            for (group, word) in last.iter().zip(&words[done..]) {
                (tag, window) = one(tag, window, group, *word);
            }
            (tag, window)
        }

        /// 128-EIA1 over the blocks of 64 bits of a message, the last of
        /// which is `last`: the evaluation at P of the polynomial whose
        /// coefficients they are, times P.
        ///
        /// Block by block, the evaluation takes a block and is multiplied
        /// by P, and each multiplication waits for the one before it. Four
        /// blocks b0 to b3 after an evaluation E give
        /// (E + b0) P^4 + b1 P^3 + b2 P^2 + b3 P, four products that wait
        /// for nothing but E. Their sum is kept as it is, of 127 bits: its
        /// high half times x^64 P^4 is added the next time, and it is
        /// reduced once, at the end.
        #[target_feature(enable = $features)]
        pub(super) fn eia1_blocks(p: u64, blocks: &[[u8; 8]], last: Option<u64>) -> u64 {
            use crate::common::nia::reduce64;
            let multiply = |a: u64, b: u64| {
                let (low, high) = clmul(a, b);
                reduce64(low, high)
            };
            let (fours, rest) = blocks.as_flattened().as_chunks::<32>();
            // The blocks after the last four, at most four with `last`
            let rest = rest.as_chunks::<8>().0;
            let mut tail = [0u64; 4];
            let mut blocks_of_tail = 0;
            for block in rest
                .iter()
                .map(|block| u64::from_be_bytes(*block))
                .chain(last)
            {
                tail[blocks_of_tail] = block;
                blocks_of_tail += 1;
            }
            let tail = &tail[..blocks_of_tail];

            // The powers of P are three multiplications: a few blocks are
            // sooner done one by one
            if fours.is_empty() && tail.len() < 4 {
                return tail
                    .iter()
                    .fold(0, |evaluation, block| multiply(evaluation ^ block, p));
            }
            let p2 = multiply(p, p);
            let powers = [p, p2, multiply(p2, p), multiply(p2, p2)];
            // x^64 P^k, reduced
            let high_powers = powers.map(|power| from_u64(reduce64(0, power)));
            let powers = powers.map(|power| from_u64(power));

            // Four blocks are two vectors, a block in each half. The first
            // block is added to the low half of the sum.
            let mut sum = zero();
            for four in fours {
                let (halves, _) = four.as_chunks::<16>();
                let reversed = from_octets(REVERSED_HALVES);
                let first = shuffle(from_octets(halves[0]), reversed);
                let second = shuffle(from_octets(halves[1]), reversed);
                sum = xor(
                    xor(
                        clmul_low(xor(sum, first), powers[3]),
                        clmul_high_low(sum, high_powers[3]),
                    ),
                    xor(
                        xor(
                            clmul_high_low(first, powers[2]),
                            clmul_low(second, powers[1]),
                        ),
                        clmul_high_low(second, powers[0]),
                    ),
                );
            }
            // The blocks of the tail, with the powers that are left
            if let Some((first, others)) = tail.split_first() {
                let count = tail.len();
                let mut next = xor(
                    clmul_low(xor(sum, from_u64(*first)), powers[count - 1]),
                    clmul_high_low(sum, high_powers[count - 1]),
                );
                for (block, power) in others.iter().zip(powers[..count - 1].iter().rev()) {
                    next = xor(next, clmul_low(from_u64(*block), *power));
                }
                sum = next;
            }
            let (low, high) = to_u64s(sum);
            reduce64(low, high)
        }

        // ── AES-128 for several keys at once ──────────────────────────────────

        /// A block or a round key, whose first octet is the low one of
        /// the number, as a vector, and back.
        #[inline]
        #[target_feature(enable = $features)]
        fn from_u128(block: u128) -> V {
            from_u64s(block as u64, (block >> 64) as u64)
        }

        #[inline]
        #[target_feature(enable = $features)]
        fn to_u128(vector: V) -> u128 {
            let (low, high) = to_u64s(vector);
            (u128::from(high) << 64) | u128::from(low)
        }

        /// The round keys of each key (FIPS 197 §5.2), the expansions side
        /// by side. A round key is the one before it with each word added
        /// to the words below it, and SubWord(RotWord(w3)) with the round
        /// constant added to all four. The last round of AES on a state
        /// whose four columns are RotWord(w3) is SubWord of it in every
        /// column: ShiftRows moves nothing between equal columns.
        #[target_feature(enable = $features)]
        pub(super) fn aes_schedules<const N: usize>(
            keys: [&[u8; 16]; N],
            schedules: &mut [AesSchedule; N],
        ) {
            let mut round_keys = [zero(); N];
            for ((round_key, schedule), key) in
                round_keys.iter_mut().zip(schedules.iter_mut()).zip(keys)
            {
                *round_key = from_octets(*key);
                schedule[0] = to_u128(*round_key);
            }
            for (round, constant) in AES_ROUND_CONSTANTS.into_iter().enumerate() {
                for (round_key, schedule) in round_keys.iter_mut().zip(schedules.iter_mut()) {
                    let last = shuffle(*round_key, from_octets(AES_ROTATED_LAST_WORD));
                    let substituted = xor(aes_last_round(last), from_words([constant; 4]));
                    let sums = xor(
                        xor(
                            *round_key,
                            shuffle(*round_key, from_octets(WORDS_MOVED_UP[0])),
                        ),
                        xor(
                            shuffle(*round_key, from_octets(WORDS_MOVED_UP[1])),
                            shuffle(*round_key, from_octets(WORDS_MOVED_UP[2])),
                        ),
                    );
                    *round_key = xor(sums, substituted);
                    schedule[round + 1] = to_u128(*round_key);
                }
            }
        }

        /// Each state encrypted with its round keys, a round of all of
        /// them at a time: the processor runs the rounds of several states
        /// together.
        #[inline]
        #[target_feature(enable = $features)]
        fn aes_states<const N: usize>(schedules: [&AesSchedule; N], mut states: [V; N]) -> [V; N] {
            for (state, schedule) in states.iter_mut().zip(schedules) {
                *state = xor(*state, from_u128(schedule[0]));
            }
            for round in 1..10 {
                for (state, schedule) in states.iter_mut().zip(schedules) {
                    *state = aes_round_key(*state, from_u128(schedule[round]));
                }
            }
            for (state, schedule) in states.iter_mut().zip(schedules) {
                *state = aes_last_round_key(*state, from_u128(schedule[10]));
            }
            states
        }

        /// Encrypt each block with its round keys.
        #[target_feature(enable = $features)]
        pub(super) fn aes_encrypt<const N: usize>(
            schedules: [&AesSchedule; N],
            blocks: &mut [u128; N],
        ) {
            let mut states = [zero(); N];
            for (state, block) in states.iter_mut().zip(blocks.iter()) {
                *state = from_u128(*block);
            }
            let states = aes_states(schedules, states);
            for (block, state) in blocks.iter_mut().zip(states) {
                *block = to_u128(state);
            }
        }

        /// The CBC-MAC of each message with its round keys: its block
        /// `first`, if it has one, the blocks of its `body` and its block
        /// `last`. The chains advance together, a block of each at a time.
        /// A chain that has no block at a step is encrypted with the
        /// others, and what that gives is not used: its state after its
        /// body was put aside.
        #[target_feature(enable = $features)]
        pub(super) fn aes_cbc_mac<const N: usize>(
            schedules: [&AesSchedule; N],
            first: [Option<u128>; N],
            body: [&[[u8; 16]]; N],
            last: &[u128; N],
        ) -> [u128; N] {
            let mut states = [zero(); N];
            if first.iter().any(Option::is_some) {
                let mut blocks = [zero(); N];
                for (block, first) in blocks.iter_mut().zip(first) {
                    if let Some(first) = first {
                        *block = from_u128(first);
                    }
                }
                let encrypted = aes_states(schedules, blocks);
                for ((state, encrypted), first) in states.iter_mut().zip(encrypted).zip(first) {
                    if first.is_some() {
                        *state = encrypted;
                    }
                }
            }

            // The state of each chain after its body
            let mut after_body = states;
            let steps = body.iter().map(|body| body.len()).max().unwrap_or(0);
            for step in 0..steps {
                for (state, body) in states.iter_mut().zip(body) {
                    if let Some(block) = body.get(step) {
                        *state = xor(*state, from_octets(*block));
                    }
                }
                states = aes_states(schedules, states);
                for ((after_body, state), body) in after_body.iter_mut().zip(states).zip(body) {
                    if step + 1 == body.len() {
                        *after_body = state;
                    }
                }
            }

            for (state, last) in after_body.iter_mut().zip(last) {
                *state = xor(*state, from_u128(*last));
            }
            let mut macs = [0; N];
            for (mac, state) in macs.iter_mut().zip(aes_states(schedules, after_body)) {
                *mac = to_u128(state);
            }
            macs
        }

        /// The counter block of 128-EEA2 with the number `number`, after
        /// the eight octets of `prefix`.
        #[inline]
        #[target_feature(enable = $features)]
        fn counter_block(prefix: u64, number: u64) -> V {
            from_u128(u128::from(prefix) | (u128::from(number.swap_bytes()) << 64))
        }

        /// AES in counter mode on one message: eight counter blocks are
        /// encrypted at a time.
        #[target_feature(enable = $features)]
        pub(super) fn aes_ctr(schedule: &AesSchedule, prefix: u64, data: &mut [u8]) {
            let (blocks, end) = data.as_chunks_mut::<16>();
            let (eights, last) = blocks.as_chunks_mut::<8>();
            let keystream = |first: u64| {
                let mut counters = [zero(); 8];
                for (counter, number) in counters.iter_mut().zip(first..) {
                    *counter = counter_block(prefix, number);
                }
                aes_states([schedule; 8], counters)
            };
            let with_keystream = |block: &mut [u8; 16], keystream: V| {
                *block = to_u128(xor(from_octets(*block), keystream)).to_le_bytes();
            };
            let mut number = 0;
            for eight in eights {
                for (block, keystream) in eight.iter_mut().zip(keystream(number)) {
                    with_keystream(block, keystream);
                }
                number += 8;
            }
            // The blocks after the last eight, and the octets after the
            // last block
            if !last.is_empty() || !end.is_empty() {
                let keystream = keystream(number);
                for (block, keystream) in last.iter_mut().zip(keystream) {
                    with_keystream(block, keystream);
                }
                let of_end = to_u128(keystream[last.len()]).to_le_bytes();
                for (octet, key_octet) in end.iter_mut().zip(of_end) {
                    *octet ^= key_octet;
                }
            }
        }

        /// The carry-less product of two words, for the caller that is
        /// not compiled for the instruction.
        #[target_feature(enable = $features)]
        pub(super) fn carry_less_product(x: u64, y: u64) -> (u64, u64) {
            clmul(x, y)
        }
    };
}
