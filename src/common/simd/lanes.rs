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

//! The messages of a batch through generators that run side by side, four
//! or eight of them.
//!
//! A generator works for one message at a time: 32 clocks of
//! initialization, the clock whose word is discarded, then one clock for
//! each keystream word that the message takes. When its message has its
//! words, the generator gets the next message of the batch, while the
//! others go on. All are clocked together, so a clock gives as many
//! keystream words as there are generators past their initialization.
//!
//! What a generator does at a clock depends on the lengths of the messages
//! and on nothing else: neither the time of a message nor its place in the
//! batch depends on the octets or the key of another.

use super::Generators;
use zeroize::Zeroize;

/// The clocks of the initialization of SNOW 3G and of ZUC, and the clock
/// after them whose word both discard.
const INITIALIZATION: usize = 32;
const DISCARDED: usize = 1;

/// How many clocks are run before their words are given to the messages.
const CLOCKS: usize = 32;

/// A message of a batch, as the generators see it.
pub(crate) trait Stream {
    /// The sixteen stages that its key and its IV give.
    fn stages(&self) -> [u32; 16];

    /// How many keystream words it takes.
    fn words(&self) -> usize;

    /// The next words of its keystream, in their order. All the calls
    /// together give [`words`](Self::words) words.
    fn take(&mut self, words: &[u32]);

    /// The message on a generator of its own, which is faster for one that
    /// would run next to idle ones.
    fn alone(self);
}

/// A generator at work: its message, and the clocks that are left of each
/// of the three things it does in turn.
struct Lane<S> {
    stream: S,
    initialization: usize,
    discarded: usize,
    words: usize,
}

impl<S> Lane<S> {
    /// The clocks until the generator does something else.
    fn clocks(&self) -> usize {
        match (self.initialization, self.discarded) {
            (0, 0) => self.words,
            (0, discarded) => discarded,
            (initialization, _) => initialization,
        }
    }
}

/// Give each of `streams` its keystream.
pub(crate) fn run<const N: usize, G: Generators<N>, S: Stream>(
    generators: &mut G,
    streams: impl Iterator<Item = S>,
) {
    let mut streams = streams.filter(|stream| stream.words() > 0).peekable();
    let mut lanes: [Option<Lane<S>>; N] = [const { None }; N];
    let mut words = [[0u32; N]; CLOCKS];
    let mut of_lane = [0u32; CLOCKS];
    loop {
        // An idle generator takes the next message. The last message of
        // the batch does not start next to idle generators.
        for index in 0..N {
            if lanes[index].is_some() {
                continue;
            }
            let Some(stream) = streams.next() else { break };
            if streams.peek().is_none() && lanes.iter().all(Option::is_none) {
                stream.alone();
                break;
            }
            let mut stages = stream.stages();
            generators.load(index, &stages);
            stages.zeroize();
            lanes[index] = Some(Lane {
                initialization: INITIALIZATION,
                discarded: DISCARDED,
                words: stream.words(),
                stream,
            });
        }

        // The clocks until a generator does something else, at most as
        // many as there is room for their words
        let Some(clocks) = lanes.iter().flatten().map(Lane::clocks).min() else {
            break;
        };
        let clocks = clocks.min(CLOCKS);
        let initialization = lanes.each_ref().map(|lane| match lane {
            Some(lane) if lane.initialization > 0 => u32::MAX,
            _ => 0,
        });
        generators.clocks(initialization, &mut words[..clocks]);

        for (index, slot) in lanes.iter_mut().enumerate() {
            let Some(lane) = slot else { continue };
            if lane.initialization > 0 {
                lane.initialization -= clocks;
            } else if lane.discarded > 0 {
                lane.discarded -= clocks;
            } else {
                for (word, of_clock) in of_lane.iter_mut().zip(&words[..clocks]) {
                    *word = of_clock[index];
                }
                lane.stream.take(&of_lane[..clocks]);
                lane.words -= clocks;
                if lane.words == 0 {
                    *slot = None;
                }
            }
        }
    }
    words.zeroize();
    of_lane.zeroize();
    generators.zeroize();
}
