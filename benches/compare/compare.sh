#!/bin/sh
# The table of the comparison in benches/README.md: oxirush-security beside the
# implementations of the same functions, on the same inputs: MILENAGE, and
# the six NAS algorithms on a message of 1500 octets.
#
#   benches/compare/compare.sh [core]
#
# The others are fetched at the versions that this directory pins: Cargo
# fetches the milenage crate 0.3.1 and 0.1.6, zuc 0.4.1, cryptography-rs
# 0.8.0 and the RustCrypto aes, ctr and cmac (Cargo.toml), go fetches
# free5GC's nas v1.2.3 and util v1.3.2 (free5gc/go.mod), git fetches Open5GS
# v2.8.0 and meson builds its libraries of NAS security. They are kept in
# target/compare beside this script, or under CARGO_TARGET_DIR.
#
# Each implementation of a case runs once a round, in turns, ROUNDS rounds
# (10 by default) of about 0.3 s each, on one core (3 by default), so that a
# busy moment of the machine falls on all of them. The table has the median
# time of the rounds and their spread, the lowest and the highest; the time
# against oxirush-security is the ratio of the medians, given only where the
# two spreads do not overlap. Cycles and instructions per operation are the
# median of those of perf stat, between a run of N operations and one of 2N
# in each round: PERF="sudo -n perf" where the kernel keeps perf from users
# (kernel.perf_event_paranoid above 2). Needs cargo, go, git, meson, ninja,
# a C compiler and the libraries that the meson setup of Open5GS asks for.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
core=${1:-3}
rounds=${ROUNDS:-10}
perf=${PERF:-perf}
target=${CARGO_TARGET_DIR:-$here/target}
out=$target/compare
mkdir -p "$out"

# The programs.
cd "$here"
cargo build --quiet --release --manifest-path "$here/Cargo.toml"
rust=$target/release/oxirush-security-compare
(cd "$here/free5gc" && go build -buildvcs=false -o "$out/free5gc-security" .)
[ -d "$out/open5gs" ] ||
	git clone --quiet --depth 1 --branch v2.8.0 https://github.com/open5gs/open5gs "$out/open5gs"
[ -d "$out/open5gs-build" ] ||
	meson setup --buildtype=release "$out/open5gs-build" "$out/open5gs" > "$out/meson-setup.log"
meson compile -C "$out/open5gs-build" ogscrypt ogsnas-common > "$out/meson-compile.log"
o=$out/open5gs b=$out/open5gs-build
cc -O2 -std=gnu99 -D_FILE_OFFSET_BITS=64 \
	-I"$o/lib" -I"$b/lib" -I"$o/lib/core" -I"$b/lib/core" -I"$o/lib/proto" -I"$b/lib/proto" \
	-I"$o/lib/crypt" -I"$b/lib/crypt" -I"$o/lib/nas/common" -I"$b/lib/nas/common" \
	-o "$out/open5gs-security" "$here/open5gs/security.c" \
	-L"$b/lib/nas/common" -L"$b/lib/crypt" -L"$b/lib/core" -logsnas-common -logscrypt -logscore \
	-Wl,-rpath,"$b/lib/nas/common:$b/lib/crypt:$b/lib/core:$b/lib/proto"

# The command of an implementation, and its name for a case
program() {
	case $1 in
	free5gc) echo "$out/free5gc-security" ;;
	open5gs) echo "$out/open5gs-security" ;;
	*) echo "$rust $1" ;;
	esac
}
name() { # implementation case
	case $1:$2 in
	oxirush-security:*) echo "oxirush-security" ;;
	milenage-*) echo "milenage $(echo $1 | cut -d- -f2)" ;;
	zuc:*) echo "zuc 0.4.1" ;;
	cryptography-rs:nea1) echo "cryptography-rs 0.8.0, Snow3g" ;;
	cryptography-rs-ct:nea1) echo "cryptography-rs 0.8.0, Snow3gCt" ;;
	cryptography-rs:nea3) echo "cryptography-rs 0.8.0, Zuc128" ;;
	cryptography-rs-ct:nea3) echo "cryptography-rs 0.8.0, Zuc128Ct" ;;
	rustcrypto:nea2) echo "aes 0.8.4, ctr 0.9.2" ;;
	rustcrypto:nia2) echo "aes 0.8.4, cmac 0.7.2" ;;
	open5gs:*) echo "Open5GS v2.8.0" ;;
	free5gc:av) echo "free5GC util v1.3.2" ;;
	free5gc:*) echo "free5GC nas v1.2.3" ;;
	esac
}
implementations() { # case
	case $1 in
	av) echo "oxirush-security milenage-0.3.1 milenage-0.1.6 open5gs free5gc" ;;
	nea1) echo "oxirush-security cryptography-rs cryptography-rs-ct open5gs free5gc" ;;
	nea2 | nia2) echo "oxirush-security rustcrypto open5gs free5gc" ;;
	nea3) echo "oxirush-security zuc cryptography-rs cryptography-rs-ct open5gs free5gc" ;;
	nia1) echo "oxirush-security open5gs free5gc" ;;
	nia3) echo "oxirush-security zuc open5gs free5gc" ;;
	esac
}
operation() {
	case $1 in
	av) echo "MILENAGE, an authentication vector" ;;
	nea1) echo "128-NEA1 (SNOW 3G), 1500 octets" ;;
	nea2) echo "128-NEA2 (AES-CTR), 1500 octets" ;;
	nea3) echo "128-NEA3 (ZUC), 1500 octets" ;;
	nia1) echo "128-NIA1 (SNOW 3G), 1500 octets" ;;
	nia2) echo "128-NIA2 (AES-CMAC), 1500 octets" ;;
	nia3) echo "128-NIA3 (ZUC), 1500 octets" ;;
	esac
}

# Cycles and instructions per operation, between a run of N operations and
# one of 2N.
counted() { # command iterations
	for iterations in "$2" $(($2 * 2)); do
		$perf stat -x, -e cycles:u,instructions:u -o "$out/perf" taskset -c "$core" $1 "$iterations" > /dev/null 2>&1
		awk -F, '$3 ~ /^(cycles|instructions)/ { printf "%s ", $1 }' "$out/perf"
		echo
	done | awk -v n="$2" 'NR == 1 { c = $1; i = $2 } NR == 2 { printf "%.0f %.0f", ($1 - c) / n, ($2 - i) / n }'
}

cases="av nea1 nea2 nea3 nia1 nia2 nia3"
rows=$out/rows
: > "$rows"
echo "$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ //'), core $core, $rounds rounds; load before: $(cut -d' ' -f1-3 /proc/loadavg)"
# The iterations of each run: about 0.3 s, from the time of 200 operations
for case in $cases; do
	for implementation in $(implementations $case); do
		one=$(taskset -c "$core" $(program $implementation) $case 200 2> /dev/null | cut -d' ' -f1)
		echo "$case $implementation $(awk -v ns="$one" 'BEGIN { n = int(3e8 / ns); print (n < 200 ? 200 : (n > 2000000 ? 2000000 : n)) }')"
	done
done > "$out/iterations"
round=0
while [ "$round" -lt "$rounds" ]; do
	while read -r case implementation iterations; do
		command="$(program $implementation) $case"
		# ns, allocations, octets allocated, peak KiB, cycles, instructions
		set -- $(taskset -c "$core" $command "$iterations" 2> /dev/null) $(counted "$command" "$iterations" 2> /dev/null || echo - -)
		echo "$case|$implementation|$1|$2|$3|$4|$5|$6" >> "$rows"
	done < "$out/iterations"
	round=$((round + 1))
done

echo
echo "| Operation | | ns | Lowest and highest | Cycles | Instructions | Allocations | Octets allocated | Peak memory | Time against oxirush-security |"
echo "|---|---|---|---|---|---|---|---|---|---|"
for case in $cases; do
	for implementation in $(implementations $case); do
		row=""
		[ $implementation = oxirush-security ] && row=$(operation $case)
		awk -F'|' -v wanted="$case" -v implementation="$implementation" -v row="$row" -v name="$(name $implementation $case)" '
			function median(list, count,    sorted, i, j, t) {
				for (i = 1; i <= count; i++) sorted[i] = list[i]
				for (i = 2; i <= count; i++)
					for (j = i; j > 1 && sorted[j - 1] + 0 > sorted[j] + 0; j--) {
						t = sorted[j]; sorted[j] = sorted[j - 1]; sorted[j - 1] = t
					}
				return count % 2 ? sorted[(count + 1) / 2] : (sorted[count / 2] + sorted[count / 2 + 1]) / 2
			}
			$1 != wanted { next }
			$2 == "oxirush-security" { ours[++o] = $3; if (o == 1 || $3 < ourlow) ourlow = $3; if (o == 1 || $3 > ourhigh) ourhigh = $3 }
			$2 == implementation {
				n++; ns[n] = $3; allocations[n] = $4; octets[n] = $5; peak[n] = $6; cycles[n] = $7; instructions[n] = $8
				if (n == 1 || $3 < low) low = $3
				if (n == 1 || $3 > high) high = $3
			}
			END {
				m = median(ns, n)
				ratio = ""
				if (implementation != "oxirush-security")
					ratio = (low > ourhigh || high < ourlow) ? sprintf("%.2f", m / median(ours, o)) : "spreads overlap"
				format = m < 1000 ? "%.1f" : "%.0f"
				printf "| %s | %s | " format " | " format " to " format " | %s | %s | %s | %s | %.1f MiB | %s |\n", row, name, m, low, high,
					cycles[1] == "-" ? "-" : sprintf("%.0f", median(cycles, n)),
					instructions[1] == "-" ? "-" : sprintf("%.0f", median(instructions, n)),
					median(allocations, n), median(octets, n), median(peak, n) / 1024, ratio
			}' "$rows"
	done
done
echo
echo "load after: $(cut -d' ' -f1-3 /proc/loadavg)"
