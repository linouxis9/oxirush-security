"""Each mutant of a list that `cargo mutants --list --json --diff` wrote, against a
program that reads what the crate leaves where it worked: leftovers/, or
emulated-aarch64/ when PROGRAM says so. The mutant is made in the tree, the program
is built and run, and the tree is put back. A mutant is caught when the program
fails, unviable when it does not build, and missed when it passes. The missed ones
are written to `leftovers-missed.txt`, and the program exits with 1 when there is
one, or when the list gives the shard no mutant.

    python3 .github/mutants-leftovers.py mutants.json [SHARD SHARDS [PROGRAM]]

The shard SHARD of SHARDS takes every SHARDS-th mutant from the SHARD-th. PROGRAM is
`leftovers` or `emulated-aarch64`.
"""

import json
import subprocess
import sys

# The builds of each program, each in its directory, then its run.
GUEST = "../guest/target/aarch64-unknown-none/release/oxirush-security-emulated-guest"
PROGRAMS = {
    "leftovers": (
        [("leftovers", ["cargo", "build", "--release", "--quiet"])],
        ("leftovers", ["cargo", "run", "--release", "--quiet"]),
    ),
    "emulated-aarch64": (
        [
            ("emulated-aarch64/guest", ["cargo", "build", "--release", "--quiet"]),
            ("emulated-aarch64/host", ["cargo", "build", "--release", "--quiet"]),
        ],
        ("emulated-aarch64/host", ["cargo", "run", "--release", "--quiet", "--", GUEST]),
    ),
}

counts = {"caught": 0, "missed": 0, "unviable": 0}
missed = []
shard, shards = (int(sys.argv[2]), int(sys.argv[3])) if len(sys.argv) > 3 else (0, 1)
builds, (directory, run) = PROGRAMS[sys.argv[4] if len(sys.argv) > 4 else "leftovers"]
mutants = json.load(open(sys.argv[1]))[shard::shards]
if not mutants:
    sys.exit(f"{sys.argv[1]} gives shard {shard} of {shards} no mutant")
for mutant in mutants:
    diff = mutant["diff"].encode()
    file = mutant["file"]
    subprocess.run(["patch", "--quiet", file], input=diff, check=True)
    try:
        built = all(
            subprocess.run(build, cwd=where, stderr=subprocess.DEVNULL).returncode == 0
            for where, build in builds
        )
        if not built:
            outcome = "unviable"
        else:
            program = subprocess.run(
                run, cwd=directory, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            outcome = "caught" if program.returncode != 0 else "missed"
    finally:
        subprocess.run(["patch", "--quiet", "--reverse", file], input=diff, check=True)
    counts[outcome] += 1
    print(f"{outcome:8} {mutant['name']}", flush=True)
    if outcome == "missed":
        missed.append(mutant["name"])

print(", ".join(f"{count} {outcome}" for outcome, count in counts.items()))
with open("leftovers-missed.txt", "w") as out:
    out.writelines(name + "\n" for name in missed)
sys.exit(1 if missed else 0)
