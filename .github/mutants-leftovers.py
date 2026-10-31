"""Each mutant of a list that `cargo mutants --list --json --diff` wrote, against the
program of leftovers/: the mutant is made in the tree, the program is built and run,
and the tree is put back. A mutant is caught when the program fails, unviable when it
does not build, and missed when it passes. The missed ones are written to
`leftovers-missed.txt`, and the program exits with 1 when there is one.

    python3 .github/mutants-leftovers.py mutants.json
"""

import json
import subprocess
import sys

counts = {"caught": 0, "missed": 0, "unviable": 0}
missed = []
for mutant in json.load(open(sys.argv[1])):
    diff = mutant["diff"].encode()
    file = mutant["file"]
    subprocess.run(["patch", "--quiet", file], input=diff, check=True)
    try:
        cargo = ["cargo", "build", "--release", "--quiet"]
        build = subprocess.run(cargo, cwd="leftovers", stderr=subprocess.DEVNULL)
        if build.returncode != 0:
            outcome = "unviable"
        else:
            cargo = ["cargo", "run", "--release", "--quiet"]
            run = subprocess.run(
                cargo, cwd="leftovers", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            outcome = "caught" if run.returncode != 0 else "missed"
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
