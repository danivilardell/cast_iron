#!/usr/bin/env python3
"""Convert the per-batch MACI timing CSV produced on the benchmark machine
(maci_bench/prove.js: label,repeat,batch,witness_s,prove_s,full_s,nproc, with
label = <MODE>_n<ballots>; kept as plots/maci_batches_raw.csv) into
plots/maci_time_raw.csv, one row per
(ballots, repeat) holding the coordinator's total proving time for that
ballot count: the sum of all MessageProcessor and VoteTally proofs
(snarkjs groth16.fullProve, i.e. witness generation + proving).

    python3 plots/maci_totals.py plots/maci_batches_raw.csv [plots/maci_time_raw.csv]
"""
import csv
import os
import re
import sys
from collections import defaultdict

src = sys.argv[1]
dst = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "maci_time_raw.csv")

totals = defaultdict(float)
batches = defaultdict(set)
with open(src, newline="") as f:
    for r in csv.DictReader(f):
        m = re.match(r".*_n(\d+)$", r["label"])
        if not m:
            continue
        n, rep = int(m.group(1)), int(r["repeat"])
        secs = r["full_s"] or ""
        if secs == "":  # split mode rows: witness + prove
            secs = float(r["witness_s"]) + float(r["prove_s"])
        totals[(n, rep)] += float(secs)
        batches[(n, rep)].add(r["batch"])

with open(dst, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["ballots", "simulated_blockchain_leaves", "proof_time_seconds"])
    for (n, rep) in sorted(totals):
        w.writerow([n, -1, f"{totals[(n, rep)]:.3f}"])
print(f"wrote {dst} ({len(totals)} rows)")
for n in sorted({k[0] for k in totals}):
    v = [totals[k] for k in sorted(totals) if k[0] == n]
    nb = sorted(batches[(n, 1)])
    npb = sum(b.startswith("process") for b in nb)
    print(f"n={n:4d}: {sum(v)/len(v):8.2f} s mean over {len(v)} runs (min {min(v):.2f}, max {max(v):.2f}); "
          f"{npb} process + {len(nb)-npb} tally proofs")
