#!/usr/bin/env python3
"""Merge the measurements behind Figure 4 and render it.

Inputs (all in plots/):
  prover_time_raw.csv          tallying circuit over BN254, written by TestProverTimePlot (one row per proof)
  maci_time_raw.csv            MACI v3.0.0 on the same machine, per ballot count (maci_totals.py, maci_bench/)
Output: prover_time_total.csv and the figure prover_time_total.{png,pdf} (plot_prover_time.py).

The circuit verifies the CTC openings itself, so the Cast Iron curve is the tallier's whole proving time.

    python3 plots/make_total_plot.py                # the paper's figure: n = 1..512
    python3 plots/make_total_plot.py --with-large   # also the single large proofs over BLS12-381
                                                    # (prover_time_raw_bls12381.csv; another curve, so
                                                    # not directly comparable with the BN254 points)
"""
import csv
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
raw_csv = os.path.join(HERE, "prover_time_raw.csv")
maci_csv = os.path.join(HERE, "maci_time_raw.csv")
pred_csv = os.path.join(HERE, "prover_time_predicted.csv")  # optional: rows marked predicted=1, if any
out_csv = os.path.join(HERE, "prover_time_total.csv")
out_png = os.path.join(HERE, "prover_time_total.png")

bls_csv = os.path.join(HERE, "prover_time_raw_bls12381.csv")  # single-proof runs over BLS12-381

rows = []
for path in [raw_csv] + ([bls_csv] if "--with-large" in sys.argv[1:] else []):
    if not os.path.exists(path):
        continue
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            rows.append((r["ballots"], r["simulated_blockchain_leaves"], r["proof_time_seconds"], 0))
with open(maci_csv, newline="") as f:
    for r in csv.DictReader(f):
        if r["simulated_blockchain_leaves"].strip() == "-1":
            rows.append((r["ballots"], "-1", r["proof_time_seconds"].strip(), 0))
n_pred = 0
if os.path.exists(pred_csv):
    with open(pred_csv, newline="") as f:
        for r in csv.DictReader(f):
            rows.append((r["ballots"], r["simulated_blockchain_leaves"], r["proof_time_seconds"], 1))
            n_pred += 1
with open(out_csv, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["ballots", "simulated_blockchain_leaves", "proof_time_seconds", "predicted"])
    w.writerows(rows)
print(f"wrote {out_csv} ({len(rows)} rows, {n_pred} predicted; MACI rows from {os.path.basename(maci_csv)})")
subprocess.check_call([sys.executable, os.path.join(HERE, "plot_prover_time.py"), out_csv, out_png])
