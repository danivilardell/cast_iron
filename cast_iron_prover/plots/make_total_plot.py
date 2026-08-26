#!/usr/bin/env python3
"""Merge the tallying circuit's raw sweep output (plots/prover_time_raw.csv,
written by TestProverTimePlot; the circuit verifies the CTC openings itself,
so this is the tallier's whole proving time) with the MACI rows of
plots/maci_time_raw.csv (MACI v3.0.0 measured on the same machine, see
plots/maci_totals.py and maci_bench/), plus the extrapolated rows of
plots/prover_time_predicted.csv if present (plots/predict_missing.py), and
write plots/prover_time_total.csv; then render Figure 4 with
plot_prover_time.py.

    python3 plots/make_total_plot.py
"""
import csv
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
raw_csv = os.path.join(HERE, "prover_time_raw.csv")
maci_csv = os.path.join(HERE, "maci_time_raw.csv")
pred_csv = os.path.join(HERE, "prover_time_predicted.csv")  # optional, see predict_missing.py
out_csv = os.path.join(HERE, "prover_time_total.csv")
out_png = os.path.join(HERE, "prover_time_total.png")

rows = []
with open(raw_csv, newline="") as f:
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
