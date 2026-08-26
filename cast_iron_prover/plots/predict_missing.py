#!/usr/bin/env python3
"""Extrapolate prover times for ballot counts that were not measured
(default: 256 and 512) and write them to plots/prover_time_predicted.csv
with predicted=1, so that make_total_plot.py / plot_prover_time.py can draw
them as hollow, dotted points.

Cast Iron: constraints(n) = A + B*n per simulated blockchain depth (from
TestConstraintModel, castiron_count_test.go); the prover time at the largest
measured n is scaled to the target constraint count, averaging a linear and an
n*log(n) extrapolation (Groth16 = MSMs + FFTs).

MACI: per-proof means from the measured per-batch data (plots/maci_batches_raw.csv):
T(n) = ceil(n/20) * t_process + ceil((n+1)/2) * t_tally (message batch 20,
tally batch 2, plus MACI's blank ballot at index 0).

    python3 plots/predict_missing.py [256 512 ...]
"""
import csv
import math
import os
import re
import statistics
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
targets = [int(a) for a in sys.argv[1:]] or [256, 512]

# constraints(n) = A + B*n  (castiron_count_test.go, TestConstraintModel)
MODEL = {1 << 10: (-1187, 76672), 1 << 20: (-1187, 80412), 1 << 30: (-1187, 84152)}
MSG_BATCH, TALLY_BATCH = 20, 2

rows_out = []

# ---- Cast Iron ---------------------------------------------------------------
meas = defaultdict(list)
with open(os.path.join(HERE, "prover_time_raw.csv"), newline="") as f:
    for r in csv.DictReader(f):
        meas[(int(r["simulated_blockchain_leaves"]), int(r["ballots"]))].append(float(r["proof_time_seconds"]))
for leaves, (A, B) in MODEL.items():
    n_ref = max(n for (l, n) in meas if l == leaves)
    t_ref = statistics.mean(meas[(leaves, n_ref)])
    N_ref = A + B * n_ref
    for n in targets:
        if (leaves, n) in meas:
            continue
        N = A + B * n
        lin = t_ref * N / N_ref
        nlogn = t_ref * (N * math.log2(N)) / (N_ref * math.log2(N_ref))
        pred = (lin + nlogn) / 2
        rows_out.append((n, leaves, pred))
        print(f"Cast Iron l=2^{int(math.log2(leaves))} n={n}: {N/1e6:.1f}M constraints -> {pred:.1f} s "
              f"(linear {lin:.1f}, n log n {nlogn:.1f}; from n={n_ref}: {t_ref:.2f} s)")

# ---- MACI --------------------------------------------------------------------
per = defaultdict(list)
measured_n = set()
with open(os.path.join(HERE, "maci_batches_raw.csv"), newline="") as f:
    for r in csv.DictReader(f):
        per[r["batch"].split("_")[0]].append(float(r["full_s"]))
        measured_n.add(int(re.match(r".*_n(\d+)$", r["label"]).group(1)))
tp, tt = statistics.mean(per["process"]), statistics.mean(per["tally"])
for n in targets:
    if n in measured_n:
        continue
    a, b = math.ceil(n / MSG_BATCH), math.ceil((n + 1) / TALLY_BATCH)
    pred = a * tp + b * tt
    rows_out.append((n, -1, pred))
    print(f"MACI n={n}: {a} process x {tp:.2f} s + {b} tally x {tt:.3f} s -> {pred:.1f} s")

out = os.path.join(HERE, "prover_time_predicted.csv")
with open(out, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["ballots", "simulated_blockchain_leaves", "proof_time_seconds", "predicted"])
    for n, leaves, t in sorted(rows_out, key=lambda x: (x[1], x[0])):
        w.writerow([n, leaves, f"{t:.3f}", 1])
print(f"wrote {out} ({len(rows_out)} rows)")
