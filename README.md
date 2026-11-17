# Cast Iron — artifact

Code and data for *Cast Iron: Coercion-Resistant Voting from Covert Self-Registration*.

| component | what it is | paper |
|---|---|---|
| [`cast_iron_prover/`](cast_iron_prover/) | the tallying relation as a gnark/Groth16 circuit (Go), its tests, and the proving-time benchmark with the MACI comparison | Definition 3, Sections 5.3 and 7 |
| [`ctc/`](ctc/) | Covert Timestamped Commitments: the ECDSA-nonce construction and a registration client (Python), with tests on the Tron Nile testnet | Section 4.1, Figure 2 |
| [`coco/`](coco/) | the Cost of Coercion optimisation and the scripts for its figures (Python) | Section 8, Appendix B |
| [`tron_usdt_rotating_addresses.sql`](tron_usdt_rotating_addresses.sql) | the Dune query measuring the anonymity set on Tron | Appendix B |

Each directory has its own README with setup and commands.

## Where each result comes from

| result | data | how to regenerate |
|---|---|---|
| Figure 4: tally proving time, Cast Iron vs MACI | `cast_iron_prover/plots/` (raw timings, merged CSV, figure) | `CASTIRON_SWEEP=1 go test -run TestProverTimePlot ...`, MACI with `cast_iron_prover/maci_bench/`, then `plots/make_total_plot.py` |
| Section 7.2: one proof of 4,096 ballots | `cast_iron_prover/plots/prover_time_raw_bls12381.csv` and `.log` | same sweep with `CASTIRON_CURVE=bls12381 CASTIRON_COUNTS=4096` |
| Constraint counts (not in the paper; tables in `cast_iron_prover/README.md`) | — | `go test -run TestConstraint -v .` in `cast_iron_prover/` |
| Figure 6: CoCo across protocols | generated into `coco/figures/` (not tracked) | `uv run python coco_sim.py` in `coco/` (it also renders election-parameter sweeps that the paper does not include) |
| Figure 7: CoCo against the anonymity-set size | generated into `coco/figures/` | `uv run python anonymity_set_curve.py` in `coco/` |
| Figure 8: anonymity set per block on Tron | — (query only) | run the SQL on Dune |
| Section 4.1: a CTC as a USDT transfer on Tron | — | `ctc/main.py`, `ctc/tests/test_tron_ctc.py` |

The proving-time measurements were taken on an AWS `x2idn.24xlarge`; see
[`cast_iron_prover/README.md`](cast_iron_prover/README.md#measurements) for the details and the numbers.

The Go and Python sides share one definition of the commitment `c = H(m ∥ r)`: `ctc/tests/vectors.json` is
generated from the Go packages (`ctc/tests/gen_vectors`) and replayed by the tests of both.
