# Voter opening circuit — implementation & benchmark (2026-08-25)

Package `cast_iron_prover/voteropening` (Go, gnark v0.14.0 / gnark-crypto v0.19.0).
Proving system: **Groth16 over BN254** (secp256k1 emulated in the BN254 scalar field).
Machine: Apple M1 Pro (10 cores, 32 GB), **native arm64 Go 1.24.9** (`/tmp/goarm/go`; the system
`/usr/local/bin/go` is an x86_64 binary under Rosetta — its numbers are listed separately).

## Relation (paper Fig. 2, `Open`)

```
witness : σreg = (SigRx, SigRy, SigS)     3 F_r elements (the B3 signature of the tallying circuit, opaque here)
          r                               commitment randomness
          rσ = RsigHi·2^128 + RsigLo      r-component of the on-chain ECDSA signature
          dom, pkAx, pkAy, posReg         remaining fields of the circuit-1 tuple
public  : TupleHash       = Poseidon(dom, pkAx, pkAy, posReg, Poseidon(σreg))
          EntryCommitment = Poseidon(1, posReg, RsigHi, RsigLo)          -- stands in for the record lookup M[t]
checks  : c = H(σreg ∥ r) ∈ [1, n-1]       Poseidon2 (BN254, width 2, 6/50 rounds = same instance as the tallier)
          rσ = x([c]G)                     on secp256k1 (emulated F_p equality)
```

Two hash modes (`Config.Hash`):
* **wide** (default): `c = (h1·2^254 + h2) mod n`, `h1 = Poseidon(σreg ∥ r)`, `h2 = Poseidon(σreg ∥ r ∥ 1)`
  (Merkle–Damgård continuation, one extra permutation). 508 bits reduced mod n in the emulated scalar
  field ⇒ `c` within 2^-252 of uniform on [0, n), i.e. exactly the H: {0,1}* → [1, n-1] random oracle of Thm. 2.
* **narrow**: `c = Poseidon(σreg ∥ r)` used directly (already < n, only a canonical 254-bit decomposition).
  2.2k constraints cheaper, but the nonce is uniform on a 2^254-subset of [1, n-1]; covertness then rests on
  short-exponent indistinguishability (standard, but an extra assumption vs. the paper's proof).

Three scalar-multiplication back-ends (`Config.Mul`): our **windowed fixed-base gadget** (default),
gnark's `ScalarMulBase` (GLV + fake-GLV) and gnark's plain double-and-add over `[2^i]G`.

## Headline numbers — default config (wide hash, windowed w=7, tensor lookup)

| metric | value |
|---|---|
| R1CS constraints | **22,920** (32,819 internal wires; 3 public wires = 2 inputs + constant; 10 secret) |
| Proving time, 10 cores | **0.113 s** min / 0.114 s median (5 runs) |
| Proving time, 4 / 2 / 1 core(s) (`GOMAXPROCS`) | 0.20 s / 0.37 s / **0.71 s** |
| Peak memory, proving | Go heap in-use 57 MB (Sys 83 MB); **process max RSS 88 MB** (`/usr/bin/time -l`, prove-only process incl. loading pk+ccs) |
| Proof size | **196 B** compressed (388 B raw) = Groth16 A,B,C 128 B + 1 Pedersen commitment 32 B + PoK 32 B + 4 B length |
| Public inputs | 2 field elements = 64 B (76 B serialized with gnark's header) |
| Verification | 1.9 ms; vk 560 B |
| Proving key / CCS on disk | 5.8 MB / 2.8 MB; artifacts load in 0.6 s |
| Setup (one-time per circuit, needs a ceremony in production) | 2.2 s |
| Compile | 0.11 s (tables: 37 windows × 128 constant points, precomputed with gnark-crypto) |
| Same config under Rosetta (x86_64 Go) | prove 0.209 s, verify 4.5 ms |

The one Pedersen commitment comes from gnark's emulated arithmetic (Fiat–Shamir challenge for the
multiplication checks and the log-derivative range-check lookup); all `emulated.Field`/range-check
instances share it.

## Same-machine numbers (AWS x2idn.24xlarge, 96 vCPU, Go 1.24.9 linux/amd64; `results/cloud/*.json`)

| configuration | constraints | prove (min / median of 5) | verify | proof | pk |
|---|---:|---:|---:|---:|---:|
| **BN254, wide, w=7 (default)** | 22,920 | **0.071 s / 0.072 s** | 1.6 ms | 196 B | 5.8 MB |
| BN254, wide, w=7, `GOMAXPROCS=1` (single core) | 22,920 | 0.839 s / 0.840 s | 2.0 ms | 196 B | 5.8 MB |
| BLS12-377, wide, w=7 (inner curve of the BW6-761 2-chain) | 24,528 | 0.091 s / 0.094 s | 3.1 ms | 292 B | 9.0 MB |

For comparison the same BN254 proof takes 0.113 s on the M1 Pro (10 cores) and 0.71 s on one M1 core.

## Where the constraints go (default config, from gnark's profiler + no-EC ablations)

| component | constraints | share |
|---|---:|---:|
| secp256k1 fixed-base multiplication `[c]G` (37 windows, 36 incomplete affine additions) | 17,624 | 77 % |
| ├ limb range checks of the hint outputs of the additions (λ, x₃, y₃ and quotients: ≈32 64-bit limbs/add, 8 chunks of 8 bits + 1 composition each) | ≈10,400 | 45 % |
| ├ one-hot table selection (tensor product of half-window one-hots, 37 windows) | 4,331 | 19 % |
| ├ multiplication-check evaluations at the challenge (3 per addition) | ≈2,600 | 11 % |
| └ log-derivative table (256 entries), commitment glue, `x([c]G) = rσ` | ≈300 | 1 % |
| Poseidon2 hashing — 13 permutations (H(σreg) 3, ∥r 1, ∥tag 1, tuple hash 5, entry commitment 3) | 2,418 | 10.6 % |
| reduction `(h1·2^254 + h2) mod n` (ToBinary(h2) canonical 254 bits, emulated mul-add, `ReduceStrict`, 256-bit `ToBits`) | ≈2,100 | 9 % |
| bit decompositions: ToBinary(h1) canonical 254 bits, rσ 2×128 bits, hash bindings | ≈780 | 3.4 % |
| **total** | **22,920** | |

(no-EC ablations: wide 5,296; narrow 3,001.)  Constraint-count ledger by builder op: 9,344 `Inverse`
(range-check lookups), 7,950 `Mul` (one-hot 4,331 / Poseidon 2,418 / reductions 1,200), 2,155 `MulAcc`
(mul-check evaluations), 1,587 `AssertIsEqual`, 1,277 `AssertIsBoolean`, 308 canonical-bit checks,
256 `DivUnchecked` (lookup table side).

The multiplication itself is cheap; **the range checks of emulated limbs dominate** (each 64-bit limb costs
9 constraints with gnark's commit-based checker). That is why the window optimum is small (w=6–7):
additions cost ≈350 constraints each, table lookups ≈`(2^⌈w/2⌉−1)(2^⌊w/2⌋−1)+…` each.

## Alternatives measured

| config | constraints | prove (10 cores) | peak heap | pk |
|---|---:|---:|---:|---:|
| **wide, windowed w=7, tensor (default)** | **22,920** | **0.113 s** | 57 MB | 5.8 MB |
| narrow, windowed w=7, tensor | 20,738 | 0.109 s | 60 MB | 5.5 MB |
| wide, windowed w=6, tensor | 23,183 | 0.118 s | 60 MB | 6.0 MB |
| wide, windowed w=8, tensor | 24,680 | 0.105 s | 72 MB | 5.8 MB |
| wide, windowed w=7, gnark `selector.Decoder` lookup | 27,874 | – | – | – |
| wide, windowed w=7, tensor + redundant table-limb range checks | 25,592 | – | – | – |
| wide, windowed w=8, decoder + table checks (first version) | 35,503 | – | – | – |
| wide, gnark `ScalarMulBase` (GLV + fake-GLV) | 65,049 | 0.259 s | 149 MB | 15.7 MB |
| wide, gnark double-and-add (`[2^i]G` table, no endomorphism) | 92,048 | 0.441 s | 294 MB | 24.2 MB |

Window sweep (tensor lookup, wide / narrow): w=4 28,903 / 26,737; w=5 unsupported / 22,836;
w=6 23,183 / 21,001; w=7 22,920 / 20,738; w=8 24,680 / 22,319; w=9 29,989 / 27,807.
(w=8 proves marginally faster than w=7 despite more constraints — fewer, denser windows; the difference
is within noise for our purposes.)

## Soundness notes

* **Incomplete addition.** The gadget uses the cheap incomplete affine formula; `P = ±Q` would make the
  λ-constraint vacuous. Tables are offset (`T_0[d] = [2^255 + d + 1]G`, `T_j[d] = [(d+1)2^{wj}]G`,
  top window absorbs `−2^255 − Σ2^{wj}`) so the accumulator stays in `[2^255, 2^255 + 2^{wj} + K_j)` while
  the added multiple is `≤ 2^{w(j+1)}`; `exceptionalScalars()` proves (interval arithmetic, checked at
  compile time) that no collision is possible below the top window and enumerates the top-window ones:
  **exactly one scalar** per supported w (w=7: `0x1fbf7efd…c03f`), hit only if the hash lands on it
  (prob. 2^-256 per attempt). `TestFixedBaseGadget` confirms that scalar fails and its neighbours pass.
* **Canonical decompositions.** `ToBinary(·, 254)` enforces the value below the BN254 modulus (unique
  bits); the wide reduction uses `ReduceStrict` (unique representative below n); `c ≠ 0` is asserted.
* **Table limbs are not range-checked** (saves 2.7k): they are linear combinations of an exact one-hot
  vector with constant coefficients < 2^64. Implemented by copying an in-circuit constant element
  (flagged `internal` by gnark) and substituting the limbs; `CheckTableLimbs: true` re-enables the checks.
* **`rσ` vs `x`.** The circuit checks `rσ = x([c]G)` as an F_p element (paper's `Open`), not `x mod n`.
  For the 2^-128 fraction of nonces with `x ≥ n` the client resamples `r` (`ComputeOpening` returns
  `ErrResample`); `TestNativeECDSA` checks a real ECDSA verifier accepts signatures made with nonce c and
  that their r-component equals `x([c]G)`. `rσ` is bound as two 128-bit halves so it hashes natively.
* **gnark GLV path caveat**: `ScalarMulBase` (fake-GLV) documents `s ∉ {0, −1}` without complete
  arithmetic; only relevant for the comparison variant.

## How to run

```
cd cast_iron_prover
go test ./voteropening/                                   # correctness (test engine + one Groth16 e2e), ~15 s
go test -run TestConstraintBreakdown -v ./voteropening/   # constraint table + profiler → voteropening/results/breakdown.txt
VO_BENCH=1 VO_HASH=wide VO_MUL=windowed VO_WINDOW=7 go test -run TestBenchGroth16 -v ./voteropening/
./voteropening/results/run_bench.sh                       # everything above + prove-only RSS via /usr/bin/time -l
```
Knobs: `VO_HASH=wide|narrow`, `VO_MUL=windowed|glv|dadd`, `VO_WINDOW`, `VO_LOOKUP=tensor|decoder`,
`VO_TABLECHECK=1`, `VO_RUNS`, `VO_PHASE=all|setup|prove`, `VO_DIR`, `VO_OUT`. The same-machine (AWS) records are in
`cloud/`; laptop records are regenerated by `run_bench.sh` (they were not kept in the repository).

## Limitations and follow-ups

* The record-entry lookup is modelled by `EntryCommitment = Poseidon(1, posReg, rσ_hi, rσ_lo)`; the audit circuit
  binds it to the record root through a Merkle path (see `auditcircuit/RESULTS.md`).
* `dom` is a witness field here and a constant (`shared.RegTupleDomainTag`) in the tallying and audit circuits.
* Further savings, if ever needed: a signed-digit / shared-x table to halve lookups, or fusing the addition's three
  multiplication checks — both are inside gnark's `add` and would need a custom formula.
