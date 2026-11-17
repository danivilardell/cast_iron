# Cast Iron tallying circuit

A [gnark](https://github.com/Consensys/gnark) (v0.14) implementation of the Cast Iron tallying relation
(paper Definition 3, Sections 5.3 and 7), proved with Groth16, and the harness that measures its
proving time (Figure 4).

Given the filtered bulletin board BB′, the roots of the weight tree T_W and the record tree T_R, the
tallier's public key and a result X, the proof shows knowledge of sk_T such that

```
pk_T    = Enc.DerivePk(sk_T)
B_dec   = Enc.D(sk_T, BB′)
v       = Validate(B_dec, T_W, T_R)
B_final = Deduplicate(B_dec, v)
X       = Accumulate(B_final)
```

FILTER (the proof of plaintext knowledge π_E and the removal of duplicate ciphertexts) happens outside
the circuit, on public data; the circuit takes BB′ as given.

## Layout

| path | contents |
|---|---|
| `castiron_circuit.go` | the circuit |
| `shared/` | proving-curve selection, Poseidon2, ElGamal, the record tree: gadgets and their native counterparts |
| `voteropening/` | the CTC opening `rσ = x([H(m ∥ r)]G)` on secp256k1: fixed-base gadget and the native computation a registration client performs |
| `castiron_harness_test.go` | builds elections (keys, registrations, record, ballots), the tallier's witness, and a reference tally written from the definition in Section 5.3 |
| `castiron_test.go` | correctness tests (below) and the JSON scenarios of `testdata/` |
| `castiron_count_test.go` | constraint counts on the Figure 4 grid and per building block |
| `castiron_scaling_test.go` | the Figure 4 sweep |
| `plots/` | Figure 4: measurements, scripts, the figure |
| `maci_bench/` | scripts that measured MACI for Figure 4 (see its README) |

## The circuit

**Public inputs.** Election identifier; `Mrk.Root(T_W)`; `Mrk.Root(T_R)`; the tallier's ElGamal key
`(g, h)`; BB′ as a list of ballots, each `16 + m + d` field-wise ElGamal ciphertexts (`m` choices, weight
tree of depth `d`); the result `X` (`m` field elements).

**Witness.** `sk_T`; for every ballot, the leaf of T_R at the ballot's registration position with its
sibling path; and the sorted view `B_sorted`.

**A ballot** (Section 5.2) decrypts to

* `B1 = (pk_i, IC.pk, (σreg, r), t_reg)`: the voting key, the inalienable credential's key, the registration
  signature and CTC randomness, and the registration's position in the record;
* `B2 = (π_W, w, ν, id_B)`: leaf index and sibling path in the weight tree, the weight, the choice as a
  one-hot vector scaled by `w`, and the ballot identifier;
* `σB`, an EdDSA signature under `pk_i` over `(eid, IC.pk, pk_i, t_reg, ν, w, σreg, id_B)`, that is,
  `(B1, B2)` without the two witnesses `r` and `π_W`.

Keys and signatures are EdDSA on the twisted Edwards curve of the proving field (Baby Jubjub over BN254,
Jubjub over BLS12-381); every hash is Poseidon2 (width 2, 6 full and 50 partial rounds, Merkle–Damgård).

**Validate.** The validity bit `v` is the product of soft predicates:

| predicate | meaning |
|---|---|
| election | the ballot's `eid` is this election's, and `IC.pk ≠ (0, 0)` |
| choice | `ν` has exactly one nonzero entry and it equals `w` |
| weight validity | `Poseidon(IC.pk, w)` is the leaf at the ballot's index of T_W |
| registration validity | `CTC.Open((pk_i, σreg), r, t_reg)`: the nonce `c = H(pk_i ∥ σreg ∥ r)` is nonzero and the leaf of T_R at `t_reg` is `Poseidon(1, t_reg, x([c]G))` |
| registration binding | `σreg` verifies under `IC.pk` over `(eid, pk_i, IC.pk)` |
| ballot authenticity | `σB` verifies under `pk_i` |

Three things are asserted rather than tested, because they are the prover's obligations and not
properties of a ballot: `h = g^{sk_T}`; that the leaf the tallier presents for a ballot is the leaf of T_R
at that ballot's `t_reg` (whenever `t_reg` is a position of the tree); and, below, the sorted view. The
consequence is that the validity bits are a function of the public inputs: the prover cannot choose them.
Conversely, nothing a ballot decrypts to — an index outside a tree, a key that is not a curve point or
lies outside the prime-order subgroup, random data — makes a constraint unsatisfiable, so no ballot can
prevent the tally from being proved. To that end the EdDSA check replaces off-curve points before doing
curve arithmetic and multiplies with the complete addition law only.

**Deduplicate.** Each ballot is projected to a row `(IC.pk, t_reg, id_B, ν·w)` multiplied by `v`, with its
position `t` on BB′ appended. The prover supplies the rows sorted; the circuit checks

1. *order*: consecutive rows are strictly increasing in `(IC.pk, t_reg, id_B, t)` (positions are distinct,
   so the sorted view is unique);
2. *multiset equality* with the unsorted rows, by a grand product over `Poseidon(row) + α` with the
   challenge `α` derived from the election identifier, the weight-tree root and the digests of both arrays.

A single pass over the sorted rows then selects, for every `IC.pk`, among the rows of its smallest `t_reg`
that are the first occurrence of their `id_B`, the one with the largest `t`. Rows of invalid ballots are
all-zero, form one block and carry no weight.

So a voter's later ballot replaces an earlier one; a ballot cast with a credential registered later than
the voter's first one is ignored; and a re-encryption of an earlier ballot, which the tallier can produce,
carries that ballot's identifier and is dropped.

**Accumulate.** `X` is the sum of the selected rows' `ν·w`.

### Size

R1CS constraints over BN254, two choices (`go test -run TestConstraint -v .`):

| | per unit |
|---|---|
| Poseidon2, per absorbed element (a two-to-one hash is two) | 186 |
| ElGamal decryption of one field | 763 |
| EdDSA verification | 6,563 |
| CTC opening without the record path (nonce hash, `[c]G` on secp256k1, entry commitment) | 21,784 |
| record path, per level | 374 |
| weight path, per level (one decryption, one hash) | 1,136 |

The whole circuit, by the number of ballots and the number of leaves |T_R| of the record tree:

| ballots (= voters) | \|T_R\| = 2^10 | \|T_R\| = 2^20 | \|T_R\| = 2^30 |
|---|---|---|---|
| 1 | 64,341 | 68,091 | 71,841 |
| 2 | 128,969 | 136,479 | 143,989 |
| 4 | 259,250 | 274,280 | 289,310 |
| 8 | 521,167 | 551,237 | 581,307 |

At |T_R| = 2^30 and n = 16, 32, 64, 128 the circuit has 73,215, 73,517, 73,611 and 74,227 constraints per
ballot: each doubling of the electorate adds a weight-tree level (one decryption and one hash per ballot),
partly offset by the lookup tables of the emulated secp256k1 arithmetic amortising over more ballots. Over
BLS12-381 the counts are 0.2% higher: 4,096 ballots at |T_R| = 2^30 are 325,926,897 constraints (79,572 per
ballot). BN254's FFT domain (2^28) caps a single proof at roughly 3,300 ballots; larger elections are
proved over BLS12-381 (`CASTIRON_CURVE=bls12381`).

## Tests

```
go test -timeout 0 ./...                      # everything except the Figure 4 sweep (a few minutes)
CASTIRON_CURVE=bls12381 go test -timeout 0 ./...
```

`castiron_test.go` checks the circuit against the reference tally with gnark's test engine, and once
end to end with Groth16 over a 2^30-entry record:

* results: weighted sums; a different result is rejected;
* Deduplicate: the latest ballot counts; replays are ignored; the earliest registration counts; random
  elections mixing all of these;
* Validate: every way a ballot can be invalid drops exactly that ballot, and it cannot be counted anyway;
* malformed ballots (out-of-range indices, points off the curve or of low order, all-zero and random
  plaintexts) leave the relation satisfiable;
* a tallier presenting a wrong record entry, a wrong decryption key or a sorted view that is not a
  permutation gets no proof.

`voteropening/` tests the secp256k1 gadget against gnark-crypto and replays the test vectors of the
Python CTC client (`../ctc/tests/vectors.json`), so that registrations made with the client open in the
circuit.

## Figure 4

```
CASTIRON_SWEEP=1 go test -run TestProverTimePlot -timeout 0 -v .          # n = 1..512, |T_R| = 2^10, 2^20, 2^30, 5 proofs each
CASTIRON_SWEEP=1 CASTIRON_CURVE=bls12381 CASTIRON_COUNTS=4096 CASTIRON_LEAVES=1073741824 CASTIRON_REPEATS=3 \
    CASTIRON_CSV=plots/prover_time_raw_bls12381.csv go test -run TestProverTimePlot -timeout 0 -v .
python3 plots/maci_totals.py plots/maci_batches_raw.csv                   # MACI per-batch timings → totals per ballot count
python3 plots/make_total_plot.py                                          # → plots/prover_time_total.{csv,pdf,png}
```

The sweep needs a large machine: its 512-ballot configurations use about 100 GB of memory, and the
4,096-ballot run peaked at 646 GiB. See the comment on `TestProverTimePlot` for its environment variables.
The trusted setup is run once per configuration and is not part of the reported proving times.

### Measurements

Everything in `plots/` was measured on 2026-11-17 on one AWS `x2idn.24xlarge` (2 × 24 cores, 1.5 TB;
`plots/cloud_machine.txt`), with nothing else running, in this order: the sweep, the 4,096-ballot proof, MACI.
Every point of the figure is a measurement (mean of 5 proofs).

| file | contents |
|---|---|
| `prover_time_raw.csv`, `.log` | tallying circuit over BN254: n = 1..512, three record sizes, 5 proofs each, with the constraint count and the compile and setup times of every configuration; the log of the run |
| `prover_time_raw_bls12381.csv`, `.log` | 4,096 ballots in one proof over BLS12-381 at \|T_R\| = 2^30, proved three times; the log of the run |
| `maci_batches_raw.csv`, `maci_time_raw.csv` | MACI v3.0.0 (QV circuits, snarkjs 0.7.5): every batch proof for n = 1..512, 5 repeats, and the totals per ballot count |
| `prover_time_total.{csv,pdf,png}` | the figure and its data (`make_total_plot.py`) |

| ballots | \|T_R\| = 2^10 | \|T_R\| = 2^20 | \|T_R\| = 2^30 | MACI |
|---|---|---|---|---|
| 1 | 0.13 s | 0.13 s | 0.14 s | 12.8 s |
| 8 | 0.78 s | 0.89 s | 0.86 s | 16.5 s |
| 64 | 5.4 s | 5.5 s | 5.7 s | 74.0 s |
| 128 | 9.6 s | 9.9 s | 10.5 s | 137.9 s |
| 256 | 19.6 s | 19.5 s | 20.1 s | 258.9 s |
| 512 | 38.4 s | 38.8 s | 40.6 s | 528.3 s |

The sweep took 1 h 48 min in total: 20 min compiling, 68 min of setups, 20 min proving.

4,096 ballots (BLS12-381, |T_R| = 2^30): compilation 31 min 35 s, setup 2 h 52 min 7 s (including writing the
96 GB proving key), proofs 7 min 30 s, 6 min 38 s and 6 min 45 s (mean 6 min 58 s; the first proof after
the setup is the slowest).
