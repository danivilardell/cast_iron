# 🧩 ZK Voting Circuit (ElGamal-based, MiMC/BN254)

This repository implements the zero-knowledge circuit used in a privacy-preserving voting protocol. The proof certifies that the publicly posted tally was computed only from the published encrypted ballots and according to the protocol rules—without revealing the decryption key or any individual vote.

---

## 1️⃣ Overview

### Roles

- Voter i  
  • Anchor keypair (sk_i, pk_i) with weight w_i  
  • Optional ephemeral voting keypair (sk_i', pk_i')  
- Tallying Authority (TA)  
  • ElGamal keypair (sk, pk)

Ballots are ElGamal-encrypted and posted to a public bulletin board. The circuit proves that:
1) Each ciphertext decrypts correctly under sk.  
2) Each decrypted ballot is valid, unique, and properly signed/registered.  
3) The tally includes only valid ballots, deduplicated per voter under the protocol’s revote rule, and is the correct sum of one-hot weighted choices.

---

## 2️⃣ Circuit Inputs

### Public Inputs

- eid: Election identifier  
- Mrk.Root: Merkle root of voter weights (anchor tree)  
- Mrk'.Root: Merkle root of registration commitments (ordered registration tree)  
- BulletinBoard: Ordered list of all posted encrypted ballots (ciphertexts and clear paths/indices as per format)  
- (optional) T: The published tally vector to be verified (if the tally is public and checked in-circuit)

### Private Witness

- sk: TA’s ElGamal secret key (used to derive the KDF seed)

Note: In this implementation, ballots encrypt PRF-masked field scalars with a MiMC-based KDF from the ElGamal shared secret; the circuit recomputes those masks and “decrypts” by subtraction in the field.

---

## 3️⃣ Phase-1 — Validity Checks (per ballot)

Each stage outputs a bit in {0,1}. Their product is the per-ballot validity flag v_i.

(A) ElGamal / PRF Decryption  
Goal: Prove knowledge of sk such that decrypting the posted ciphertext yields the clear ballot fields. Compute R = [sk]·C1, K = MiMC(Rx, Ry), and for each labeled scalar m_label = c_label − MiMC(DOMAIN, K, label). This is used for eid, keys, choice vector entries, and signature scalars.

(B) Single-Choice  
Exactly one choice is selected (one-hot times weight). For each c_ij, define z_ij = 1 − isZero(c_ij), enforce z_ij ∈ {0,1}, and enforce Σ_j z_ij = 1.

(C) Weight Consistency + Voter-Roll Inclusion  
Recompute leaf = MiMC(pk_anchor.X, pk_anchor.Y, weight). Verify Mrk.Ver(Mrk.Root, leaf, pathWeight, leafIndex) using an ordered fold. Enforce Σ_j c_ij = weight.

(D) Registration Commitment  
B3 is an anchor signature over (eid, pk_vote, pk_anchor). Compute H_B3 = MiMC(B3.Rx, B3.Ry, B3.S) and leaf' = MiMC(0, posReg, H_B3). Verify Mrk'.Ver(Mrk'.Root, leaf', pathReg, posReg) using an ordered fold.

(E) Ballot Signature  
B4 is a vote signature by pk_vote over (eid, Mrk.Root, Mrk'.Root, B1(keys, posReg), B2(choices, weight), B3(sig)). Verify the EdDSA relation on the BN254 twisted Edwards curve using a MiMC transcript.

(F) Validity Bit  
v_i = v_dec · v_single · v_weight · v_reg · v_sig ∈ {0,1}.

---

## 4️⃣ Phase-2 — Tallying (Filtering, Ordering, Dedup, Sum)

This phase proves that the published tally counts exactly the ballots permitted by the rules and nothing else.

### Data Views A1 → A★

We manipulate three views of the same list and enforce linking constraints between them.

1. **A1**: The posted list (as on the bulletin board).  
2. **A2 (Filter)**: Zero out invalid ballots with `A2[i] = v_i · A1[i]`. All fields in the row are multiplied by `v_i` so invalid rows become all-zero.  
3. **A★ (Sort by voter + registration)**: Reorder A2 by `(pk_anchor, posReg)` lexicographically (ascending). Enforce multiset equality `SetEq(A2, A★)` (same rows, permuted) and global lexicographic sortedness: `(pk_anchor_X[i], pk_anchor_Y[i], posReg[i]) ≤ (pk_anchor_X[i+1], pk_anchor_Y[i+1], posReg[i+1])`. This ensures same-voter rows are contiguous and sorted by `posReg` within each voter.

**Intuition**: A2 removes invalid ballots; A★ groups ballots by voter (contiguous blocks) and orders each voter's ballots by registration position (earliest commitment first).

**Optimization note**: A★ combines what would be two separate sorts (A3: sort by voter, A4: sort by registration within voter) into a single lexicographic sort, saving one full pass of hashing, comparison, and multiset equality checking.

### Deduplication Rule (revoting semantics)

For each voter (fixed pk_anchor), only one ballot contributes to the tally: the last valid ballot under that voter's earliest committed key. This is realized by the A★ ordering (which groups ballots by voter and sorts them by registration position) plus a per-voter selector.

Define a guard `keep_i ∈ {0,1}` on A★ such that:
- `keep_i = 1` for exactly one row in each contiguous block with equal `pk_anchor`, and  
- the chosen row corresponds to the last ballot associated with the earliest `posReg` for that voter (as established by the A★ ordering and how B3 binds ballots to the earliest committed key).

Then the tally vector is: `T = Σ_i keep_i · A★[i].B2.c` (vector sum over choices).

### Tally Check

The circuit computes the tally `T` and asserts equality with the public tally input: `T_public = Σ_i keep_i · A★[i].Choice`. The tally is a public input/output of the circuit, allowing anyone to verify that the published election results match the tallied valid ballots.

---

## 5️⃣ Security Properties (What the Proof Guarantees)

- Correct PRF-mask removal under sk: (A)  
- Exactly one choice per ballot: (B)  
- Voter weight and roll inclusion: (C)  
- Valid registration commitment and path: (D)  
- Authentic ballot (vote signature): (E)  
- Inclusion of all posted ballots: SetEq(A1 ↔ A2 ↔ A3 ↔ A4)  
- Exclusion of invalid ballots: A2 = A1 · v  
- Correct grouping and intra-voter order: A3 sort by pk, A4 sort by posReg  
- Revote rule (one counted ballot per voter): keep_i on A4 block per voter  
- Correct tally sum: T = Σ keep_i · c_i

---

## 6️⃣ Developer Notes

- Curves & hashes  
  • Proof system: Groth16 over BN254.  
  • Curve arithmetic: BN254 twisted Edwards (for EdDSA and ElGamal group ops).  
  • Hash/KDF/PRF: MiMC (BN254 field), used for KDF from [sk]·C1, PRF labels, Merkle hashing, and signature transcripts in this codebase.

- ElGamal decrypt path  
  • Derive R = [sk]·C1 and K = MiMC(Rx, Ry), then unmask each scalar as m = c − MiMC(domain, K, label).

- Merkle paths  
  • Ordered fold (LSB-first index bits). In-circuit we recompute the leaf and fold over siblings only.

- Set equality (SetEq)  
  • Implement as a multiset equality gadget (e.g., commit each row with MiMC and prove permutation via a product-argument with a public randomizer, or use a permutation check if your circuit framework provides one).

- Sortedness  
  • Adjacent-pair ≤ checks; conditionals for ties (pk equal ⇒ compare posReg).

- Dedup guard (keep_i)  
  • For each voter block in A4, enforce Σ keep_i = 1 and use simple “is boundary / is last” indicators to assign the 1 to the appropriate row.

- Complexity  
  • Roughly quasi-linear in the number of ballots n (dominated by sort + set-equality); linear in the number of choices C for the final accumulation.

---

## 7️⃣ Testing Tips

- If using the PLONK backend, generate the SRS once before running tests:
  `./utilities/generate_plonk_srs.sh`
  This writes `testdata/plonk_srs_bn254_canonical.bin` and
  `testdata/plonk_srs_bn254_lagrange.bin`. Re-run if the max ballot size changes.

- Flip one sibling in a Merkle path → proof must fail.  
- Change LeafIndex or posReg by ±1 → fail.  
- Tamper a ChoiceC[j] or Weight → fail.  
- Duplicate ballots for a voter → only the designated one (per revote rule) should contribute to T.  
- Shuffle A1 and re-prove → SetEq should still pass, tally unchanged.

---

## 8️⃣ Summary

Given all posted encrypted ballots and public election parameters, the prover knows a secret key sk such that decrypting, validating, ordering, deduplicating per voter, and summing the one-hot weighted choices yields exactly the published tally T. The proof reveals no secret key material, individual votes, or voter-to-ballot linkages beyond what the protocol intentionally makes public.
"""
