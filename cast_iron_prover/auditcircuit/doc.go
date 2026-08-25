// Package auditcircuit implements circuit 2 of Cast Iron, the *audit circuit*:
// the tallier proves, for every ballot on the bulletin board, that it
// decrypted the registration fields with the same ElGamal key as the tallying
// circuit, that the voter's opening proof π_open (carried encrypted in the
// ballot) verifies for the registration tuple those fields hash to, and that
// the record entry the proof refers to is in the record tree; the result is a
// per-ballot bit b_i bound to the tallying circuit through the accumulator
//
//	CReg = ∏_i ( Poseidon(tupleHash_i, b_i) + alphaReg ),
//
// computed with exactly the gadgets of package shared that the tallying
// circuit uses (same Poseidon2 instance, tuple hash, alphaReg derivation).
// The two circuits are linked only by public equality of CReg.
//
// # Curve decision (mocked verifier; native 2-chain verification measured separately)
//
// This package is compiled over the BN254 scalar field like the tallying
// circuit and the current voter circuit.  Verifying a Groth16/BN254 proof
// inside a BN254 circuit requires an emulated pairing (millions of
// constraints per proof), and the native 2-chain alternative — voter proofs
// on BLS12-377 verified natively in a BW6-761 audit circuit — moves the audit
// circuit to BW6-761's scalar field (= BLS12-377's base field), where it can
// neither decrypt the BN254-Fr ElGamal ciphertexts nor recompute the BN254-Fr
// Poseidon tuple hash except through emulated arithmetic (10^5–10^6
// constraints per ballot).  Reconciling the fields is an architectural
// decision (which curve the tallier lives on) that is documented in
// RESULTS.md.  The in-circuit verifier is therefore abstracted behind
// [InnerVerifier]: [MockVerifier] stands in for
// it here so that every other part of the circuit (decryption, hashing,
// record-tree check, accumulator) is accounted for exactly, and the real cost
// of the native BLS12-377-in-BW6-761 soft verifier is measured standalone in
// the bw6verifier subpackage.  The mock's own cost is reported separately and
// excluded from the estimates.
//
// # Soft verification
//
// Verification failure or an absent proof must yield b_i = 0, never an
// unsatisfiable circuit.  Every check of a ballot is therefore a soft
// predicate: key relation, record-tree membership (index range and Merkle
// root compared with IsZero), and InnerVerifier.VerifyBit, whose contract is
// that any decrypted field values produce a bit and that b = 1 is impossible
// without a valid proof.  See bw6verifier for how the real pairing-based
// verifier is made soft (on-curve bits + Select onto a constant valid proof).
package auditcircuit
