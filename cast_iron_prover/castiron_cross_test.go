package main

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	"cast_iron/auditcircuit"
	"cast_iron/shared"
)

// TestCrossCircuitCReg runs the same ballots through the tallying circuit and
// the audit circuit and checks that both produce the same CReg: the audit
// circuit's per-ballot bits (valid opening proof and record entry ⇒ 1) match
// the RegOk bits the tallying circuit was given, on the same ciphertexts and
// the same public context (election id, voter-roll root, record root).
func TestCrossCircuitCReg(t *testing.T) {
	field := ecc.BN254.ScalarField()
	const recordLeaves = 1 << 10
	depth := shared.MerkleHeight(recordLeaves)
	mock := auditcircuit.MockVerifier{Fields: 12}
	cfg := auditcircuit.Config{ProofFields: 12, RecordDepth: depth, Verifier: mock}

	// Scenario: 4 voters, one of them with a bad registration (RegOk = 0) and
	// one with a corrupted anchor signature (validity 0 but RegOk = 1).
	scen := generateSyntheticScenario(4)
	scen.Voters[1].Registrations[0].Ballots[0].GoodRegMerkle = false
	scen.Voters[2].Registrations[0].Ballots[0].GoodAnchorSig = false

	// Record tree: one entry per registration (positions 0..R-1, as the
	// harness numbers them), random ECDSA r-components.
	R := 0
	for _, v := range scen.Voters {
		R += len(v.Registrations)
	}
	entries := make([]auditcircuit.PlainBallot, R)
	leaves := make([]*big.Int, R)
	for pos := range entries {
		entries[pos].PosReg = big.NewInt(int64(pos))
		entries[pos].RsigHi = new(big.Int).Rsh(shared.RandomScalar(), 128)
		entries[pos].RsigLo = new(big.Int).Rsh(shared.RandomScalar(), 128)
		leaves[pos] = shared.EntryCommitmentNative(entries[pos].PosReg, entries[pos].RsigHi, entries[pos].RsigLo)
	}
	recordRoot, _ := shared.BuildPlainMerkle(leaves, recordLeaves)

	// Tallying circuit witness with that record root as RegistrationRoot.
	sb := buildScenarioOpts(t, scen, recordLeaves, scenarioOptions{recordRoot: recordRoot})
	if err := test.IsSolved(sb.skeleton, &sb.assignment, field); err != nil {
		t.Fatalf("tallying witness rejected: %v", err)
	}

	// Audit fixture from the same plaintext ballots: same ElGamal key, same
	// record tree; a valid mock proof exactly for the ballots whose RegOk is 1.
	ballots := make([]auditcircuit.PlainBallot, sb.numBallots)
	for i, pb := range sb.plain {
		pos := pb.PosReg.Int64()
		ballots[i] = auditcircuit.PlainBallot{
			PkAx: pb.PkAx, PkAy: pb.PkAy, PosReg: pb.PosReg,
			B3Rx: pb.B3_Rx, B3Ry: pb.B3_Ry, B3S: pb.B3_S,
			RsigHi: entries[pos].RsigHi, RsigLo: entries[pos].RsigLo,
		}
	}
	sk := sb.assignment.ElGamalSk.(*big.Int)
	g := sb.assignment.ElGamalG.(*big.Int)
	h := sb.assignment.ElGamalH.(*big.Int)
	f := auditcircuit.NewFixture(cfg, sk, g, h, sb.eid, sb.voterRootBI, ballots, recordLeaves)
	if f.RecordRoot.Cmp(recordRoot) != 0 {
		t.Fatal("record roots differ")
	}
	for i := range f.Ballots {
		if sb.regOk[i] {
			f.Ballots[i].Proof = mock.MockProve(f.TupleHashes[i], f.Entries[i])
		} // else: absent proof
	}
	f.Refresh()
	// Use the very same registration ciphertexts the tallying circuit decrypts.
	for i := range f.Ciphertexts {
		bb := sb.assignment.BulletinBoard[i]
		cv := func(c ElGamalCiphertext) auditcircuit.Ciphertext { return auditcircuit.Ciphertext{C1: c.C1, C2: c.C2} }
		f.Ciphertexts[i].PkAnchorX_C = cv(bb.PkAnchorX_C)
		f.Ciphertexts[i].PkAnchorY_C = cv(bb.PkAnchorY_C)
		f.Ciphertexts[i].PosRegC = cv(bb.PosRegC)
		f.Ciphertexts[i].B3_RX_C = cv(bb.B3_RX_C)
		f.Ciphertexts[i].B3_RY_C = cv(bb.B3_RY_C)
		f.Ciphertexts[i].B3_S_C = cv(bb.B3_S_C)
	}

	// Same tuple hashes, same bits, same CReg.
	for i := range f.TupleHashes {
		if f.TupleHashes[i].Cmp(sb.tupleHashes[i]) != 0 {
			t.Fatalf("ballot %d: tuple hash differs between circuits", i)
		}
		if f.Bits[i] != sb.regOk[i] {
			t.Fatalf("ballot %d: audit bit %v != tallying RegOk %v", i, f.Bits[i], sb.regOk[i])
		}
	}
	if f.CReg.Cmp(sb.creg) != 0 {
		t.Fatal("CReg differs between the tallying and the audit fixture")
	}
	// The audit circuit accepts the tallying circuit's CReg as its public output.
	a := f.Assignment()
	a.CReg = sb.creg
	if err := test.IsSolved(f.Skeleton(), a, field); err != nil {
		t.Fatalf("audit circuit rejected the tallying circuit's CReg: %v", err)
	}
	// ... and rejects the CReg of a run where the bad registration were valid.
	flipped := append([]bool{}, sb.regOk...)
	flipped[1] = true
	a.CReg = shared.ComputeCReg(sb.alphaReg, sb.tupleHashes, flipped)
	if err := test.IsSolved(f.Skeleton(), a, field); err == nil {
		t.Fatal("audit circuit accepted a CReg with a flipped bit")
	}
	t.Logf("%d ballots, RegOk/audit bits %v, CReg equal", sb.numBallots, sb.regOk)
}
