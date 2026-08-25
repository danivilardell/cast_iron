package auditcircuit

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"

	"cast_iron/shared"
)

var field = ecc.BN254.ScalarField()

func testConfig() Config {
	return Config{ProofFields: 12, RecordDepth: 10, Verifier: MockVerifier{Fields: 12}}
}

func solved(t *testing.T, f *Fixture, a *Circuit) error {
	t.Helper()
	return test.IsSolved(f.Skeleton(), a, field)
}

func withCReg(a *Circuit, creg *big.Int) *Circuit {
	b := *a
	b.CReg = creg
	return &b
}

func TestHonest(t *testing.T) {
	f := RandomFixture(testConfig(), 3, 1<<10)
	for i, b := range f.Bits {
		if !b {
			t.Fatalf("ballot %d expected valid", i)
		}
	}
	if err := solved(t, f, f.Assignment()); err != nil {
		t.Fatalf("honest fixture rejected: %v", err)
	}
	want := shared.ComputeCReg(f.Alpha, f.TupleHashes, []bool{true, true, true})
	if want.Cmp(f.CReg) != 0 {
		t.Fatal("CReg mismatch with the shared accumulator")
	}
}

// An invalid or absent proof yields b_i = 0 and the circuit stays satisfiable.
func TestInvalidOrAbsentProof(t *testing.T) {
	f := RandomFixture(testConfig(), 3, 1<<10)
	for j := range f.Ballots[1].Proof { // invalid: random fields
		f.Ballots[1].Proof[j] = shared.RandomScalar()
	}
	f.Ballots[2].Proof = nil // absent: all-zero ciphertext payload
	f.Refresh()
	if got, want := f.Bits, []bool{true, false, false}; got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("expected bits %v, fixture computed %v", want, got)
	}
	if err := solved(t, f, f.Assignment()); err != nil {
		t.Fatalf("circuit with invalid/absent proofs must stay satisfiable: %v", err)
	}
	// ... and the circuit really computed 0 for those ballots:
	optimistic := shared.ComputeCReg(f.Alpha, f.TupleHashes, []bool{true, true, true})
	if err := solved(t, f, withCReg(f.Assignment(), optimistic)); err == nil {
		t.Fatal("CReg computed with b=1 for invalid proofs was accepted")
	}
}

// A record entry that is not in the tree (wrong rσ, wrong path, or a
// position beyond the tree) yields b_i = 0, satisfiably.
func TestBadRecord(t *testing.T) {
	f := RandomFixture(testConfig(), 3, 1<<10)
	f.Ballots[0].RsigLo = new(big.Int).Add(f.Ballots[0].RsigLo, big.NewInt(1))
	f.Ballots[1].Path[3] = shared.RandomScalar()
	f.Ballots[2].PosReg = new(big.Int).Lsh(big.NewInt(1), 40) // out of range
	f.Refresh()
	for i, b := range f.Bits {
		if b {
			t.Fatalf("ballot %d expected b=0", i)
		}
	}
	if err := solved(t, f, f.Assignment()); err != nil {
		t.Fatalf("bad records must stay satisfiable: %v", err)
	}
	if err := solved(t, f, withCReg(f.Assignment(), shared.ComputeCReg(f.Alpha, f.TupleHashes, []bool{true, true, true}))); err == nil {
		t.Fatal("bad records accepted as valid")
	}
}

// Changing a registration field changes tupleHash_i: the old CReg no longer
// matches (and the proof, bound to the old tuple, no longer verifies).
func TestTamperedTuple(t *testing.T) {
	f := RandomFixture(testConfig(), 2, 1<<10)
	oldCReg := f.CReg
	f.Ballots[0].PkAx = shared.RandomScalar()
	f.Refresh() // new tuple hash for ballot 0; its proof is bound to the old one → b_0 = 0
	if f.Bits[0] {
		t.Fatal("proof bound to the old tuple must not verify")
	}
	if err := solved(t, f, withCReg(f.Assignment(), oldCReg)); err == nil {
		t.Fatal("tampered tuple accepted against the old CReg")
	}
	if err := solved(t, f, f.Assignment()); err != nil { // consistent witness (new tuple, b_0 = 0)
		t.Fatalf("consistent witness rejected: %v", err)
	}
}

// A wrong key relation zeroes every bit (as in the tallying circuit).
func TestWrongKey(t *testing.T) {
	f := RandomFixture(testConfig(), 2, 1<<10)
	a := f.Assignment()
	a.ElGamalH = shared.RandomScalar()
	zeros := shared.ComputeCReg(f.Alpha, f.TupleHashes, []bool{false, false})
	if err := solved(t, f, withCReg(a, zeros)); err != nil {
		t.Fatalf("wrong key must yield b=0 satisfiably: %v", err)
	}
	if err := solved(t, f, a); err == nil {
		t.Fatal("wrong key accepted with b=1")
	}
}

func TestGroth16EndToEnd(t *testing.T) {
	f := RandomFixture(testConfig(), 2, 1<<10)
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, f.Skeleton())
	if err != nil {
		t.Fatal(err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	w, err := frontend.NewWitness(f.Assignment(), field)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := groth16.Prove(ccs, pk, w)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := w.Public()
	if err := groth16.Verify(proof, vk, pub); err != nil {
		t.Fatal(err)
	}
	t.Logf("n=2: %d constraints", ccs.GetNbConstraints())
}
