package auditcircuit

import (
	"math/big"

	"github.com/consensys/gnark/frontend"

	"cast_iron/shared"
)

// InnerVerifier verifies a decrypted opening proof π_open for the statement
// (TupleHash = tupleHash, EntryCommitment = entry).
//
// Contract (soundness-critical):
//   - VerifyBit returns a boolean variable and never makes the circuit
//     unsatisfiable, whatever the proof field values are (an absent proof is
//     all zeros); and
//   - a prover cannot obtain 1 for a statement it holds no valid proof for.
type InnerVerifier interface {
	// NbFields is the number of scalar-field elements the proof is encoded in.
	NbFields() int
	// VerifyBit returns 1 iff proof verifies for (tupleHash, entry).
	VerifyBit(api frontend.API, proof []frontend.Variable, tupleHash, entry frontend.Variable) frontend.Variable
}

// MockVerifier stands in for the real (pairing-based) verifier while the
// curve architecture is undecided (see package doc).  A "proof" is NbFields
// field elements whose last element must equal
// Poseidon(MockDomainTag, tupleHash, entry, fields[0..NbFields-2]); the bit
// is the soft equality of that recomputed value with the last field, so the
// data flow (decrypted proof → bit depending on the recomputed statement) is
// the real one, and an absent (all-zero) or random proof yields 0.  Its cost
// (NbFields+1 Poseidon permutations) is a placeholder and is reported
// separately from the real verifier's.
type MockVerifier struct {
	Fields int
}

// MockDomainTag separates the mock's hash from every other Poseidon use.
const MockDomainTag = 0x4D0C

func (m MockVerifier) NbFields() int { return m.Fields }

func (m MockVerifier) VerifyBit(api frontend.API, proof []frontend.Variable, tupleHash, entry frontend.Variable) frontend.Variable {
	h := shared.NewPoseidonHasher(api)
	h.Write(MockDomainTag, tupleHash, entry)
	h.Write(proof[:len(proof)-1]...)
	return shared.EqBit(api, proof[len(proof)-1], h.Sum())
}

// MockProve produces a valid mock proof for (tupleHash, entry): random
// fields plus the binding last element.
func (m MockVerifier) MockProve(tupleHash, entry *big.Int) []*big.Int {
	fields := make([]*big.Int, m.Fields)
	for j := 0; j < m.Fields-1; j++ {
		fields[j] = shared.RandomScalar()
	}
	vals := append([]*big.Int{big.NewInt(MockDomainTag), tupleHash, entry}, fields[:m.Fields-1]...)
	fields[m.Fields-1] = shared.PoseidonMD(vals...)
	return fields
}

// ConstVerifier returns a constant bit and ignores the proof; used only for
// constraint accounting (verification excluded).
type ConstVerifier struct {
	Fields int
	Bit    int
}

func (v ConstVerifier) NbFields() int { return v.Fields }

func (v ConstVerifier) VerifyBit(api frontend.API, proof []frontend.Variable, tupleHash, entry frontend.Variable) frontend.Variable {
	return v.Bit
}
