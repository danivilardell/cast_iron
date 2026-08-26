package main

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"cast_iron/shared"
)

// TestRegistrationOpening checks the in-circuit CTC opening with the test
// engine: honest ballots are valid; a ballot whose randomness does not open
// the record entry, a wrong record entry, and a wrong Merkle path each make
// the ballot invalid (validity bit 0) while the circuit stays satisfiable.
func TestRegistrationOpening(t *testing.T) {
	field := ecc.BN254.ScalarField()
	scen := generateSyntheticScenario(3)
	scen.Voters[1].Registrations[0].Ballots[0].GoodRegMerkle = false // bad randomness
	sb := buildScenario(t, scen, 1<<10)
	if got, want := sb.validity, []bool{true, false, true}; got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("validity %v, want %v", got, want)
	}
	if err := test.IsSolved(sb.skeleton, &sb.assignment, field); err != nil {
		t.Fatalf("honest witness rejected: %v", err)
	}
	// claiming ballot 1 valid must fail (the circuit computed okReg = 0)
	allValid := sb.assignmentFor([]bool{true, true, true})
	if err := test.IsSolved(sb.skeleton, &allValid, field); err == nil {
		t.Fatal("ballot with bad opening randomness accepted as valid")
	}

	// wrong record entry for ballot 0: invalid, satisfiable
	a := sb.assignmentFor([]bool{false, false, true})
	a.RecordOpenings[0].RsigLo = new(big.Int).Add(a.RecordOpenings[0].RsigLo.(*big.Int), big.NewInt(1))
	if err := test.IsSolved(sb.skeleton, &a, field); err != nil {
		t.Fatalf("wrong record entry must give an invalid ballot, satisfiably: %v", err)
	}
	a = sb.assignmentFor([]bool{true, false, true})
	a.RecordOpenings[0].RsigLo = new(big.Int).Add(a.RecordOpenings[0].RsigLo.(*big.Int), big.NewInt(1))
	if err := test.IsSolved(sb.skeleton, &a, field); err == nil {
		t.Fatal("wrong record entry accepted as valid")
	}

	// wrong Merkle path for ballot 2: invalid, satisfiable
	a = sb.assignmentFor([]bool{true, false, false})
	a.RecordOpenings[2].Path = append([]frontend.Variable{}, a.RecordOpenings[2].Path...)
	a.RecordOpenings[2].Path[2] = shared.RandomScalar()
	if err := test.IsSolved(sb.skeleton, &a, field); err != nil {
		t.Fatalf("wrong path must give an invalid ballot, satisfiably: %v", err)
	}
	a = sb.assignmentFor([]bool{true, false, true})
	a.RecordOpenings[2].Path = append([]frontend.Variable{}, a.RecordOpenings[2].Path...)
	a.RecordOpenings[2].Path[2] = shared.RandomScalar()
	if err := test.IsSolved(sb.skeleton, &a, field); err == nil {
		t.Fatal("wrong path accepted as valid")
	}
}

// TestSyntheticGroth16Small runs the real prove path (compile, setup, prove,
// verify) on a small synthetic scenario with a 2^30-entry record tree.
func TestSyntheticGroth16Small(t *testing.T) {
	scen := generateSyntheticScenario(2)
	_, _, numBallots, tally := runScenarioWithBlockchainLeavesProveRepeats(t, scen, 1<<30, 1, Groth16)
	if numBallots != 2 {
		t.Fatalf("got %d ballots", numBallots)
	}
	for j, v := range tally {
		if v.(*big.Int).Int64() != 1 {
			t.Fatalf("tally[%d] = %v, want 1", j, v)
		}
	}
}
