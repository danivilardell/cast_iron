package main

import (
	"errors"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"cast_iron/voteropening"
)

// TestRegOkFlip checks that flipping a RegOk bit changes CReg and flips the
// ballot's validity bit (test engine, no proving):
//
//	(a) the baseline witness satisfies the circuit;
//	(b) flipping RegOk[0] alone is rejected (CReg mismatch);
//	(c) flipping RegOk[0] and recomputing CReg, but keeping the views of a
//	    valid ballot 0, is still rejected: the circuit now computes
//	    ValidityBits[0] = 0, zeroes the ballot in A2, and the multiset check
//	    against the unchanged sorted view fails;
//	(d) the fully consistent witness (ballot 0 treated as invalid everywhere)
//	    is accepted, its CReg differs from the baseline and the tally lost the vote.
func TestRegOkFlip(t *testing.T) {
	field := ecc.BN254.ScalarField()
	sb := buildScenario(t, generateSyntheticScenario(3), 1<<10)

	if err := test.IsSolved(sb.skeleton, &sb.assignment, field); err != nil {
		t.Fatalf("baseline witness rejected: %v", err)
	}

	// (b)
	a := sb.assignment
	a.RegOk = append([]frontend.Variable{}, sb.assignment.RegOk...)
	a.RegOk[0] = 0
	if err := test.IsSolved(sb.skeleton, &a, field); err == nil {
		t.Fatal("flipped RegOk[0] with the old CReg was accepted")
	}

	// (c)
	flippedRegOk := append([]bool{}, sb.regOk...)
	flippedRegOk[0] = false
	b := a
	b.CReg = computeCReg(sb.alphaReg, sb.tupleHashes, flippedRegOk)
	if b.CReg.(*big.Int).Cmp(sb.creg) == 0 {
		t.Fatal("CReg did not change when RegOk[0] flipped")
	}
	if err := test.IsSolved(sb.skeleton, &b, field); err == nil {
		t.Fatal("flipped RegOk[0] with matching CReg but unchanged views was accepted (validity bit did not flip)")
	}

	// (d)
	flippedValidity := append([]bool{}, sb.validity...)
	flippedValidity[0] = false
	c := sb.assignmentFor(flippedValidity, flippedRegOk)
	if err := test.IsSolved(sb.skeleton, &c, field); err != nil {
		t.Fatalf("consistent witness with ballot 0 invalid rejected: %v", err)
	}
	if c.CReg.(*big.Int).Cmp(sb.creg) == 0 {
		t.Fatal("CReg unchanged")
	}
	sum := func(tally []frontend.Variable) *big.Int {
		s := new(big.Int)
		for _, v := range tally {
			s.Add(s, v.(*big.Int))
		}
		return s
	}
	if got, want := sum(c.Tally), new(big.Int).Sub(sum(sb.expectedTally), big.NewInt(1)); got.Cmp(want) != 0 {
		t.Fatalf("tally after invalidating ballot 0: got %s, want %s", got, want)
	}
}

// TestTupleHashMatchesVoterOpening checks that the tuple hash accumulated by
// circuit 1 is exactly the TupleHash public input of the voter opening circuit
// (same Poseidon2 instance, domain tag and input order).
func TestTupleHashMatchesVoterOpening(t *testing.T) {
	sb := buildScenario(t, generateSyntheticScenario(2), 1<<10)
	cfg := voteropening.DefaultConfig()
	for i, pb := range sb.plain {
		var o *voteropening.Opening
		for {
			var err error
			o, err = voteropening.ComputeOpening(cfg, big.NewInt(regTupleDomainTag), pb.PkAx, pb.PkAy, pb.PosReg,
				pb.B3_Rx, pb.B3_Ry, pb.B3_S, voteropening.RandomFr())
			if err == nil {
				break
			}
			if !errors.Is(err, voteropening.ErrResample) {
				t.Fatal(err)
			}
		}
		if o.TupleHash.Cmp(sb.tupleHashes[i]) != 0 {
			t.Fatalf("ballot %d: circuit-1 tuple hash %s != voter opening TupleHash %s", i, sb.tupleHashes[i].Text(16), o.TupleHash.Text(16))
		}
	}
}

// TestSyntheticGroth16Small runs the real prove path (compile, setup, prove,
// verify) on a small synthetic scenario with a 2^30-leaf registration tree.
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
