package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"cast_iron/shared"
)

// TestConstraintModel compiles n = 1 and n = 2 ballots for the record sizes of
// Figure 4 (and 2^33) and prints the exact affine model
// constraints(n) = A + B·n of the tallying circuit (voter-roll path length 1,
// i.e. the n = 1 grid point; each extra voter-roll level adds 2 Poseidon
// permutations + decryption per ballot).  Set CASTIRON_COUNTS_ONLY=1 to skip
// the larger depths.
func TestConstraintModel(t *testing.T) {
	depths := []int{10, 20, 30, 33}
	if os.Getenv("CASTIRON_COUNTS_ONLY") != "" {
		depths = []int{30}
	}
	for _, d := range depths {
		c := func(n int) int {
			ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, NewSkeleton(n, 2, 1, d))
			if err != nil {
				t.Fatal(err)
			}
			return ccs.GetNbConstraints()
		}
		c1, c2 := c(1), c(2)
		B := c2 - c1
		t.Logf("record depth %2d (ℓ = 2^%d): constraints(n) = %d + %d·n   (n=1: %d)", d, d, c1-B, B, c1)
	}
	_ = shared.MerkleHeight
	fmt.Println()
}
