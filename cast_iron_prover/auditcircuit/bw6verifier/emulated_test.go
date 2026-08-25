package bw6verifier

import (
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

// emulatedOuter verifies a Groth16/BN254 proof inside a BN254 circuit with
// gnark's emulated pairing (the "no curve change" alternative).  Compile-only
// cost reference; set BN254_EMULATED=1 (several minutes, ~10 GB).
type emulatedOuter struct {
	Proof   stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	VK      stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
	Witness stdgroth16.Witness[sw_bn254.ScalarField]
}

func (c *emulatedOuter) Define(api frontend.API) error {
	v, err := stdgroth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return err
	}
	return v.AssertProof(c.VK, c.Proof, c.Witness)
}

func TestEmulatedBN254Cost(t *testing.T) {
	if os.Getenv("BN254_EMULATED") == "" {
		t.Skip("set BN254_EMULATED=1")
	}
	innerCcs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &innerCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(innerCcs.GetCommitments().(constraint.Groth16Commitments)); n != 1 {
		t.Fatalf("inner circuit has %d commitments, want 1", n)
	}
	outer := &emulatedOuter{
		Proof:   stdgroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerCcs),
		VK:      stdgroth16.PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerCcs),
		Witness: stdgroth16.PlaceholderWitness[sw_bn254.ScalarField](innerCcs),
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, outer)
	if err != nil {
		t.Fatal(err)
	}
	msg := "emulated BN254-in-BN254 Groth16 verification (gnark AssertProof, 2 public inputs, 1 commitment): " + itoa(ccs.GetNbConstraints()) + " constraints"
	t.Log(msg)
	_ = os.WriteFile("results/emulated_bn254_cost.txt", []byte(msg+"\n"), 0o644)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
