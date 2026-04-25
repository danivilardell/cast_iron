package main

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type MultiplicationCircuit struct {
	X frontend.Variable `gnark:",secret"`
	Y frontend.Variable `gnark:",secret"`

	Z frontend.Variable `gnark:",public"`
}

func (circuit *MultiplicationCircuit) Define(api frontend.API) error {
	// Compute x * y
	product := api.Mul(circuit.X, circuit.Y)

	// Assert that x * y == z
	api.AssertIsEqual(product, circuit.Z)

	return nil
}

func main() {
	var circuit MultiplicationCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}

	assignment := MultiplicationCircuit{
		X: 3,
		Y: 5,
		Z: 15,
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}

	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		panic(err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Println("❌ Verification failed:", err)
	} else {
		fmt.Println("✅ Proof verified successfully!")
		fmt.Println("\nCircuit Details:")
		fmt.Printf("  - Private inputs: x = 3, y = 5\n")
		fmt.Printf("  - Public output: z = 15\n")
		fmt.Printf("  - Proven: x * y = z\n")
	}
}
