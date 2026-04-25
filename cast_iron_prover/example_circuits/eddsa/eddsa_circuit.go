package main

import (
	"crypto/rand"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	cryptoEddsa "github.com/consensys/gnark-crypto/signature/eddsa"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	stdEddsa "github.com/consensys/gnark/std/signature/eddsa"
)

// ----------------------------------------------------
// Circuit definition
// ----------------------------------------------------

type EddsaCircuit struct {
	PublicKey stdEddsa.PublicKey `gnark:",public"`
	Signature stdEddsa.Signature `gnark:",public"`
	Message   frontend.Variable  `gnark:",public"`
}

// Define implements the constraint system: verify the EdDSA signature.
func (circuit *EddsaCircuit) Define(api frontend.API) error {
	// create the twisted Edwards curve (BabyJubJub for BN254)
	curve, err := twistededwards.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}

	// MiMC hash for h(R, A, M)
	mimcHash, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// enforce signature verification constraints
	return stdEddsa.Verify(curve, circuit.Signature, circuit.Message, circuit.PublicKey, &mimcHash)
}

// ----------------------------------------------------
// Main test / usage
// ----------------------------------------------------

func main() {
	// Hash function used outside the circuit (must match inside)
	hFunc := hash.MIMC_BN254.New()

	// Generate EdDSA key pair over BabyJubJub (BN254 companion curve)
	privateKey, err := cryptoEddsa.New(tedwards.BN254, rand.Reader)
	if err != nil {
		panic(err)
	}
	publicKey := privateKey.Public()

	// Example message
	msg := []byte("zk-ed25519-test")

	// Sign the message
	signature, err := privateKey.Sign(msg, hFunc)
	if err != nil {
		panic(err)
	}

	// Verify signature in plain Go (outside the circuit)
	isValid, err := publicKey.Verify(signature, msg, hFunc)
	if err != nil || !isValid {
		panic("❌ Invalid signature outside circuit")
	}
	fmt.Println("✓ Valid EdDSA signature (plain Go check)")

	// Compile the circuit
	var circuit EddsaCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}
	fmt.Printf("✓ Circuit compiled with %d constraints\n", ccs.GetNbConstraints())

	// Setup Groth16
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}

	// Create witness (assign message, public key, and signature)
	var assignment EddsaCircuit
	assignment.Message = msg
	assignment.PublicKey.Assign(tedwards.BN254, publicKey.Bytes())
	assignment.Signature.Assign(tedwards.BN254, signature)

	// Build witnesses
	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	// Prove and verify
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		panic(err)
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Println("❌ ZK proof verification failed:", err)
	} else {
		fmt.Println("✅ ZK proof verified successfully (EdDSA signature correct)")
	}
}
