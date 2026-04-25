package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/std/hash/mimc"
)

type MerkleCircuit struct {
	Root      frontend.Variable   `gnark:",public"`
	LeafIndex frontend.Variable   `gnark:",secret"`
	Path      []frontend.Variable `gnark:",secret"`
}

func (c *MerkleCircuit) Define(api frontend.API) error {
	h, _ := mimc.NewMiMC(api)
	proof := merkle.MerkleProof{
		RootHash: c.Root,
		Path:     c.Path,
	}
	proof.VerifyProof(api, &h, c.LeafIndex)
	return nil
}

func main() {
	const numLeaves = 9
	depth := int(math.Ceil(math.Log2(numLeaves)))
	const segmentSize = 32
	const proveIndex = 5

	// Build tree data using BuildReaderProof
	mod := ecc.BN254.ScalarField()
	modNbBytes := len(mod.Bytes())

	var buf bytes.Buffer
	for i := 0; i < numLeaves; i++ {
		leaf, _ := rand.Int(rand.Reader, mod)
		b := leaf.Bytes()
		buf.Write(make([]byte, modNbBytes-len(b)))
		buf.Write(b)
	}

	// Create proof using merkletree library
	hGo := hash.MIMC_BN254.New()
	merkleRoot, proofPath, _, err := merkletree.BuildReaderProof(&buf, hGo, segmentSize, proveIndex)
	if err != nil {
		panic(err)
	}

	// Verify proof in plain Go
	verified := merkletree.VerifyProof(hGo, merkleRoot, proofPath, proveIndex, uint64(numLeaves))
	fmt.Printf("✓ Plain Go verification: %v\n", verified)

	// Setup circuit
	circuit := MerkleCircuit{
		Root:      0,
		LeafIndex: 0,
		Path:      make([]frontend.Variable, depth+1),
	}
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	pk, vk, _ := groth16.Setup(ccs)
	fmt.Printf("✓ Circuit compiled with %d constraints\n", ccs.GetNbConstraints())

	// Create witness
	pathVars := make([]frontend.Variable, depth+1)
	for i := 0; i < depth+1; i++ {
		pathVars[i] = proofPath[i]
	}

	witness, _ := frontend.NewWitness(&MerkleCircuit{
		Root:      merkleRoot,
		LeafIndex: proveIndex,
		Path:      pathVars,
	}, ecc.BN254.ScalarField())

	// Prove and verify
	proof, _ := groth16.Prove(ccs, pk, witness)
	pub, _ := witness.Public()

	if err := groth16.Verify(proof, vk, pub); err != nil {
		fmt.Println("❌", err)
	} else {
		fmt.Printf("✅ Merkle proof verified in zkSNARK! Leaf #%d in tree of %d leaves\n", proveIndex, numLeaves)
	}
}
