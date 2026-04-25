package main

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	// native Poseidon2 permutation (BN254)
	swPoseidon "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	// in‑circuit Poseidon2 permutation (BN254, width=3)
	circuitPoseidon2 "github.com/consensys/gnark/std/permutation/poseidon2"
)

// -------------------------- Native Duplex Encryption --------------------------

// poseidonDuplexEncrypt implements a Poseidon2-based duplex sponge encryption
// scheme similar in spirit to the circom implementation you referenced, but
// instantiated with width=3 (rate=2, capacity=1) on BN254.
//
// State layout (width = 3):
//
//	S = (0, k[0], k[1] + nonce + l * 2^128)
//
// For each block of 2 message elements:
//   - apply Poseidon2 permutation to S
//   - absorb msg into S[1], S[2]
//   - output S[1], S[2] as ciphertext
//
// After all blocks:
//   - apply Poseidon2 permutation once more
//   - output S[1] as final authentication element.
func poseidonDuplexEncrypt(msg []fr.Element, key [2]fr.Element, nonce fr.Element) []fr.Element {
	// Clone & pad message to a multiple of 2 (rate = 2)
	message := make([]fr.Element, len(msg))
	copy(message, msg)
	for len(message)%2 != 0 {
		message = append(message, fr.Element{}) // pad with zero
	}

	l := len(msg)

	// two128 = 2^128 in Fr
	two128Big := new(big.Int).Lsh(big.NewInt(1), 128)
	var two128 fr.Element
	two128.SetBigInt(two128Big)

	// l * 2^128
	var lElem fr.Element
	lElem.SetUint64(uint64(l))
	lElem.Mul(&lElem, &two128)

	// Initial state S = (0, k[0], k[1] + nonce + l * 2^128)
	state := make([]fr.Element, 3)
	// state[0] = 0 (already zero)
	state[1] = key[0]
	state[2].Add(&key[1], &nonce)
	state[2].Add(&state[2], &lElem)

	// Poseidon2 permutation (width=3, fullRounds=8, partialRounds=40)
	perm := swPoseidon.NewPermutation(3, 8, 40)

	nBlocks := len(message) / 2
	ciphertexts := make([]fr.Element, 0, 2*nBlocks+1)

	for i := 0; i < nBlocks; i++ {
		// Permute state
		perm.Permutation(state)

		// Absorb and squeeze two words
		for j := 0; j < 2; j++ {
			idx := 2*i + j
			state[1+j].Add(&state[1+j], &message[idx])

			var ct fr.Element
			ct = state[1+j]
			ciphertexts = append(ciphertexts, ct)
		}
	}

	// Finalization: one more permutation and output S[1]
	perm.Permutation(state)
	ciphertexts = append(ciphertexts, state[1])

	return ciphertexts
}

// -------------------------- Circuit: Duplex Decrypt ---------------------------

// PoseidonDuplexDecryptCircuit checks that a given ciphertext decrypts under
// the duplex sponge scheme above to the provided plaintext.
//
// The circuit replays the decryption:
//   - same initial state
//   - same Poseidon2 permutation (width=3)
//   - for each block:
//     state = Perm(state)
//     m[i]   = c[i] - state[1+j]
//     state[1+j] = c[i]
//   - final check on last ciphertext element == state[1]
//   - padding elements beyond plaintext length must be zero.
type PoseidonDuplexDecryptCircuit struct {
	Key         [2]frontend.Variable `gnark:",secret"`
	Nonce       frontend.Variable    `gnark:",public"`
	Ciphertexts []frontend.Variable  `gnark:",public"`
	Plaintexts  []frontend.Variable  `gnark:",public"`
}

func (c *PoseidonDuplexDecryptCircuit) Define(api frontend.API) error {
	L := len(c.Plaintexts)
	if L == 0 {
		return nil
	}

	// Number of message blocks of size 2
	nBlocks := (L + 1) / 2

	// Allocate and initialize state: S = (0, k[0], k[1] + nonce + L * 2^128)
	state := make([]frontend.Variable, 3)
	state[0] = 0
	state[1] = c.Key[0]

	// Compute L * 2^128 as a constant
	two128 := new(big.Int).Lsh(big.NewInt(1), 128)
	lTimesTwo128 := new(big.Int).Mul(big.NewInt(int64(L)), two128)

	nonceTerm := api.Add(c.Nonce, lTimesTwo128)
	state[2] = api.Add(c.Key[1], nonceTerm)

	// Instantiate in‑circuit Poseidon2 permutation with matching parameters
	perm, err := circuitPoseidon2.NewPoseidon2FromParameters(api, 3, 8, 40)
	if err != nil {
		return err
	}

	// Ciphertexts layout:
	//   - first 2*nBlocks elements: body
	//   - last element: final tag
	if len(c.Ciphertexts) < 2*nBlocks+1 {
		return fmt.Errorf("ciphertext too short for configured plaintext length")
	}

	bodyLen := 2 * nBlocks
	body := c.Ciphertexts[:bodyLen]
	tag := c.Ciphertexts[bodyLen]

	// Decrypt message words (including padded zeros)
	msgRecovered := make([]frontend.Variable, bodyLen)

	for i := 0; i < nBlocks; i++ {
		if err := perm.Permutation(state); err != nil {
			return err
		}

		for j := 0; j < 2; j++ {
			idx := 2*i + j
			if idx >= bodyLen {
				break
			}

			mask := state[1+j]
			m := api.Sub(body[idx], mask)
			msgRecovered[idx] = m

			// Update state lane with ciphertext
			state[1+j] = body[idx]
		}
	}

	// Enforce that the first L elements equal the provided plaintext
	for i := 0; i < L; i++ {
		api.AssertIsEqual(msgRecovered[i], c.Plaintexts[i])
	}

	// If padding was added, enforce those tail elements are zero
	for i := L; i < bodyLen; i++ {
		api.AssertIsEqual(msgRecovered[i], 0)
	}

	// Final permutation and tag check
	if err := perm.Permutation(state); err != nil {
		return err
	}
	api.AssertIsEqual(tag, state[1])

	return nil
}

// ------------------------------------ main -----------------------------------

func main() {
	// Example parameters
	var key [2]fr.Element
	key[0].SetUint64(42)
	key[1].SetUint64(1337)

	var nonce fr.Element
	nonce.SetUint64(123456)

	plaintexts := []fr.Element{
		fr.NewElement(1),
		fr.NewElement(0),
		fr.NewElement(10),
	}

	// 1. Native encryption (duplex Poseidon2, width=3)
	ciphertexts := poseidonDuplexEncrypt(plaintexts, key, nonce)

	// 2. Circuit compilation
	var circuit PoseidonDuplexDecryptCircuit
	circuit.Ciphertexts = make([]frontend.Variable, len(ciphertexts))
	circuit.Plaintexts = make([]frontend.Variable, len(plaintexts))

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}
	fmt.Printf("✓ Poseidon2 Duplex Circuit compiled with %d constraints\n", ccs.GetNbConstraints())

	// 3. Proving and verification
	assignment := PoseidonDuplexDecryptCircuit{
		Ciphertexts: make([]frontend.Variable, len(ciphertexts)),
		Plaintexts:  make([]frontend.Variable, len(plaintexts)),
	}
	assignment.Key[0] = key[0]
	assignment.Key[1] = key[1]
	assignment.Nonce = nonce
	for i := range ciphertexts {
		assignment.Ciphertexts[i] = ciphertexts[i]
	}
	for i := range plaintexts {
		assignment.Plaintexts[i] = plaintexts[i]
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}

	pk, vk, err := groth16.Setup(ccs)
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

	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		fmt.Printf("❌ Verification failed: %v\n", err)
	} else {
		fmt.Println("✅ ZK proof for Poseidon2 duplex encryption verified!")
	}
}
