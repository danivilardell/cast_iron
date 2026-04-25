package main

import (
	"crypto/rand"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	poseidonbn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
)

/* ----------------------------- helpers: encoding ------------------------------ */

func fieldToBigInt(e fr.Element) *big.Int {
	b := e.Bytes()
	return new(big.Int).SetBytes(b[:])
}

type byteWriter interface{ Write([]byte) (int, error) }

func writeField(h byteWriter, val *big.Int) {
	var el fr.Element
	el.SetBigInt(val)
	buf := el.Bytes()
	_, _ = h.Write(buf[:])
}

/* ---------------------------- Poseidon helpers -------------------------------- */

func poseidonHashBytes(vals ...*big.Int) []byte {
	hasher := poseidonbn254.NewMerkleDamgardHasher()
	for _, v := range vals {
		writeField(hasher, v)
	}
	return hasher.Sum(nil)
}

func poseidonHashFields(vals ...*big.Int) *big.Int {
	sum := poseidonHashBytes(vals...)
	return new(big.Int).SetBytes(sum)
}

/* ----------------------------- ElGamal helpers -------------------------------- */

func elgamalKeygen() (sk, g, h *big.Int) {
	p := ecc.BN254.ScalarField()
	sk, _ = rand.Int(rand.Reader, ecc.BN254.ScalarField())
	g = big.NewInt(5)
	h = new(big.Int).Exp(g, sk, p)
	return sk, g, h
}

func elgamalEncryptScalar(m, g, h *big.Int) (c1, c2 *big.Int) {
	p := ecc.BN254.ScalarField()
	r, _ := rand.Int(rand.Reader, p)
	c1 = new(big.Int).Exp(g, r, p)
	hr := new(big.Int).Exp(h, r, p)
	c2 = new(big.Int).Mul(m, hr)
	c2.Mod(c2, p)
	return c1, c2
}
