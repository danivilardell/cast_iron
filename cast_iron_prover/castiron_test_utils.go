package main

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	"cast_iron/shared"
)

/* ----------------------------- helpers: encoding ------------------------------ */

func fieldToBigInt(e fr.Element) *big.Int { return shared.FieldToBigInt(e) }

/* ---------------------------- Poseidon helpers -------------------------------- */

func poseidonHashBytes(vals ...*big.Int) []byte {
	return poseidonHashFields(vals...).FillBytes(make([]byte, fr.Bytes))
}

func poseidonHashFields(vals ...*big.Int) *big.Int { return shared.PoseidonMD(vals...) }

/* ----------------------------- ElGamal helpers -------------------------------- */

func elgamalKeygen() (sk, g, h *big.Int) { return shared.ElGamalKeygen() }

func elgamalEncryptScalar(m, g, h *big.Int) (c1, c2 *big.Int) {
	return shared.ElGamalEncryptScalar(m, g, h)
}

/* ------------------------ registration-opening accumulator ------------------------ */

func regTupleHashNative(pkAx, pkAy, posReg, hB3 *big.Int) *big.Int {
	return shared.RegTupleHashNative(pkAx, pkAy, posReg, hB3)
}

func cregAlphaNative(eid, voterRoot, regRoot *big.Int) *big.Int {
	return shared.CRegAlphaNative(eid, voterRoot, regRoot)
}

func computeCReg(alpha *big.Int, tupleHashes []*big.Int, regOk []bool) *big.Int {
	return shared.ComputeCReg(alpha, tupleHashes, regOk)
}
