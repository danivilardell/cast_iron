package voteropening

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"

	"cast_iron/shared"
)

// ErrResample is returned by ComputeOpening when the derived nonce is unusable
// (c = 0, or x([c]G) ≥ n so that the ECDSA r-component would differ from the
// x-coordinate).  Both have probability ≈ 2^-128; the registration client
// simply draws fresh randomness r.
var ErrResample = errors.New("voteropening: resample commitment randomness")

// Opening is everything the registration client derives for one covert
// registration: the nonce c = H(σreg ∥ r) and rσ = x([c]G), the ECDSA
// r-component of the registration transaction that the tallying circuit
// checks against the record tree (castiron_circuit.go, registrationOpeningBit).
type Opening struct {
	SigRx, SigRy, SigS *big.Int // σreg (ballot component B3)
	R                  *big.Int // commitment randomness

	HSig   *big.Int           // Poseidon(σreg): the chaining state the circuit continues from
	H1, H2 *big.Int           // Poseidon(σreg ∥ r), Poseidon(σreg ∥ r ∥ WideHashTag)
	C      *big.Int           // nonce c = (H1·2^254 + H2) mod n ∈ [1, n-1]
	Point  secp256k1.G1Affine // [c]G
	Rsig   *big.Int           // x([c]G) < n
	RsigHi *big.Int           // Rsig = RsigHi·2^128 + RsigLo, the witness form used in-circuit
	RsigLo *big.Int
}

// NonceFromHashes derives the nonce c = (h1·2^254 + h2) mod n from the two
// Poseidon outputs (the native form of FixedBaseGadget.NonceBitsWide).  The
// 508-bit value reduced mod n is within 2^-252 of uniform on [0, n).
func NonceFromHashes(h1, h2 *big.Int) *big.Int {
	c := new(big.Int).Lsh(h1, frBits)
	c.Add(c, h2)
	return c.Mod(c, secpOrder)
}

// ComputeOpening is the registration client's side of the relation: it derives
// the nonce and rσ from σreg and the commitment randomness r, hashing exactly
// like the tallying circuit (Merkle–Damgård Poseidon2 continued from
// Poseidon(σreg), see shared.NewPoseidonHasherFromState).
func ComputeOpening(sigRx, sigRy, sigS, r *big.Int) (*Opening, error) {
	hSig := shared.PoseidonMD(sigRx, sigRy, sigS)
	h1 := shared.PoseidonMD(sigRx, sigRy, sigS, r)
	h2 := shared.PoseidonMD(sigRx, sigRy, sigS, r, big.NewInt(WideHashTag))
	c := NonceFromHashes(h1, h2)
	if c.Sign() == 0 {
		return nil, ErrResample
	}
	var P secp256k1.G1Affine
	P.ScalarMultiplicationBase(c)
	x := P.X.BigInt(new(big.Int))
	if x.Cmp(secpOrder) >= 0 {
		return nil, ErrResample
	}
	hi, lo := split128(x)
	return &Opening{
		SigRx: sigRx, SigRy: sigRy, SigS: sigS, R: r,
		HSig: hSig, H1: h1, H2: h2, C: c, Point: P, Rsig: x, RsigHi: hi, RsigLo: lo,
	}, nil
}

func split128(x *big.Int) (hi, lo *big.Int) {
	mask := new(big.Int).Sub(pow2(128), big.NewInt(1))
	lo = new(big.Int).And(x, mask)
	hi = new(big.Int).Rsh(x, 128)
	return hi, lo
}

// RandomOpening builds an opening from random inputs (resampling r if needed).
func RandomOpening() *Opening {
	for {
		o, err := ComputeOpening(shared.RandomScalar(), shared.RandomScalar(), shared.RandomScalar(), shared.RandomScalar())
		if err == nil {
			return o
		}
		if !errors.Is(err, ErrResample) {
			panic(err)
		}
	}
}

// SignWithNonce produces the ECDSA signature (rσ, sσ) of Fig. 2 over the
// transaction hash msgHash with the nonce c:  rσ = x([c]G) mod n,
// sσ = c^{-1}(msgHash + rσ·sk) mod n.
func SignWithNonce(sk, msgHash, c *big.Int) (r, s *big.Int, err error) {
	n := secpOrder
	if c.Sign() == 0 || c.Cmp(n) >= 0 {
		return nil, nil, fmt.Errorf("nonce out of range")
	}
	var P secp256k1.G1Affine
	P.ScalarMultiplicationBase(c)
	r = P.X.BigInt(new(big.Int))
	r.Mod(r, n)
	if r.Sign() == 0 {
		return nil, nil, fmt.Errorf("r = 0")
	}
	s = new(big.Int).Mul(r, sk)
	s.Add(s, msgHash)
	s.Mul(s, new(big.Int).ModInverse(c, n))
	s.Mod(s, n)
	if s.Sign() == 0 {
		return nil, nil, fmt.Errorf("s = 0")
	}
	return r, s, nil
}

// VerifyECDSA is a textbook ECDSA verifier (no low-s normalisation), used to
// check that SignWithNonce produces signatures an ordinary verifier accepts.
func VerifyECDSA(pk *secp256k1.G1Affine, msgHash, r, s *big.Int) bool {
	n := secpOrder
	if r.Sign() <= 0 || r.Cmp(n) >= 0 || s.Sign() <= 0 || s.Cmp(n) >= 0 {
		return false
	}
	w := new(big.Int).ModInverse(s, n)
	u1 := new(big.Int).Mul(msgHash, w)
	u1.Mod(u1, n)
	u2 := new(big.Int).Mul(r, w)
	u2.Mod(u2, n)
	var a, b secp256k1.G1Affine
	a.ScalarMultiplicationBase(u1)
	b.ScalarMultiplication(pk, u2)
	a.Add(&a, &b)
	if a.IsInfinity() {
		return false
	}
	x := a.X.BigInt(new(big.Int))
	x.Mod(x, n)
	return x.Cmp(r) == 0
}
