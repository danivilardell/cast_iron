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
// registration: the nonce c = H(m ∥ r) and rσ = x([c]G), the ECDSA
// r-component of the registration transaction that the tallying circuit
// checks against the record tree (castiron_circuit.go, registrationOpeningBit).
type Opening struct {
	Msg []*big.Int // committed message m as field elements
	R   *big.Int   // commitment randomness

	// σreg when the opening was built by ComputeOpening (m = σreg).
	SigRx, SigRy, SigS *big.Int

	H1, H2 *big.Int           // Poseidon(m ∥ r), Poseidon(m ∥ r ∥ WideHashTag)
	C      *big.Int           // nonce c = (H1·2^k + H2) mod n ∈ [1, n-1]
	Point  secp256k1.G1Affine // [c]G
	Rsig   *big.Int           // x([c]G) < n
	RsigHi *big.Int           // Rsig = RsigHi·2^128 + RsigLo, the form committed in the record tree
	RsigLo *big.Int
}

// NonceFromHashes derives the nonce c = (h1·2^k + h2) mod n from the two
// Poseidon outputs, k the bit length of the proving field (254 on BN254; the
// native form of FixedBaseGadget.NonceBitsWide).  The ≥508-bit value reduced
// mod n is within 2^-252 of uniform on [0, n).
func NonceFromHashes(h1, h2 *big.Int) *big.Int {
	c := new(big.Int).Lsh(h1, uint(shared.Field.BitLen()))
	c.Add(c, h2)
	return c.Mod(c, secpOrder)
}

// RegistrationMessage is the message a Cast Iron registration commits to,
// m = (pk_i, σreg) (paper Section 5.1), as the field elements the circuit
// hashes: the voting key's coordinates followed by σreg = (R.x, R.y, S).
func RegistrationMessage(pkX, pkY, sigRx, sigRy, sigS *big.Int) []*big.Int {
	return []*big.Int{pkX, pkY, sigRx, sigRy, sigS}
}

// ComputeOpeningMsg is the registration client's side of the relation: it
// derives the nonce and rσ from the message m (field elements) and the
// commitment randomness r, hashing exactly like the tallying circuit.
func ComputeOpeningMsg(msg []*big.Int, r *big.Int) (*Opening, error) {
	in := append(append([]*big.Int{}, msg...), r)
	h1 := shared.PoseidonMD(in...)
	h2 := shared.PoseidonMD(append(in, big.NewInt(WideHashTag))...)
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
	return &Opening{Msg: msg, R: r, H1: h1, H2: h2, C: c, Point: P, Rsig: x, RsigHi: hi, RsigLo: lo}, nil
}

// ComputeOpening is ComputeOpeningMsg for the three-element message
// m = σreg = (R.x, R.y, S).  The tallying circuit commits to (pk_i, σreg)
// (RegistrationMessage); this form is kept for the cross-language test
// vectors of ctc/tests/gen_vectors.
func ComputeOpening(sigRx, sigRy, sigS, r *big.Int) (*Opening, error) {
	o, err := ComputeOpeningMsg([]*big.Int{sigRx, sigRy, sigS}, r)
	if err != nil {
		return nil, err
	}
	o.SigRx, o.SigRy, o.SigS = sigRx, sigRy, sigS
	return o, nil
}

func split128(x *big.Int) (hi, lo *big.Int) {
	mask := new(big.Int).Sub(pow2(128), big.NewInt(1))
	lo = new(big.Int).And(x, mask)
	hi = new(big.Int).Rsh(x, 128)
	return hi, lo
}

// RandomOpening builds an opening of a random registration message
// (resampling r if needed).
func RandomOpening() *Opening {
	msg := RegistrationMessage(shared.RandomScalar(), shared.RandomScalar(), shared.RandomScalar(), shared.RandomScalar(), shared.RandomScalar())
	for {
		o, err := ComputeOpeningMsg(msg, shared.RandomScalar())
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
