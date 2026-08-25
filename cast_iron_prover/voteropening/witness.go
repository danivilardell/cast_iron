package voteropening

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	poseidonbls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/poseidon2"
	poseidonbn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	gnarkhash "github.com/consensys/gnark-crypto/hash"
)

// ErrResample is returned by ComputeOpening when the derived nonce is unusable
// (c = 0, or x([c]G) ≥ n so that the ECDSA r-component would differ from the
// x-coordinate).  Both have probability ≈ 2^-128; the registration client
// simply draws fresh randomness r.
var ErrResample = errors.New("voteropening: resample commitment randomness")

// mdHasher wraps gnark-crypto's Merkle–Damgård Poseidon2 (width 2, 6/50
// rounds, over the proving curve's scalar field) so that it matches the
// in-circuit hasher of newPoseidon.
type mdHasher struct {
	h     gnarkhash.StateStorer
	field *big.Int
}

func newMD() *mdHasher { return newMDFor(ecc.BN254) }

func newMDFor(curve ecc.ID) *mdHasher {
	switch curve {
	case ecc.BN254:
		return &mdHasher{h: poseidonbn254.NewMerkleDamgardHasher(), field: curve.ScalarField()}
	case ecc.BLS12_377:
		// explicit parameters: the BLS12-377 defaults differ from (2, 6, 50)
		perm := poseidonbls12377.NewPermutation(poseidonWidth, poseidonFullRounds, poseidonPartialRounds)
		return &mdHasher{h: gnarkhash.NewMerkleDamgardHasher(perm, make([]byte, 32)), field: curve.ScalarField()}
	}
	panic("unsupported curve " + curve.String())
}

func (m *mdHasher) write(vals ...*big.Int) {
	for _, v := range vals {
		b := new(big.Int).Mod(v, m.field).FillBytes(make([]byte, 32)) // big-endian regular form, as fr.Element.Bytes()
		if _, err := m.h.Write(b); err != nil {
			panic(err)
		}
	}
}

func (m *mdHasher) sum() *big.Int { return new(big.Int).SetBytes(m.h.Sum(nil)) }

// PoseidonMD hashes field elements exactly like the circuit's Poseidon hasher
// (BN254 configuration).
func PoseidonMD(vals ...*big.Int) *big.Int { return PoseidonMDFor(ecc.BN254, vals...) }

// PoseidonMDFor is PoseidonMD over the given proving curve's scalar field.
func PoseidonMDFor(curve ecc.ID, vals ...*big.Int) *big.Int {
	m := newMDFor(curve)
	m.write(vals...)
	return m.sum()
}

// Opening is everything the voter holds about one covert registration.
type Opening struct {
	Cfg Config

	Dom, PkAx, PkAy, PosReg *big.Int
	SigRx, SigRy, SigS      *big.Int // σreg
	R                       *big.Int // commitment randomness

	HSig  *big.Int // Poseidon(σreg)
	C     *big.Int // nonce c = H(σreg ∥ r) ∈ [1, n-1]
	Point secp256k1.G1Affine
	Rsig  *big.Int // x([c]G) = ECDSA r-component

	TupleHash       *big.Int
	EntryCommitment *big.Int
}

// NonceFromHashes derives the nonce from the Poseidon outputs according to cfg.
func NonceFromHashes(cfg Config, h1, h2 *big.Int) *big.Int {
	if cfg.Hash == HashNarrow {
		return new(big.Int).Set(h1)
	}
	c := new(big.Int).Lsh(h1, uint(cfg.FrBits()))
	c.Add(c, h2)
	return c.Mod(c, secpOrder)
}

// ComputeOpening derives the nonce, the point [c]G and the two public
// commitments from the voter's data.
func ComputeOpening(cfg Config, dom, pkAx, pkAy, posReg, sigRx, sigRy, sigS, r *big.Int) (*Opening, error) {
	m := newMDFor(cfg.CurveID())
	m.write(sigRx, sigRy, sigS)
	hSig := m.sum()
	m.write(r)
	h1 := m.sum()
	var h2 *big.Int
	if cfg.Hash == HashWide {
		m.write(big.NewInt(wideHashTag))
		h2 = m.sum()
	}
	c := NonceFromHashes(cfg, h1, h2)
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
		Cfg: cfg,
		Dom: dom, PkAx: pkAx, PkAy: pkAy, PosReg: posReg,
		SigRx: sigRx, SigRy: sigRy, SigS: sigS, R: r,
		HSig: hSig, C: c, Point: P, Rsig: x,
		TupleHash:       PoseidonMDFor(cfg.CurveID(), dom, pkAx, pkAy, posReg, hSig),
		EntryCommitment: PoseidonMDFor(cfg.CurveID(), big.NewInt(entryDomainTag), posReg, hi, lo),
	}, nil
}

// Assignment returns the full witness for the circuit.
func (o *Opening) Assignment() *Circuit {
	hi, lo := split128(o.Rsig)
	return &Circuit{
		TupleHash:       o.TupleHash,
		EntryCommitment: o.EntryCommitment,
		Dom:             o.Dom,
		PkAx:            o.PkAx,
		PkAy:            o.PkAy,
		PosReg:          o.PosReg,
		SigRx:           o.SigRx,
		SigRy:           o.SigRy,
		SigS:            o.SigS,
		R:               o.R,
		RsigHi:          hi,
		RsigLo:          lo,
	}
}

func split128(x *big.Int) (hi, lo *big.Int) {
	mask := new(big.Int).Sub(pow2(128), big.NewInt(1))
	lo = new(big.Int).And(x, mask)
	hi = new(big.Int).Rsh(x, 128)
	return hi, lo
}

// RandomFr samples a uniform BN254 scalar-field element.
func RandomFr() *big.Int { return RandomFieldElement(Config{}) }

// RandomFieldElement samples a uniform element of cfg's proving field.
func RandomFieldElement(cfg Config) *big.Int {
	v, err := rand.Int(rand.Reader, cfg.Field())
	if err != nil {
		panic(err)
	}
	return v
}

// RandomOpening builds an opening from random inputs (resampling r if needed).
func RandomOpening(cfg Config) *Opening {
	r := func() *big.Int { return RandomFieldElement(cfg) }
	for {
		o, err := ComputeOpening(cfg, r(), r(), r(), r(), r(), r(), r(), r())
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
