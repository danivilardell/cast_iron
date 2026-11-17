// Package voteropening implements the CTC-opening relation of Cast Iron
// (paper Fig. 2, "Open"): a registration transaction is a covert commitment
// to the message m = (pk_i, σreg) if its ECDSA nonce was c = H(m ∥ r) for the
// committed randomness r, i.e.
//
//	c  = (h1·2^k + h2) mod n,  h1 = Poseidon(m ∥ r),  h2 = Poseidon(m ∥ r ∥ WideHashTag)
//	rσ = x([c]G)               on secp256k1 (emulated over the proving field, k its bit length)
//
// The tallying circuit evaluates this relation once per ballot with
// FixedBaseGadget (castiron_circuit.go, registrationOpeningBit); the
// registration client evaluates it natively with ComputeOpeningMsg (the Python
// client in ctc/ computes the same values).  The secp256k1 part is a windowed
// fixed-base multiplication with constant tables (fixedbase.go).
package voteropening

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

// FixedBaseGadget evaluates the relation in-circuit.  The constant tables are
// built once and serve every scalar in the same circuit (one opening check per
// ballot in the tallying circuit).
type FixedBaseGadget struct {
	api   frontend.API
	curve *sw_emulated.Curve[Fp, Fr]
	fp    *emulated.Field[Fp]
	fr    *emulated.Field[Fr]
	tabs  *fixedBaseTables
	opts  FixedBaseOptions
}

// NewFixedBaseGadget precomputes the tables for nbBits-bit scalars (ScalarBits
// for the nonce derived by NonceBitsWide).
func NewFixedBaseGadget(api frontend.API, opts FixedBaseOptions, nbBits int) (*FixedBaseGadget, error) {
	tabs, err := newFixedBaseTables(opts.Window, nbBits)
	if err != nil {
		return nil, err
	}
	curve, err := sw_emulated.New[Fp, Fr](api, sw_emulated.GetSecp256k1Params())
	if err != nil {
		return nil, err
	}
	fp, err := emulated.NewField[Fp](api)
	if err != nil {
		return nil, err
	}
	fr, err := emulated.NewField[Fr](api)
	if err != nil {
		return nil, err
	}
	return &FixedBaseGadget{api: api, curve: curve, fp: fp, fr: fr, tabs: tabs, opts: opts}, nil
}

// MulBits returns [c]G for c = Σ bits[i]·2^i (bits boolean-constrained by the
// caller, len(bits) = nbBits, c ≠ 0; see fixedbase.go for the exceptional set).
func (g *FixedBaseGadget) MulBits(bits []frontend.Variable) (*sw_emulated.AffinePoint[Fp], error) {
	if len(bits) != g.tabs.nbBits {
		return nil, fmt.Errorf("expected %d scalar bits, got %d", g.tabs.nbBits, len(bits))
	}
	return fixedBaseMulWithTables(g.api, g.curve, g.fp, g.tabs, bits), nil
}

// XHalves returns the x-coordinate of P as two 128-bit halves (hi, lo), the
// form in which the record tree commits to a transaction's rσ.  The halves
// are read off the limbs of the reduced element: its value is below 2^256 and
// congruent to x mod p, hence equal to x unless x < 2^256 − p ≈ 2^32, which
// for a hash-derived point happens with probability ≈ 2^-224.
func (g *FixedBaseGadget) XHalves(P *sw_emulated.AffinePoint[Fp]) (hi, lo frontend.Variable) {
	var params Fp
	nbLimbs, limbBits := int(params.NbLimbs()), int(params.BitsPerLimb())
	if 128%limbBits != 0 || nbLimbs*limbBits != 256 {
		panic(fmt.Sprintf("unsupported limb layout %d×%d bits", nbLimbs, limbBits))
	}
	x := g.fp.Reduce(&P.X)
	half := nbLimbs / 2
	pack := func(limbs []frontend.Variable) frontend.Variable {
		v := frontend.Variable(0)
		for k := len(limbs) - 1; k >= 0; k-- {
			v = g.api.Add(g.api.Mul(v, pow2(limbBits)), limbs[k])
		}
		return v
	}
	return pack(x.Limbs[half:]), pack(x.Limbs[:half])
}

// NonceBitsWide derives the nonce c = (h1·2^k + h2) mod n from the two
// Poseidon outputs and returns its ScalarBits bits (canonical) together with
// the soft bit [c ≠ 0].  The reduction is done in the emulated scalar field
// (NonceFromHashes is the native counterpart).
func (g *FixedBaseGadget) NonceBitsWide(h1, h2 frontend.Variable) ([]frontend.Variable, frontend.Variable) {
	nb := g.api.Compiler().FieldBitLen() // k: 254 for BN254, 255 for BLS12-381
	H1 := g.fr.FromBits(g.api.ToBinary(h1, nb)...)
	H2 := g.fr.FromBits(g.api.ToBinary(h2, nb)...)
	shift := g.fr.NewElement(pow2(nb))
	C := g.fr.Add(g.fr.Mul(H1, shift), H2)
	C = g.fr.ReduceStrict(C)
	nonzero := g.api.Sub(1, g.fr.IsZero(C))
	return g.fr.ToBits(C), nonzero
}
