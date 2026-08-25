// Package voteropening implements the voter-side CTC opening circuit of Cast
// Iron (paper Fig. 2, "Open"): a voter proves, once at registration time, that
// the ECDSA signature of their blockchain transaction was produced with the
// nonce c = H(σreg ∥ r), i.e. that the transaction is a covert commitment to
// their registration σreg.
//
// Relation (secp256k1 arithmetic emulated over the BN254 scalar field):
//
//	witness : σreg = (SigRx, SigRy, SigS)   -- the registration signature (3 field elements, opaque here)
//	          r                             -- commitment randomness
//	          rσ = (RsigHi, RsigLo)         -- r-component of the on-chain ECDSA signature (two 128-bit halves)
//	          dom, pkAx, pkAy, posReg       -- the remaining tuple fields bound by circuit 1
//	public  : TupleHash       = Poseidon(dom, pkAx, pkAy, posReg, Poseidon(σreg))
//	          EntryCommitment = Poseidon(entryDomainTag, posReg, RsigHi, RsigLo)   -- stands in for the record lookup M[t]
//	checks  : c  = H(σreg ∥ r) ∈ [1, n-1]        (Poseidon2, see HashMode)
//	          rσ = x( [c]G )                    on secp256k1
//	          the two public hashes recompute.
//
// The proving curve is BN254 (Groth16).
package voteropening

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	stdhash "github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/permutation/poseidon2"
)

// Fp and Fr are the secp256k1 base and scalar fields, emulated in-circuit.
type (
	Fp = emulated.Secp256k1Fp
	Fr = emulated.Secp256k1Fr
)

// Poseidon2 parameters: identical to the tallying circuit (castiron_circuit.go)
// and to gnark-crypto's default BN254 Poseidon2 (width 2, 6 full / 50 partial
// rounds), so all hashes are cross-checkable natively.
const (
	poseidonWidth         = 2
	poseidonFullRounds    = 6
	poseidonPartialRounds = 50

	bn254FrBits    = 254 // bit length of the BN254 scalar field (Poseidon output)
	secpScalarBits = 256 // bit length of the secp256k1 group order n

	entryDomainTag = 1 // domain tag of the record-entry commitment
	wideHashTag    = 1 // tag absorbed after h1 to derive h2 (HashWide)
)

// HashMode selects how the nonce c = H(σreg ∥ r) ∈ [1, n-1] is derived from
// Poseidon2 (whose output lives in the 254-bit field F_r ⊂ [0, n)).
type HashMode int

const (
	// HashNarrow: c = Poseidon2(σreg ∥ r).  Already < n, so no modular
	// reduction is needed (just a canonical 254-bit decomposition).  The nonce
	// is then uniform on a 2^254-element subset of [0, n); covertness then
	// rests on the (standard) short-exponent indistinguishability assumption
	// rather than on c being exactly uniform on [1, n-1].
	HashNarrow HashMode = iota
	// HashWide: c = (h1·2^254 + h2) mod n with h1 = Poseidon2(σreg ∥ r) and
	// h2 = Poseidon2(σreg ∥ r ∥ wideHashTag) (Merkle–Damgård continuation, one
	// extra permutation).  The 508-bit value reduced mod n is within 2^-252 of
	// uniform on [0, n), matching the random-oracle model of Theorem 2.  The
	// reduction is done in the emulated scalar field.
	HashWide
)

// MulMethod selects the in-circuit implementation of [c]G.
type MulMethod int

const (
	// MulWindowed: this package's fixed-base windowed gadget (fixedbase.go).
	MulWindowed MulMethod = iota
	// MulGnarkGLV: gnark's sw_emulated.ScalarMulBase (GLV + fake-GLV, EEMP25).
	MulGnarkGLV
	// MulGnarkDoubleAdd: gnark's ScalarMulBase without the endomorphism, i.e.
	// bit-by-bit double-and-add over the precomputed [2^i]G table.
	MulGnarkDoubleAdd
)

func (m HashMode) String() string {
	switch m {
	case HashNarrow:
		return "narrow"
	case HashWide:
		return "wide"
	}
	return fmt.Sprintf("hash(%d)", int(m))
}

func (m MulMethod) String() string {
	switch m {
	case MulWindowed:
		return "windowed"
	case MulGnarkGLV:
		return "gnark-glv"
	case MulGnarkDoubleAdd:
		return "gnark-dadd"
	}
	return fmt.Sprintf("mul(%d)", int(m))
}

// Config parametrises the circuit.
type Config struct {
	// Curve is the proving curve: ecc.BN254 (default, zero value) or
	// ecc.BLS12_377 (the inner curve of the BLS12-377/BW6-761 2-chain used by
	// the audit circuit's native recursion option; see auditcircuit/RESULTS.md).
	Curve  ecc.ID
	Hash   HashMode
	Mul    MulMethod
	Window int        // window width (bits) for MulWindowed
	Lookup LookupMode // one-hot construction for MulWindowed
	// CheckTableLimbs range-checks the looked-up table limbs (redundant, for
	// measurement only; see FixedBaseOptions).
	CheckTableLimbs bool
	// OmitScalarMul drops the secp256k1 part (scalar multiplication and the
	// x-coordinate binding).  Benchmark-only: used to attribute constraints.
	OmitScalarMul bool
}

// DefaultConfig is the configuration reported in the benchmark write-up.
func DefaultConfig() Config {
	return Config{Hash: HashWide, Mul: MulWindowed, Window: 7, Lookup: LookupTensor}
}

func (c Config) String() string {
	s := fmt.Sprintf("hash=%s mul=%s", c.Hash, c.Mul)
	if c.CurveID() != ecc.BN254 {
		s = c.CurveID().String() + " " + s
	}
	if c.Mul == MulWindowed {
		s += fmt.Sprintf(" w=%d lookup=%s", c.Window, c.Lookup)
		if c.CheckTableLimbs {
			s += " +tablecheck"
		}
	}
	if c.OmitScalarMul {
		s += " (no-EC)"
	}
	return s
}

// CurveID returns the proving curve (BN254 unless set).
func (c Config) CurveID() ecc.ID {
	if c.Curve == ecc.UNKNOWN {
		return ecc.BN254
	}
	return c.Curve
}

// Field returns the proving curve's scalar field.
func (c Config) Field() *big.Int { return c.CurveID().ScalarField() }

// FrBits is the bit length of the proving field (254 for BN254, 253 for BLS12-377).
func (c Config) FrBits() int { return c.Field().BitLen() }

// ScalarBits is the number of bits of the nonce c for this configuration.
func (c Config) ScalarBits() int {
	if c.Hash == HashWide {
		return secpScalarBits
	}
	return c.FrBits()
}

// Circuit is the voter opening circuit.  Field order matters for gnark's
// witness schema: public inputs first.
type Circuit struct {
	// Public inputs
	TupleHash       frontend.Variable `gnark:",public"`
	EntryCommitment frontend.Variable `gnark:",public"`

	// Private witness
	Dom    frontend.Variable
	PkAx   frontend.Variable
	PkAy   frontend.Variable
	PosReg frontend.Variable
	SigRx  frontend.Variable // σreg (as stored in ballot component B3 of the tallying circuit)
	SigRy  frontend.Variable
	SigS   frontend.Variable
	R      frontend.Variable // commitment randomness
	RsigHi frontend.Variable // rσ = RsigHi·2^128 + RsigLo
	RsigLo frontend.Variable

	cfg Config
}

// NewCircuit returns a circuit skeleton for compilation.
func NewCircuit(cfg Config) *Circuit { return &Circuit{cfg: cfg} }

func newPoseidon(api frontend.API) stdhash.FieldHasher {
	perm, err := poseidon2.NewPoseidon2FromParameters(api, poseidonWidth, poseidonFullRounds, poseidonPartialRounds)
	if err != nil {
		panic(err)
	}
	return stdhash.NewMerkleDamgardHasher(api, perm, 0)
}

// Define implements frontend.Circuit.
func (c *Circuit) Define(api frontend.API) error {
	// ---- (1) hashing: hSig = H(σreg), c = H(σreg ∥ r) = MD-continuation of hSig with r.
	h := newPoseidon(api)
	h.Write(c.SigRx, c.SigRy, c.SigS)
	hSig := h.Sum()
	h.Write(c.R)
	h1 := h.Sum()

	frBits := api.Compiler().FieldBitLen() // 254 (BN254) or 253 (BLS12-377)
	var scalarBits []frontend.Variable
	var scalarEl *emulated.Element[Fr]
	switch c.cfg.Hash {
	case HashNarrow:
		api.AssertIsDifferent(h1, 0)
		// canonical decomposition (ToBinary with the full field width enforces
		// the value is below the field modulus, hence unique); c < r < n.
		scalarBits = api.ToBinary(h1, frBits)
	case HashWide:
		h.Write(wideHashTag)
		h2 := h.Sum()
		fr, err := emulated.NewField[Fr](api)
		if err != nil {
			return err
		}
		H1 := fr.FromBits(api.ToBinary(h1, frBits)...)
		H2 := fr.FromBits(api.ToBinary(h2, frBits)...)
		shift := fr.NewElement(pow2(frBits))
		C := fr.Add(fr.Mul(H1, shift), H2)
		C = fr.ReduceStrict(C) // canonical representative in [0, n)
		api.AssertIsEqual(fr.IsZero(C), 0)
		scalarBits = fr.ToBits(C) // 256 bits
		scalarEl = C
	default:
		return fmt.Errorf("unknown hash mode %v", c.cfg.Hash)
	}

	// ---- (2) rσ = x([c]G) on secp256k1.
	loBits := api.ToBinary(c.RsigLo, 128)
	hiBits := api.ToBinary(c.RsigHi, 128)
	if !c.cfg.OmitScalarMul {
		curve, err := sw_emulated.New[Fp, Fr](api, sw_emulated.GetSecp256k1Params())
		if err != nil {
			return err
		}
		var P *sw_emulated.AffinePoint[Fp]
		switch c.cfg.Mul {
		case MulWindowed:
			P, err = fixedBaseMul(api, curve, scalarBits, FixedBaseOptions{Window: c.cfg.Window, Lookup: c.cfg.Lookup, CheckTableLimbs: c.cfg.CheckTableLimbs})
			if err != nil {
				return err
			}
		case MulGnarkGLV, MulGnarkDoubleAdd:
			if scalarEl == nil {
				fr, err := emulated.NewField[Fr](api)
				if err != nil {
					return err
				}
				scalarEl = fr.FromBits(scalarBits...)
			}
			if c.cfg.Mul == MulGnarkGLV {
				P = curve.ScalarMulBase(scalarEl)
			} else {
				params := sw_emulated.GetSecp256k1Params()
				params.Eigenvalue, params.ThirdRootOne = nil, nil
				plain, err := sw_emulated.New[Fp, Fr](api, params)
				if err != nil {
					return err
				}
				P = plain.ScalarMulBase(scalarEl, algopts.WithNbScalarBits(len(scalarBits)))
			}
		default:
			return fmt.Errorf("unknown mul method %v", c.cfg.Mul)
		}
		fp, err := emulated.NewField[Fp](api)
		if err != nil {
			return err
		}
		rsig := fp.FromBits(append(append([]frontend.Variable{}, loBits...), hiBits...)...)
		fp.AssertIsEqual(&P.X, rsig)
	}

	// ---- (3) public bindings.
	ht := newPoseidon(api)
	ht.Write(c.Dom, c.PkAx, c.PkAy, c.PosReg, hSig)
	api.AssertIsEqual(ht.Sum(), c.TupleHash)

	he := newPoseidon(api)
	he.Write(entryDomainTag, c.PosReg, c.RsigHi, c.RsigLo)
	api.AssertIsEqual(he.Sum(), c.EntryCommitment)
	return nil
}

// fixedBaseTestCircuit exercises the fixed-base gadget alone: it checks
// [Σ Bits_i 2^i]G = (X, Y).
type fixedBaseTestCircuit struct {
	Bits []frontend.Variable
	X, Y emulated.Element[Fp] `gnark:",public"`
	opts FixedBaseOptions
}

func (c *fixedBaseTestCircuit) Define(api frontend.API) error {
	for _, b := range c.Bits {
		api.AssertIsBoolean(b)
	}
	curve, err := sw_emulated.New[Fp, Fr](api, sw_emulated.GetSecp256k1Params())
	if err != nil {
		return err
	}
	P, err := fixedBaseMul(api, curve, c.Bits, c.opts)
	if err != nil {
		return err
	}
	fp, err := emulated.NewField[Fp](api)
	if err != nil {
		return err
	}
	fp.AssertIsEqual(&P.X, &c.X)
	fp.AssertIsEqual(&P.Y, &c.Y)
	return nil
}

func bigBits(v *big.Int, nb int) []frontend.Variable {
	out := make([]frontend.Variable, nb)
	for i := range out {
		out[i] = v.Bit(i)
	}
	return out
}
