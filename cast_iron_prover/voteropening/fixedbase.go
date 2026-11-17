package voteropening

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

// Fp and Fr are the secp256k1 base and scalar fields, emulated in-circuit.
type (
	Fp = emulated.Secp256k1Fp
	Fr = emulated.Secp256k1Fr
)

const (
	// ScalarBits is the bit length of the nonce c (the secp256k1 group order n
	// is 256 bits); the width the gadget's tables are built for.
	ScalarBits = 256
	// DefaultWindow is the window width used by the tallying circuit.
	DefaultWindow = 7
	// WideHashTag is the tag absorbed after h1 to derive h2 (see package doc).
	WideHashTag = 1
)

// Fixed-base scalar multiplication [c]G on secp256k1 with c given as bits.
//
// The scalar is split into w-bit windows d_0, ..., d_{J-1} (little-endian).  For
// every window j a constant table T_j of 2^w affine points is baked into the
// circuit at compile time; the entry T_j[d_j] is selected with a one-hot vector
// over the window's bits (the coordinates themselves are free linear
// combinations of the one-hot bits) and the selected points are summed with
// the *incomplete* affine addition formula.
//
// Incomplete addition is only sound if the two operands are never equal or
// opposite (P = ±Q makes the λ-constraint vacuous, which a malicious prover
// could exploit).  We therefore use tables
//
//	T_0[d]     = [z + d + 1]G                              (z = 2^255)
//	T_j[d]     = [(d+1)·2^{wj}]G                 for 0 < j < J-1
//	T_{J-1}[d] = [(d+1)·2^{w(J-1)} - z - K]G     with K = Σ_j 2^{wj}
//
// so that the running sum after window j is [z + K_j + (c mod 2^{wj})]G with
// K_j = Σ_{i<j} 2^{wi}, i.e. it always lies in the integer interval
// [2^255, 2^255 + 2^{wj} + K_j) while the point being added is a multiple in
// [2^{wj}, 2^{w(j+1)}].  The two can never coincide (nor be opposite mod n)
// for any window below the top one; only the top window can hit an
// exceptional case and only for the specific scalar(s) listed by
// exceptionalScalars (one scalar for every supported w).  Since c is a hash
// output the prover cannot steer c to that value.  The sum of all table
// scalars is z + K + c - z - K = c, so no final correction is needed.
const fixedBaseOffsetExp = 255

var secpOrder = ecc.SECP256K1.ScalarField()

// FixedBaseOptions parametrises the windowed multiplication.  The one-hot
// selector of a window is the tensor product of the one-hot vectors of its two
// half-windows (oneHot), exact by construction.
type FixedBaseOptions struct {
	Window int // window width in bits (DefaultWindow = 7)
}

type fixedBaseTables struct {
	w      int
	nbBits int
	widths []int           // widths[j] = number of scalar bits consumed by window j
	z, k   *big.Int        // offset z = 2^255 and K = Σ_j 2^{wj}
	tables [][][2]*big.Int // tables[j][d] = affine (x, y) of the constant point for window j, digit d
}

func pow2(e int) *big.Int { return new(big.Int).Lsh(big.NewInt(1), uint(e)) }

func newFixedBaseTables(w, nbBits int) (*fixedBaseTables, error) {
	if w < 1 || w > 16 {
		return nil, fmt.Errorf("window width %d out of range [1,16]", w)
	}
	if nbBits < 2 || nbBits > 256 {
		return nil, fmt.Errorf("nbBits %d out of range [2,256]", nbBits)
	}
	J := (nbBits + w - 1) / w
	if J < 2 {
		return nil, errors.New("need at least two windows")
	}
	widths := make([]int, J)
	for j := range widths {
		widths[j] = w
	}
	widths[J-1] = nbBits - w*(J-1)

	n := secpOrder
	z := pow2(fixedBaseOffsetExp)
	K := new(big.Int)
	for j := 0; j < J; j++ {
		K.Add(K, pow2(w*j))
	}

	gJac, _ := secp256k1.Generators()
	tables := make([][][2]*big.Int, J)
	for j := 0; j < J; j++ {
		size := 1 << widths[j]
		shift := pow2(w * j)
		base := new(big.Int)
		switch {
		case j == 0:
			base.Add(z, big.NewInt(1))
		case j == J-1:
			base.Sub(shift, z)
			base.Sub(base, K)
			base.Mod(base, n)
		default:
			base.Set(shift)
		}
		var step, cur secp256k1.G1Jac
		step.ScalarMultiplication(&gJac, shift)
		cur.ScalarMultiplication(&gJac, base)
		jacs := make([]secp256k1.G1Jac, size)
		for d := 0; d < size; d++ {
			jacs[d].Set(&cur)
			cur.AddAssign(&step)
		}
		affs := secp256k1.BatchJacobianToAffineG1(jacs)
		tables[j] = make([][2]*big.Int, size)
		for d := range affs {
			if affs[d].IsInfinity() {
				return nil, fmt.Errorf("table entry (%d,%d) is the point at infinity", j, d)
			}
			tables[j][d] = [2]*big.Int{affs[d].X.BigInt(new(big.Int)), affs[d].Y.BigInt(new(big.Int))}
		}
	}
	t := &fixedBaseTables{w: w, nbBits: nbBits, widths: widths, z: z, k: K, tables: tables}
	if _, err := t.exceptionalScalars(); err != nil {
		return nil, err
	}
	return t, nil
}

// exceptionalScalars returns the scalars c ∈ [1, n) for which the addition
// chain of fixedBaseMul hits an exceptional case of the incomplete addition
// formula (P = ±Q, or an operand equal to the point at infinity).  For those c
// the circuit is not sound (a malicious prover could choose λ freely), so the
// set must be tiny and un-steerable.  The method returns an error when a
// collision is possible in any window below the top one, because in that case
// the higher digits are unconstrained and the exceptional set would be huge.
func (t *fixedBaseTables) exceptionalScalars() ([]*big.Int, error) {
	n := secpOrder
	J := len(t.widths)
	// Kj[j] = Σ_{i<j} 2^{w i}
	Kj := make([]*big.Int, J+1)
	Kj[0] = new(big.Int)
	for j := 1; j <= J; j++ {
		Kj[j] = new(big.Int).Add(Kj[j-1], pow2(t.w*(j-1)))
	}
	if Kj[J].Cmp(t.k) != 0 {
		return nil, errors.New("internal: K mismatch")
	}
	// Window-0 table entries are [z+1]G .. [z+2^{w_0}]G: nonzero and < n.
	if new(big.Int).Add(t.z, pow2(t.widths[0])).Cmp(n) >= 0 {
		return nil, errors.New("window-0 table scalars reach the group order")
	}
	// Accumulator before window j (j ≥ 1): a = z + K_j + c_low, c_low ∈ [0, 2^{wj}).
	// Point added in window j (1 ≤ j ≤ J-2): t = (d+1)·2^{wj} ∈ [2^{wj}, 2^{wj+widths[j]}].
	for j := 1; j <= J-1; j++ {
		wj := t.w * j
		aMin := new(big.Int).Add(t.z, Kj[j])
		aMax := new(big.Int).Add(aMin, pow2(wj))
		aMax.Sub(aMax, big.NewInt(1))
		if aMax.Cmp(n) >= 0 {
			return nil, fmt.Errorf("window %d: accumulator can reach the group order", j)
		}
		if j == J-1 {
			break
		}
		tMax := pow2(wj + t.widths[j])
		if tMax.Cmp(aMin) >= 0 {
			return nil, fmt.Errorf("window %d: P = Q collision possible (tMax=%s ≥ aMin=%s)", j, tMax, aMin)
		}
		if new(big.Int).Add(aMax, tMax).Cmp(n) >= 0 {
			return nil, fmt.Errorf("window %d: P = -Q collision possible", j)
		}
	}
	// Top window: t' = (d+1)·2^{wj} - z - K (mod n).
	j := J - 1
	wj := t.w * j
	var exc []*big.Int
	twoZ := new(big.Int).Lsh(t.z, 1)
	bound := pow2(wj)
	for d := 0; d < 1<<t.widths[j]; d++ {
		dp1shift := new(big.Int).Mul(big.NewInt(int64(d+1)), bound)
		dshift := new(big.Int).Mul(big.NewInt(int64(d)), bound)
		// table entry must not be the point at infinity
		ts := new(big.Int).Sub(dp1shift, t.z)
		ts.Sub(ts, t.k)
		ts.Mod(ts, n)
		if ts.Sign() == 0 {
			return nil, fmt.Errorf("top window entry %d is the point at infinity", d)
		}
		// P = Q:  c_low ≡ (d+1)·2^{wj} - 2z - K - K_j
		v := new(big.Int).Sub(dp1shift, twoZ)
		v.Sub(v, t.k)
		v.Sub(v, Kj[j])
		v.Mod(v, n)
		if v.Cmp(bound) < 0 {
			c := new(big.Int).Add(v, dshift)
			if c.Sign() != 0 && c.Cmp(n) < 0 {
				exc = append(exc, c)
			}
		}
		// P = -Q: c_low ≡ K - K_j - (d+1)·2^{wj}
		v = new(big.Int).Sub(t.k, Kj[j])
		v.Sub(v, dp1shift)
		v.Mod(v, n)
		if v.Cmp(bound) < 0 {
			c := new(big.Int).Add(v, dshift)
			if c.Sign() != 0 && c.Cmp(n) < 0 {
				exc = append(exc, c)
			}
		}
	}
	return exc, nil
}

// ExceptionalScalars exposes the (tiny) set of scalars for which the windowed
// fixed-base gadget with the given parameters is not sound; see the comment at
// the top of fixedbase.go.
func ExceptionalScalars(w, nbBits int) ([]*big.Int, error) {
	t, err := newFixedBaseTables(w, nbBits)
	if err != nil {
		return nil, err
	}
	return t.exceptionalScalars()
}

// oneHot returns the 2^len(bits) indicator vector of the integer Σ bits[i]·2^i
// (bits little-endian and already constrained to be boolean).  The vector is
// exact by construction: it is the tensor product of the indicator vectors of
// the two halves, where the last row and column of the product are derived
// linearly from Σ_i lo[i] = Σ_k hi[k] = 1.
func oneHot(api frontend.API, bits []frontend.Variable) []frontend.Variable {
	switch len(bits) {
	case 0:
		return []frontend.Variable{1}
	case 1:
		return []frontend.Variable{api.Sub(1, bits[0]), bits[0]}
	}
	lo := oneHot(api, bits[:len(bits)/2])
	hi := oneHot(api, bits[len(bits)/2:])
	nl, nh := len(lo), len(hi)
	out := make([]frontend.Variable, nl*nh)
	for k := 0; k < nh-1; k++ {
		for i := 0; i < nl-1; i++ {
			out[i+k*nl] = api.Mul(lo[i], hi[k])
		}
		// last row: lo[nl-1]·hi[k] = hi[k] - Σ_{i<nl-1} lo[i]·hi[k]
		s := hi[k]
		for i := 0; i < nl-1; i++ {
			s = api.Sub(s, out[i+k*nl])
		}
		out[nl-1+k*nl] = s
	}
	// last column: lo[i]·hi[nh-1] = lo[i] - Σ_{k<nh-1} lo[i]·hi[k]
	for i := 0; i < nl; i++ {
		s := lo[i]
		for k := 0; k < nh-1; k++ {
			s = api.Sub(s, out[i+k*nl])
		}
		out[i+(nh-1)*nl] = s
	}
	return out
}

// fixedBaseMul returns [c]G where c = Σ_i bits[i]·2^i.  The bits must already
// be constrained to be boolean by the caller and c must be nonzero (and, for
// soundness, a hash output: see exceptionalScalars).
func fixedBaseMul(api frontend.API, curve *sw_emulated.Curve[Fp, Fr], bits []frontend.Variable, opts FixedBaseOptions) (*sw_emulated.AffinePoint[Fp], error) {
	tabs, err := newFixedBaseTables(opts.Window, len(bits))
	if err != nil {
		return nil, err
	}
	fp, err := emulated.NewField[Fp](api)
	if err != nil {
		return nil, err
	}
	return fixedBaseMulWithTables(api, curve, fp, tabs, bits), nil
}

// fixedBaseMulWithTables is fixedBaseMul with precomputed tables (see
// FixedBaseGadget); len(bits) must equal tabs.nbBits.
func fixedBaseMulWithTables(api frontend.API, curve *sw_emulated.Curve[Fp, Fr], fp *emulated.Field[Fp], tabs *fixedBaseTables, bits []frontend.Variable) *sw_emulated.AffinePoint[Fp] {
	var fpParams Fp
	nbLimbs := int(fpParams.NbLimbs())
	bitsPerLimb := int(fpParams.BitsPerLimb())
	limbMask := new(big.Int).Sub(pow2(bitsPerLimb), big.NewInt(1))
	limbOf := func(v *big.Int, k int) *big.Int {
		l := new(big.Int).Rsh(v, uint(k*bitsPerLimb))
		return l.And(l, limbMask)
	}
	sum := func(terms []frontend.Variable) frontend.Variable {
		if len(terms) == 1 {
			return terms[0]
		}
		return api.Add(terms[0], terms[1], terms[2:]...)
	}
	// newElement wraps limbs into an emulated element.  The limbs are linear
	// combinations of a one-hot vector with constant coefficients below
	// 2^bitsPerLimb, i.e. exact by construction, so no range check is needed:
	// we reuse a constant element (flagged as internal, i.e. width-constrained)
	// and substitute the limbs.
	newElement := func(limbs []frontend.Variable) emulated.Element[Fp] {
		e := *fp.NewElement(big.NewInt(0))
		e.Limbs = limbs
		return e
	}
	lookup := func(j int, wbits []frontend.Variable) *sw_emulated.AffinePoint[Fp] {
		size := 1 << tabs.widths[j]
		ind := oneHot(api, wbits)
		xl := make([]frontend.Variable, nbLimbs)
		yl := make([]frontend.Variable, nbLimbs)
		for k := 0; k < nbLimbs; k++ {
			xt := make([]frontend.Variable, size)
			yt := make([]frontend.Variable, size)
			for d := 0; d < size; d++ {
				xt[d] = api.Mul(ind[d], limbOf(tabs.tables[j][d][0], k))
				yt[d] = api.Mul(ind[d], limbOf(tabs.tables[j][d][1], k))
			}
			xl[k] = sum(xt)
			yl[k] = sum(yt)
		}
		return &sw_emulated.AffinePoint[Fp]{X: newElement(xl), Y: newElement(yl)}
	}
	off := 0
	window := func(j int) []frontend.Variable {
		wb := bits[off : off+tabs.widths[j]]
		off += tabs.widths[j]
		return wb
	}
	acc := lookup(0, window(0))
	for j := 1; j < len(tabs.widths); j++ {
		acc = curve.Add(acc, lookup(j, window(j)))
	}
	return acc
}
