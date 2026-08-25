// Package bw6verifier is the option-(a) prototype of the audit circuit's inner
// verifier: a *soft* (bit-returning) Groth16 verifier for proofs of BLS12-377
// circuits, running inside a BW6-761 circuit with gnark's native 2-chain
// gadgets.  It exists to measure the real per-ballot cost of in-circuit
// verification (see ../RESULTS.md); wiring it into the audit circuit requires
// the field decision documented there.
//
// # How verification is made soft (soundness-critical)
//
// gnark's std/recursion/groth16 verifier only asserts.  VerifyBit reproduces
// its computation but turns every check into a bit:
//
//  1. Well-formedness of the proof points is checked without any division:
//     on-curve (y² = x³ + b, which also rejects (0,0), i.e. an absent proof)
//     and prime-subgroup membership through the GLV/Frobenius characterisations
//     gnark uses (P = −[x₀²]φ(P) on G1, ψ(Q) = [x₀]Q on G2) computed with
//     *complete* (unified) point additions so that small-order points cannot
//     make the circuit unsatisfiable.  wellFormed = AND of all these bits.
//  2. Every proof point is replaced by Select(wellFormed, point, dummy) where
//     dummy is a constant, known-valid proof.  The MSM and Miller loops then
//     only ever run on points in the right subgroups (their incomplete
//     formulas have no exceptional case for prime-order inputs and
//     non-adversarial scalars), so the circuit is always satisfiable.
//  3. The Pedersen-commitment check and the main pairing equation are
//     evaluated with Pair (not PairingCheck) and compared to 1 / vk.E with a
//     full 12-coordinate equality test (gnark's Pairing.IsEqual in v0.14.0
//     compares only 8 coordinates and must not be used for this).
//  4. bit = wellFormed ∧ commitmentOk ∧ pairingOk.  If wellFormed = 0 the
//     other bits are evaluated on the dummy proof and are irrelevant.
//
// A valid proof gives 1 (completeness); 1 is impossible without a proof that
// the standard verifier accepts (soundness: with wellFormed = 1 the checks are
// exactly the standard verifier's on the very same points).
package bw6verifier

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/fields_bls12377"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/commitments/pedersen"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

type (
	G1Affine = sw_bls12377.G1Affine
	G2Affine = sw_bls12377.G2Affine
	GT       = sw_bls12377.GT
	Scalar   = sw_bls12377.Scalar

	Proof        = stdgroth16.Proof[G1Affine, G2Affine]
	VerifyingKey = stdgroth16.VerifyingKey[G1Affine, G2Affine, GT]
	Witness      = stdgroth16.Witness[sw_bls12377.ScalarField]
)

// BLS12-377 constants (as in gnark's sw_bls12377 subgroup checks).
var (
	seed        = mustBig("9586122913090633729")                                                                    // x₀
	seedSquared = new(big.Int).Mul(seed, seed)                                                                      // x₀²
	omegaG1     = "80949648264912719408558363140637477264845294720710499478137287262712535938301461879813459410945" // φ: x ↦ ω·x
	psiXCoeff   = "80949648264912719408558363140637477264845294720710499478137287262712535938301461879813459410946"
	psiYCoeff   = "216465761340224619389371505802605247630151569547285782856803747159100223055385581585702401816380679166954762214499"
	twistB      = "155198655607781456406391640216936120121836107652948796323930557600032281009004493664981332883744016074664192874906" // b' = 1/u for y² = x³ + b'
)

func mustBig(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("bad constant")
	}
	return v
}

// Options of VerifyBit.
type Options struct {
	// SubgroupChecks enables the (soft) prime-subgroup membership checks of
	// the proof points.  They are required for soundness against a malicious
	// outer prover; disable only for cost accounting.
	SubgroupChecks bool
	// Debug prints every sub-bit (test engine only).
	Debug bool
}

// Verifier is a soft Groth16 verifier for BLS12-377 proofs in a BW6-761 circuit.
type Verifier struct {
	api       frontend.API
	curve     *sw_bls12377.Curve
	pairing   *sw_bls12377.Pairing
	scalarApi *emulated.Field[sw_bls12377.ScalarField]
}

// New returns a verifier bound to api (which must be a BW6-761 circuit).
func New(api frontend.API) (*Verifier, error) {
	curve, err := sw_bls12377.NewCurve(api)
	if err != nil {
		return nil, err
	}
	scalarApi, err := emulated.NewField[sw_bls12377.ScalarField](api)
	if err != nil {
		return nil, err
	}
	return &Verifier{api: api, curve: curve, pairing: sw_bls12377.NewPairing(api), scalarApi: scalarApi}, nil
}

/* ------------------------------ soft predicates ------------------------------ */

// isOnCurveG1 returns 1 iff y² = x³ + 1 (which excludes (0,0)).
func (v *Verifier) isOnCurveG1(p *G1Affine) frontend.Variable {
	left := v.api.Mul(p.Y, p.Y)
	right := v.api.Add(v.api.Mul(p.X, v.api.Mul(p.X, p.X)), 1)
	return v.api.IsZero(v.api.Sub(left, right))
}

// isOnTwistG2 returns 1 iff y² = x³ + b' over Fp2 (excludes (0,0)).
func (v *Verifier) isOnTwistG2(q *G2Affine) frontend.Variable {
	var left, right, b fields_bls12377.E2
	b.A0, b.A1 = 0, twistB
	left.Square(v.api, q.P.Y)
	right.Square(v.api, q.P.X)
	right.Mul(v.api, right, q.P.X)
	right.Add(v.api, right, b)
	left.Sub(v.api, left, right)
	return left.IsZero(v.api)
}

// mulConstUnifiedG1 computes [k]P with complete additions (AddUnified for
// both doubling and addition), so it is satisfiable for every point on the
// curve, including small-order ones; (0,0) represents infinity.
func (v *Verifier) mulConstUnifiedG1(p *G1Affine, k *big.Int) *G1Affine {
	acc := &G1Affine{X: 0, Y: 0}
	for i := k.BitLen() - 1; i >= 0; i-- {
		acc.AddUnified(v.api, *acc)
		if k.Bit(i) == 1 {
			acc.AddUnified(v.api, *p)
		}
	}
	return acc
}

func (v *Verifier) mulConstUnifiedG2(q *G2Affine, k *big.Int) *G2Affine {
	var acc G2Affine
	acc.P.X.SetZero()
	acc.P.Y.SetZero()
	for i := k.BitLen() - 1; i >= 0; i-- {
		acc.P.AddUnified(v.api, acc.P)
		if k.Bit(i) == 1 {
			acc.P.AddUnified(v.api, q.P)
		}
	}
	return &acc
}

// isInG1 returns 1 iff P (assumed on the curve) is in the prime-order
// subgroup: P = −[x₀²]φ(P), φ(x, y) = (ω·x, y).
func (v *Verifier) isInG1(p *G1Affine) frontend.Variable {
	phi := &G1Affine{X: v.api.Mul(p.X, omegaG1), Y: p.Y}
	r := v.mulConstUnifiedG1(phi, seedSquared)
	xOk := v.api.IsZero(v.api.Sub(r.X, p.X))
	yOk := v.api.IsZero(v.api.Add(r.Y, p.Y))
	return v.api.And(xOk, yOk)
}

// isInG2 returns 1 iff Q (assumed on the twist) is in G2: ψ(Q) = [x₀]Q.
func (v *Verifier) isInG2(q *G2Affine) frontend.Variable {
	var psiX, psiY fields_bls12377.E2
	psiX.Conjugate(v.api, q.P.X)
	psiX.MulByFp(v.api, psiX, psiXCoeff)
	psiY.Conjugate(v.api, q.P.Y)
	psiY.MulByFp(v.api, psiY, psiYCoeff)
	xq := v.mulConstUnifiedG2(q, seed)
	var dx, dy fields_bls12377.E2
	dx.Sub(v.api, xq.P.X, psiX)
	dy.Sub(v.api, xq.P.Y, psiY)
	return v.api.And(dx.IsZero(v.api), dy.IsZero(v.api))
}

// gtIsEqual compares all 12 coordinates of two GT elements.
func (v *Verifier) gtIsEqual(a, b *GT) frontend.Variable {
	coords := func(e *GT) []frontend.Variable {
		return []frontend.Variable{
			e.C0.B0.A0, e.C0.B0.A1, e.C0.B1.A0, e.C0.B1.A1, e.C0.B2.A0, e.C0.B2.A1,
			e.C1.B0.A0, e.C1.B0.A1, e.C1.B1.A0, e.C1.B1.A1, e.C1.B2.A0, e.C1.B2.A1,
		}
	}
	ca, cb := coords(a), coords(b)
	ok := frontend.Variable(1)
	for i := range ca {
		ok = v.api.And(ok, v.api.IsZero(v.api.Sub(ca[i], cb[i])))
	}
	return ok
}

func (v *Verifier) selectG1(b frontend.Variable, p, q *G1Affine) *G1Affine {
	return &G1Affine{X: v.api.Select(b, p.X, q.X), Y: v.api.Select(b, p.Y, q.Y)}
}

func (v *Verifier) selectG2(b frontend.Variable, p, q *G2Affine) *G2Affine {
	var r G2Affine
	r.P.X.Select(v.api, b, p.P.X, q.P.X)
	r.P.Y.Select(v.api, b, p.P.Y, q.P.Y)
	return &r
}

/* --------------------------------- VerifyBit --------------------------------- */

// VerifyBit returns 1 iff proof is a valid Groth16 proof for witness under vk
// (exactly one Pedersen commitment is supported, as in gnark's verifier).
// dummy must be a valid proof for some statement under vk; it is only used to
// keep the circuit satisfiable when proof is malformed.
func (v *Verifier) VerifyBit(vk VerifyingKey, proof, dummy Proof, witness Witness, opts Options) (frontend.Variable, error) {
	if len(vk.CommitmentKeys) != 1 || len(proof.Commitments) != 1 || len(dummy.Commitments) != 1 {
		return nil, fmt.Errorf("exactly one commitment is supported (vk %d, proof %d)", len(vk.CommitmentKeys), len(proof.Commitments))
	}
	nbPublicVars := len(vk.G1.K) - len(vk.PublicAndCommitmentCommitted)
	if len(witness.Public) != nbPublicVars-1 {
		return nil, fmt.Errorf("invalid witness size, got %d, expected %d", len(witness.Public), nbPublicVars-1)
	}

	// 1) well-formedness
	dbg := func(name string, b frontend.Variable) {
		if opts.Debug {
			v.api.Println("bw6verifier", name, b)
		}
	}
	g1s := []*G1Affine{&proof.Ar, &proof.Krs, &proof.Commitments[0].G1El, &proof.CommitmentPok.G1El}
	ok := v.isOnTwistG2(&proof.Bs)
	dbg("onTwist(B)", ok)
	for i, p := range g1s {
		b := v.isOnCurveG1(p)
		dbg(fmt.Sprintf("onCurveG1(%d)", i), b)
		ok = v.api.And(ok, b)
	}
	if opts.SubgroupChecks {
		// subgroup checks run on points already gated to be on the curve
		// (Select onto the dummy), so the unified chains see curve points only.
		bs := v.selectG2(ok, &proof.Bs, &dummy.Bs)
		b := v.isInG2(bs)
		dbg("inG2(B)", b)
		ok = v.api.And(ok, b)
		dummies := []*G1Affine{&dummy.Ar, &dummy.Krs, &dummy.Commitments[0].G1El, &dummy.CommitmentPok.G1El}
		for i, p := range g1s {
			b := v.isInG1(v.selectG1(ok, p, dummies[i]))
			dbg(fmt.Sprintf("inG1(%d)", i), b)
			ok = v.api.And(ok, b)
		}
	}

	// 2) gate every point onto the dummy proof
	ar := v.selectG1(ok, &proof.Ar, &dummy.Ar)
	krs := v.selectG1(ok, &proof.Krs, &dummy.Krs)
	bs := v.selectG2(ok, &proof.Bs, &dummy.Bs)
	com := v.selectG1(ok, &proof.Commitments[0].G1El, &dummy.Commitments[0].G1El)
	pok := v.selectG1(ok, &proof.CommitmentPok.G1El, &dummy.CommitmentPok.G1El)

	// 3) public-input MSM with the commitment challenge (as gnark's AssertProof)
	inP := make([]*G1Affine, len(vk.G1.K)-1)
	for i := range inP {
		inP[i] = &vk.G1.K[i+1]
	}
	inS := make([]*Scalar, len(witness.Public)+1)
	for i := range witness.Public {
		inS[i] = &witness.Public[i]
	}
	var fr sw_bls12377.ScalarField
	hashToField, err := recursion.NewHash(v.api, fr.Modulus(), true)
	if err != nil {
		return nil, err
	}
	hashToField.Write(v.curve.MarshalG1(*com)...)
	for _, j := range vk.PublicAndCommitmentCommitted[0] {
		hashToField.Write(v.curve.MarshalScalar(*inS[j-1])...)
	}
	h := hashToField.Sum()
	inS[len(witness.Public)] = v.scalarApi.FromBits(v.api.ToBinary(h)...)
	kSum, err := v.curve.MultiScalarMul(inP, inS)
	if err != nil {
		return nil, err
	}
	kSum = v.curve.Add(kSum, &vk.G1.K[0])
	kSum = v.curve.Add(kSum, com)

	// 4) commitment proof of knowledge: e(com, GSigmaNeg)·e(pok, G) = 1
	one := GT{}
	one.SetOne()
	gtCom, err := v.pairing.Pair([]*G1Affine{com, pok}, []*G2Affine{&vk.CommitmentKeys[0].GSigmaNeg, &vk.CommitmentKeys[0].G})
	if err != nil {
		return nil, err
	}
	comOk := v.gtIsEqual(gtCom, &one)
	dbg("commitmentOk", comOk)

	// 5) main equation: e(kSum, −γ)·e(krs, −δ)·e(ar, bs) = e(α, β) = vk.E
	gt, err := v.pairing.Pair([]*G1Affine{kSum, krs, ar}, []*G2Affine{&vk.G2.GammaNeg, &vk.G2.DeltaNeg, bs})
	if err != nil {
		return nil, err
	}
	mainOk := v.gtIsEqual(gt, &vk.E)
	dbg("mainOk", mainOk)

	return v.api.And(ok, v.api.And(comOk, mainOk)), nil
}

// Placeholder helpers re-exported for callers.
var (
	PlaceholderProof        = stdgroth16.PlaceholderProof[G1Affine, G2Affine]
	PlaceholderWitness      = stdgroth16.PlaceholderWitness[sw_bls12377.ScalarField]
	PlaceholderVerifyingKey = stdgroth16.PlaceholderVerifyingKey[G1Affine, G2Affine, GT]
	ValueOfProof            = stdgroth16.ValueOfProof[G1Affine, G2Affine]
	ValueOfWitness          = stdgroth16.ValueOfWitness[sw_bls12377.ScalarField]
	ValueOfVerifyingKey     = stdgroth16.ValueOfVerifyingKey[G1Affine, G2Affine, GT]
)

// pedersenCommitment is the element type of Proof.Commitments.
type pedersenCommitment = pedersen.Commitment[G1Affine]
