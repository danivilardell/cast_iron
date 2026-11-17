// Package castiron implements the Cast Iron tallying relation (paper
// Definition 3) as a gnark circuit.  Given the filtered bulletin board BB′,
// the roots of the weight tree T_W and of the record tree T_R, the tallier's
// public key and the claimed result X, the circuit proves knowledge of sk_T
// such that
//
//	pk_T    = Enc.DerivePk(sk_T)
//	B_dec   = Enc.D(sk_T, BB′)            (field by field)
//	v       = Validate(B_dec, T_W, T_R)
//	B_final = Deduplicate(B_dec, v)
//	X       = Accumulate(B_final)
//
// The key relation is asserted; everything computed from ballot contents is
// a soft predicate (a bit), so that no ballot — however malformed — can make
// the relation unsatisfiable, and no choice of the prover's witness can change
// which ballots count.  See README.md for the mapping to the paper.
package castiron

import (
	"errors"
	"fmt"
	"math/big"
	"math/bits"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	stdhash "github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/math/cmp"

	"cast_iron/shared"
	"cast_iron/voteropening"
)

/* =============================== Circuit IO =============================== */

// ElGamalCiphertext is one field element encrypted under the tallier's key.
type ElGamalCiphertext struct {
	C1 frontend.Variable
	C2 frontend.Variable
}

// BallotCiphertexts is one entry β of BB′: the field-wise encryption of the
// ballot (B1, B2, σB) of paper Section 5.2 — 16 + m + d ciphertexts for m
// choices and a weight tree of depth d.
type BallotCiphertexts struct {
	EidC ElGamalCiphertext // election identifier

	// B1 = (pk_i, IC.pk, (σreg, r), t_reg)
	PkVoteX_C   ElGamalCiphertext // voting credential pk_i
	PkVoteY_C   ElGamalCiphertext
	PkAnchorX_C ElGamalCiphertext // inalienable credential IC.pk
	PkAnchorY_C ElGamalCiphertext
	B3_RX_C     ElGamalCiphertext // σreg = Sig.Sign(IC.sk, pk_i)
	B3_RY_C     ElGamalCiphertext
	B3_S_C      ElGamalCiphertext
	RegRandC    ElGamalCiphertext // CTC commitment randomness r
	PosRegC     ElGamalCiphertext // t_reg: record position of the registration

	// B2 = (π_W, w, ν, id_B)
	LeafIndexC  ElGamalCiphertext   // π_W: leaf index in the weight tree ...
	PathWeightC []ElGamalCiphertext // ... and sibling path, leaf level first
	WeightC     ElGamalCiphertext   // w
	ChoiceC     []ElGamalCiphertext // ν as a one-hot vector scaled by w
	BallotIDC   ElGamalCiphertext   // id_B

	// σB = Sig.Sign(sk_i, (B1, B2))
	B4_RX_C ElGamalCiphertext
	B4_RY_C ElGamalCiphertext
	B4_S_C  ElGamalCiphertext
}

// Row is a decrypted ballot projected onto what Deduplicate and Accumulate
// read: (IC.pk, t_reg, id_B, ν·w), multiplied by the ballot's validity bit,
// and the ballot's position t on BB′ (not masked: every row has its own t).
type Row struct {
	PkAnchorX frontend.Variable
	PkAnchorY frontend.Variable
	PosReg    frontend.Variable
	BallotID  frontend.Variable
	Pos       frontend.Variable
	Choice    []frontend.Variable
}

// RecordOpening is the tallier's lookup of one ballot's registration in the
// public record: the leaf of T_R at the ballot's t_reg and its sibling path
// (leaf level first).
type RecordOpening struct {
	Leaf frontend.Variable
	Path []frontend.Variable
}

// CastIronCircuit is the tallying relation for a fixed number of ballots,
// choices and tree depths (see NewSkeleton).
type CastIronCircuit struct {
	ElectionID       frontend.Variable   `gnark:",public"`
	VoterRollRoot    frontend.Variable   `gnark:",public"` // Mrk.Root(T_W)
	RegistrationRoot frontend.Variable   `gnark:",public"` // Mrk.Root(T_R)
	ElGamalG         frontend.Variable   `gnark:",public"`
	ElGamalH         frontend.Variable   `gnark:",public"` // pk_T
	BulletinBoard    []BallotCiphertexts `gnark:",public"` // BB′, in posting order
	Tally            []frontend.Variable `gnark:",public"` // X

	ElGamalSk      frontend.Variable `gnark:",secret"` // sk_T
	RecordOpenings []RecordOpening   `gnark:",secret"` // one per ballot
	Sorted         []Row             `gnark:",secret"` // B_sorted
}

// NewSkeleton returns an unassigned circuit sized for numBallots ballots with
// numChoices choices, a weight tree of depth weightDepth and a record tree of
// depth recordDepth.
func NewSkeleton(numBallots, numChoices, weightDepth, recordDepth int) *CastIronCircuit {
	c := &CastIronCircuit{
		BulletinBoard:  make([]BallotCiphertexts, numBallots),
		Tally:          make([]frontend.Variable, numChoices),
		RecordOpenings: make([]RecordOpening, numBallots),
		Sorted:         make([]Row, numBallots),
	}
	for i := range c.BulletinBoard {
		c.BulletinBoard[i].ChoiceC = make([]ElGamalCiphertext, numChoices)
		c.BulletinBoard[i].PathWeightC = make([]ElGamalCiphertext, weightDepth)
		c.RecordOpenings[i].Path = make([]frontend.Variable, recordDepth)
		c.Sorted[i].Choice = make([]frontend.Variable, numChoices)
	}
	return c
}

// Fixed-base gadget configuration for the in-circuit CTC opening: 7-bit
// windows, 256-bit scalar from the wide hash (see package voteropening).
var openingGadgetOpts = voteropening.FixedBaseOptions{Window: voteropening.DefaultWindow}

// Domain tag of the Fiat–Shamir challenge of the multiset check.
const fiatShamirTag = 0xA23

/* ============================= Small predicates ============================ */

func newPoseidonHasher(api frontend.API) stdhash.FieldHasher { return shared.NewPoseidonHasher(api) }

// eqBit returns 1 iff a = b.
func eqBit(api frontend.API, a, b frontend.Variable) frontend.Variable {
	return api.IsZero(api.Sub(a, b))
}

// boolAll returns the AND of the given bits.
func boolAll(api frontend.API, xs ...frontend.Variable) frontend.Variable {
	acc := frontend.Variable(1)
	for _, x := range xs {
		acc = api.Mul(acc, x)
	}
	return acc
}

// singleChoiceBit returns 1 iff exactly one entry of vec is nonzero.
func singleChoiceBit(api frontend.API, vec []frontend.Variable) frontend.Variable {
	nonzero := frontend.Variable(0)
	for _, v := range vec {
		nonzero = api.Add(nonzero, api.Sub(1, api.IsZero(v)))
	}
	return eqBit(api, nonzero, 1)
}

// sumEqualsBit returns 1 iff Σ vec = target.
func sumEqualsBit(api frontend.API, vec []frontend.Variable, target frontend.Variable) frontend.Variable {
	sum := frontend.Variable(0)
	for _, v := range vec {
		sum = api.Add(sum, v)
	}
	return eqBit(api, sum, target)
}

// fieldOrder compares field elements as the integers in [0, p) they
// represent.  An element is decomposed once (canonically) and compared through
// its two halves, each with a bounded comparator.
type fieldOrder struct {
	api  frontend.API
	half int
	cmp  *cmp.BoundedComparator
}

func newFieldOrder(api frontend.API) *fieldOrder {
	half := (api.Compiler().FieldBitLen() + 1) / 2
	bound := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(half)), big.NewInt(1))
	return &fieldOrder{api: api, half: half, cmp: cmp.NewBoundedComparator(api, bound, false)}
}

// split returns the canonical bits of x (little-endian) and its halves
// x = hi·2^half + lo.
func (o *fieldOrder) split(x frontend.Variable) (xBits []frontend.Variable, hi, lo frontend.Variable) {
	xBits = o.api.ToBinary(x, o.api.Compiler().FieldBitLen())
	return xBits, o.api.FromBinary(xBits[o.half:]...), o.api.FromBinary(xBits[:o.half]...)
}

// splitConst is split for a constant.
func (o *fieldOrder) splitConst(x *big.Int) (hi, lo *big.Int) {
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(o.half)), big.NewInt(1))
	return new(big.Int).Rsh(x, uint(o.half)), new(big.Int).And(x, mask)
}

// less returns 1 iff a < b, the operands given by their halves.
func (o *fieldOrder) less(aHi, aLo, bHi, bLo frontend.Variable) frontend.Variable {
	return o.api.Add(o.cmp.IsLess(aHi, bHi), o.api.Mul(eqBit(o.api, aHi, bHi), o.cmp.IsLess(aLo, bLo)))
}

// lessEq returns 1 iff a ≤ b, the operands given by their halves.
func (o *fieldOrder) lessEq(aHi, aLo, bHi, bLo frontend.Variable) frontend.Variable {
	return o.api.Add(o.cmp.IsLess(aHi, bHi), o.api.Mul(eqBit(o.api, aHi, bHi), o.cmp.IsLessEq(aLo, bLo)))
}

/* ============================== Validate: gadgets =========================== */

// voterRollBit is weight validity: 1 iff (IC.pk, w) is the leaf at leafIndex
// of the weight tree with the given root.  The tree hashes a leaf
// L = Poseidon(IC.pk, w) into its level-0 node Poseidon(L).  The index is
// range-checked softly: an out-of-range index yields 0, never an
// unsatisfiable constraint.
func voterRollBit(api frontend.API, root, pkAx, pkAy, weight, leafIndex frontend.Variable, path []frontend.Variable) frontend.Variable {
	h := newPoseidonHasher(api)
	h.Write(pkAx, pkAy, weight)
	leaf := h.Sum()
	h.Reset()
	h.Write(leaf)
	node := h.Sum()

	idxBits := api.ToBinary(leafIndex, api.Compiler().FieldBitLen())
	high := frontend.Variable(0)
	for _, b := range idxBits[len(path):] {
		high = api.Add(high, b)
	}
	inRange := api.IsZero(high)

	for k := range path {
		left := api.Select(idxBits[k], path[k], node)
		right := api.Select(idxBits[k], node, path[k])
		h.Reset()
		h.Write(left, right)
		node = h.Sum()
	}
	return api.Mul(inRange, eqBit(api, node, root))
}

// registrationOpeningBit is registration validity: CTC.Open((pk_i, σreg), r,
// t_reg) against the record committed in recordRoot (paper Fig. 2).  It
// returns 1 iff
//   - the nonce c = H(pk_i ∥ σreg ∥ r), derived exactly as the registration
//     client does (voteropening.ComputeOpeningMsg), is nonzero,
//   - t_reg is a position of the record tree, and
//   - the leaf of the record tree at t_reg is the commitment
//     Poseidon(1, t_reg, rσ) to rσ = x([c]G).
//
// The leaf is supplied by the tallier (rec).  Its membership at index t_reg is
// asserted, not merely tested, whenever t_reg is in range: the tallier cannot
// present anything but the true record entry, so it has no way to make a
// valid registration fail.  For an out-of-range t_reg the opening is ignored.
func registrationOpeningBit(
	api frontend.API, g *voteropening.FixedBaseGadget,
	pkVx, pkVy, sigRx, sigRy, sigS, r, posReg, recordRoot frontend.Variable,
	rec RecordOpening,
) (frontend.Variable, error) {
	h := newPoseidonHasher(api)
	h.Write(pkVx, pkVy, sigRx, sigRy, sigS, r)
	h1 := h.Sum()
	h.Write(voteropening.WideHashTag)
	h2 := h.Sum()
	nonceBits, nonzero := g.NonceBitsWide(h1, h2)
	P, err := g.MulBits(nonceBits)
	if err != nil {
		return nil, err
	}
	rsigHi, rsigLo := g.XHalves(P)

	posBits := api.ToBinary(posReg, api.Compiler().FieldBitLen())
	depth := len(rec.Path)
	high := frontend.Variable(0)
	for _, b := range posBits[depth:] {
		high = api.Add(high, b)
	}
	inRange := api.IsZero(high)
	root := shared.MerkleRootFromPath(api, rec.Leaf, rec.Path, posBits[:depth])
	api.AssertIsEqual(api.Mul(inRange, api.Sub(root, recordRoot)), 0)

	committed := eqBit(api, rec.Leaf, shared.EntryCommitment(api, posReg, rsigHi, rsigLo))
	return boolAll(api, nonzero, inRange, committed), nil
}

// onCurveBit returns 1 iff (x, y) satisfies a·x² + y² = 1 + d·x²·y².
func onCurveBit(api frontend.API, params *twistededwards.CurveParams, x, y frontend.Variable) frontend.Variable {
	xx := api.Mul(x, x)
	yy := api.Mul(y, y)
	lhs := api.Add(api.Mul(params.A, xx), yy)
	rhs := api.Add(1, api.Mul(params.D, xx, yy))
	return eqBit(api, lhs, rhs)
}

// doubleBaseMul returns [Σ b1[i]·2^i]·p1 + [Σ b2[i]·2^i]·p2 (Straus–Shamir,
// bits little-endian).  It only uses the complete addition law, so for points
// on the curve it has no exceptional case and no unsatisfiable constraint.
func doubleBaseMul(api frontend.API, curve twistededwards.Curve, p1, p2 twistededwards.Point, b1, b2 []frontend.Variable) twistededwards.Point {
	sum := curve.Add(p1, p2)
	pick := func(i int) twistededwards.Point {
		return twistededwards.Point{
			X: api.Lookup2(b1[i], b2[i], 0, p1.X, p2.X, sum.X),
			Y: api.Lookup2(b1[i], b2[i], 1, p1.Y, p2.Y, sum.Y),
		}
	}
	n := len(b1)
	res := pick(n - 1)
	for i := n - 2; i >= 0; i-- {
		res = curve.Add(curve.Double(res), pick(i))
	}
	return res
}

// eddsaVerifyBit is a soft EdDSA verification on the twisted Edwards curve of
// the proving field: it returns 1 iff A and R are curve points, S ≤ ℓ (the
// group order) and [c]([S]B − [h]A − R) is the identity, with
// h = Poseidon(R, A, msg) and c the cofactor.
//
// A and R come out of a ciphertext and can be anything.  Points that are not
// on the curve are replaced by the base point before any curve arithmetic
// (and the result forced to 0), and the scalar multiplications use only the
// complete addition law, so every constraint below is satisfiable for every
// input.  (gnark's Curve.ScalarMul is not: it asserts a hinted result, which
// fails for points outside the prime-order subgroup.)
func eddsaVerifyBit(api frontend.API, curve twistededwards.Curve, ord *fieldOrder, rx, ry, s, ax, ay, msg frontend.Variable) frontend.Variable {
	params := curve.Params()
	base := twistededwards.Point{X: params.Base[0], Y: params.Base[1]}

	onA := onCurveBit(api, params, ax, ay)
	onR := onCurveBit(api, params, rx, ry)
	A := twistededwards.Point{X: api.Select(onA, ax, base.X), Y: api.Select(onA, ay, base.Y)}
	R := twistededwards.Point{X: api.Select(onR, rx, base.X), Y: api.Select(onR, ry, base.Y)}

	h := newPoseidonHasher(api)
	h.Write(rx, ry, ax, ay, msg)
	hBits, _, _ := ord.split(h.Sum())

	sBits, sHi, sLo := ord.split(s)
	orderHi, orderLo := ord.splitConst(params.Order)
	sInRange := ord.lessEq(sHi, sLo, orderHi, orderLo)

	// Q = [S]B − [h]A − R
	Q := doubleBaseMul(api, curve, base, curve.Neg(A), sBits, hBits)
	Q = curve.Add(Q, curve.Neg(R))
	for c := params.Cofactor.Uint64(); c > 1; c >>= 1 {
		Q = curve.Double(Q)
	}
	isIdentity := api.Mul(api.IsZero(Q.X), eqBit(api, Q.Y, 1))
	return boolAll(api, onA, onR, sInRange, isIdentity)
}

/* ================================= Define ================================== */

func (c *CastIronCircuit) Define(api frontend.API) error {
	n := len(c.BulletinBoard)
	m := len(c.Tally)
	if n == 0 || m == 0 {
		return errors.New("the circuit needs at least one ballot and one choice")
	}
	if len(c.RecordOpenings) != n || len(c.Sorted) != n {
		return fmt.Errorf("RecordOpenings and Sorted must have one entry per ballot (%d)", n)
	}
	recordDepth := len(c.RecordOpenings[0].Path)
	if recordDepth < 1 {
		return errors.New("the record tree needs depth ≥ 1")
	}
	fieldBits := api.Compiler().FieldBitLen()

	curve, err := twistededwards.NewEdCurve(api, shared.EdwardsCurveID(api))
	if err != nil {
		return err
	}
	if co := curve.Params().Cofactor; !co.IsUint64() || bits.OnesCount64(co.Uint64()) != 1 {
		return errors.New("unsupported Edwards cofactor")
	}
	opening, err := voteropening.NewFixedBaseGadget(api, openingGadgetOpts, voteropening.ScalarBits)
	if err != nil {
		return err
	}
	ord := newFieldOrder(api)

	// pk_T = Enc.DerivePk(sk_T).  Asserted: a wrong key must not yield a proof
	// (with a soft check it would yield one for the empty tally).
	skBits := api.ToBinary(c.ElGamalSk, fieldBits)
	api.AssertIsEqual(shared.ExpBits(api, c.ElGamalG, skBits), c.ElGamalH)
	dec := func(ct ElGamalCiphertext) frontend.Variable {
		return shared.ElGamalDecryptBits(api, ct.C1, ct.C2, skBits)
	}

	/* ---------------- Decryption and Validate, ballot by ballot ---------------- */

	rows := make([]Row, n) // B_dec: masked rows, in posting order
	for i := range c.BulletinBoard {
		ct := &c.BulletinBoard[i]
		if len(ct.ChoiceC) != m || len(c.Sorted[i].Choice) != m {
			return fmt.Errorf("ballot %d: expected %d choices", i, m)
		}
		if len(c.RecordOpenings[i].Path) != recordDepth {
			return fmt.Errorf("ballot %d: record path length differs", i)
		}

		eid := dec(ct.EidC)
		pkVx, pkVy := dec(ct.PkVoteX_C), dec(ct.PkVoteY_C)
		pkAx, pkAy := dec(ct.PkAnchorX_C), dec(ct.PkAnchorY_C)
		sigRegRx, sigRegRy, sigRegS := dec(ct.B3_RX_C), dec(ct.B3_RY_C), dec(ct.B3_S_C)
		regRand := dec(ct.RegRandC)
		posReg := dec(ct.PosRegC)
		leafIndex := dec(ct.LeafIndexC)
		path := make([]frontend.Variable, len(ct.PathWeightC))
		for k := range path {
			path[k] = dec(ct.PathWeightC[k])
		}
		weight := dec(ct.WeightC)
		choices := make([]frontend.Variable, m)
		for j := range choices {
			choices[j] = dec(ct.ChoiceC[j])
		}
		ballotID := dec(ct.BallotIDC)
		sigBRx, sigBRy, sigBS := dec(ct.B4_RX_C), dec(ct.B4_RY_C), dec(ct.B4_S_C)

		// The ballot belongs to this election and names a credential.  IC.pk =
		// (0, 0) is not a curve point; excluding it explicitly keeps the block
		// of masked (all-zero) rows free of valid ballots.
		okEid := eqBit(api, eid, c.ElectionID)
		okKey := api.Sub(1, api.Mul(api.IsZero(pkAx), api.IsZero(pkAy)))

		// Well-formed choice: one-hot, scaled by the weight.
		okOneHot := singleChoiceBit(api, choices)
		okWeight := sumEqualsBit(api, choices, weight)

		// Weight validity: π_W verifies against Mrk.Root(T_W) for (IC.pk, w).
		okRoll := voterRollBit(api, c.VoterRollRoot, pkAx, pkAy, weight, leafIndex, path)

		// Registration validity: CTC.Open((pk_i, σreg), r, t_reg).
		okReg, err := registrationOpeningBit(api, opening, pkVx, pkVy, sigRegRx, sigRegRy, sigRegS,
			regRand, posReg, c.RegistrationRoot, c.RecordOpenings[i])
		if err != nil {
			return err
		}

		// Registration binding: σreg verifies under IC.pk over (eid, pk_i, IC.pk).
		h := newPoseidonHasher(api)
		h.Write(c.ElectionID, pkVx, pkVy, pkAx, pkAy)
		okSigReg := eddsaVerifyBit(api, curve, ord, sigRegRx, sigRegRy, sigRegS, pkAx, pkAy, h.Sum())

		// Ballot authenticity: σB verifies under pk_i over the ballot.
		h.Reset()
		h.Write(c.ElectionID, pkAx, pkAy, pkVx, pkVy, posReg)
		h.Write(choices...)
		h.Write(weight, sigRegRx, sigRegRy, sigRegS, ballotID)
		okSigB := eddsaVerifyBit(api, curve, ord, sigBRx, sigBRy, sigBS, pkVx, pkVy, h.Sum())

		v := boolAll(api, okEid, okKey, okOneHot, okWeight, okRoll, okReg, okSigReg, okSigB)

		// Masked decryption: an invalid ballot becomes an all-zero row.
		rows[i] = Row{
			PkAnchorX: api.Mul(v, pkAx),
			PkAnchorY: api.Mul(v, pkAy),
			PosReg:    api.Mul(v, posReg),
			BallotID:  api.Mul(v, ballotID),
			Pos:       i + 1,
			Choice:    make([]frontend.Variable, m),
		}
		for j := range choices {
			rows[i].Choice[j] = api.Mul(v, choices[j])
		}
	}

	/* ------------------------- Deduplicate: sorted view ------------------------ */
	// The prover supplies B_sorted; the circuit checks that it is B_dec in
	// strictly increasing (IC.pk, t_reg, id_B, t) order.  Positions are
	// distinct, so this order is total and B_sorted is unique.

	sorted := c.Sorted
	posBits := bits.Len(uint(n))
	posCmp := cmp.NewBoundedComparator(api, big.NewInt(int64(1)<<uint(posBits)-1), false)
	regCmp := cmp.NewBoundedComparator(api, new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(recordDepth)), big.NewInt(1)), false)

	type halves struct{ xHi, xLo, yHi, yLo, idHi, idLo frontend.Variable }
	keys := make([]halves, n)
	for i := range sorted {
		_, keys[i].xHi, keys[i].xLo = ord.split(sorted[i].PkAnchorX)
		_, keys[i].yHi, keys[i].yLo = ord.split(sorted[i].PkAnchorY)
		_, keys[i].idHi, keys[i].idLo = ord.split(sorted[i].BallotID)
		// Ranges the bounded comparators rely on (they hold for B_dec: a valid
		// ballot has t_reg inside the record tree, a masked row has 0).
		api.ToBinary(sorted[i].PosReg, recordDepth)
		api.ToBinary(sorted[i].Pos, posBits)
	}

	samePk := make([]frontend.Variable, n)  // row i has the IC.pk of row i−1
	sameKey := make([]frontend.Variable, n) // ... and the same (t_reg, id_B)
	samePk[0], sameKey[0] = 0, 0
	for i := 1; i < n; i++ {
		a, b, ka, kb := sorted[i-1], sorted[i], keys[i-1], keys[i]
		xEq := eqBit(api, a.PkAnchorX, b.PkAnchorX)
		yEq := eqBit(api, a.PkAnchorY, b.PkAnchorY)
		regEq := eqBit(api, a.PosReg, b.PosReg)
		idEq := eqBit(api, a.BallotID, b.BallotID)
		xLt := ord.less(ka.xHi, ka.xLo, kb.xHi, kb.xLo)
		yLt := ord.less(ka.yHi, ka.yLo, kb.yHi, kb.yLo)
		regLt := regCmp.IsLess(a.PosReg, b.PosReg)
		idLt := ord.less(ka.idHi, ka.idLo, kb.idHi, kb.idLo)
		posLt := posCmp.IsLess(a.Pos, b.Pos)

		// (x, y, t_reg, id_B, t)[i−1] < (x, y, t_reg, id_B, t)[i], lexicographically
		lt := api.Add(idLt, api.Mul(idEq, posLt))
		lt = api.Add(regLt, api.Mul(regEq, lt))
		lt = api.Add(yLt, api.Mul(yEq, lt))
		lt = api.Add(xLt, api.Mul(xEq, lt))
		api.AssertIsEqual(lt, 1)

		samePk[i] = api.Mul(xEq, yEq)
		sameKey[i] = boolAll(api, samePk[i], regEq, idEq)
	}

	// Multiset equality of B_dec and B_sorted by a grand product at a
	// Fiat–Shamir challenge derived from the election identifier, the
	// weight-tree root and the digests of both arrays.
	rowHash := func(r Row) frontend.Variable {
		h := newPoseidonHasher(api)
		h.Write(r.PkAnchorX, r.PkAnchorY, r.PosReg, r.BallotID, r.Pos)
		h.Write(r.Choice...)
		return h.Sum()
	}
	decHashes := make([]frontend.Variable, n)
	sortedHashes := make([]frontend.Variable, n)
	decDigest, sortedDigest := newPoseidonHasher(api), newPoseidonHasher(api)
	for i := 0; i < n; i++ {
		decHashes[i] = rowHash(rows[i])
		sortedHashes[i] = rowHash(sorted[i])
		decDigest.Write(decHashes[i])
		sortedDigest.Write(sortedHashes[i])
	}
	hAlpha := newPoseidonHasher(api)
	hAlpha.Write(fiatShamirTag, c.ElectionID, c.VoterRollRoot, decDigest.Sum(), sortedDigest.Sum())
	alpha := hAlpha.Sum()
	prodDec, prodSorted := frontend.Variable(1), frontend.Variable(1)
	for i := 0; i < n; i++ {
		prodDec = api.Mul(prodDec, api.Add(decHashes[i], alpha))
		prodSorted = api.Mul(prodSorted, api.Add(sortedHashes[i], alpha))
	}
	api.AssertIsEqual(prodDec, prodSorted)

	/* ---------------------- Deduplicate (scan) and Accumulate ------------------ */
	// One pass over B_sorted.  Within a voter's block (equal IC.pk) the rows of
	// the earliest registration come first; within a registration, equal
	// identifiers are adjacent with their earliest occurrence first.  best is
	// the latest of those earliest occurrences seen so far in the block's
	// earliest registration; at the last row of the block it is the voter's
	// final ballot.  Masked rows form the block IC.pk = (0, 0) and carry no
	// weight.

	tally := make([]frontend.Variable, m)
	for j := range tally {
		tally[j] = 0
	}
	var earliestReg, bestPos frontend.Variable
	bestChoice := make([]frontend.Variable, m)
	for i := 0; i < n; i++ {
		row := sorted[i]
		if i == 0 {
			earliestReg, bestPos = row.PosReg, row.Pos
			copy(bestChoice, row.Choice)
		} else {
			newVoter := api.Sub(1, samePk[i])
			first := api.Sub(1, sameKey[i]) // earliest occurrence of its (IC.pk, t_reg, id_B)
			earliestReg = api.Select(newVoter, row.PosReg, earliestReg)
			inEarliest := eqBit(api, row.PosReg, earliestReg)
			later := posCmp.IsLess(bestPos, row.Pos)
			// take the row at the start of a block, or when it supersedes best
			take := api.Add(newVoter, api.Mul(samePk[i], boolAll(api, first, inEarliest, later)))
			bestPos = api.Select(take, row.Pos, bestPos)
			for j := 0; j < m; j++ {
				bestChoice[j] = api.Select(take, row.Choice[j], bestChoice[j])
			}
		}
		last := frontend.Variable(1) // last row of its voter's block
		if i < n-1 {
			last = api.Sub(1, samePk[i+1])
		}
		for j := 0; j < m; j++ {
			tally[j] = api.Add(tally[j], api.Mul(last, bestChoice[j]))
		}
	}
	for j := 0; j < m; j++ {
		api.AssertIsEqual(tally[j], c.Tally[j])
	}
	return nil
}
