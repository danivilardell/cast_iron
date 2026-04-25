package main

import (
	"github.com/consensys/gnark/frontend"

	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	stdhash "github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/math/cmp"
	poseidonstd "github.com/consensys/gnark/std/permutation/poseidon2"
	stdEddsa "github.com/consensys/gnark/std/signature/eddsa"

	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
)

/* ======================= Public ballot container ======================= */

type ElGamalCiphertext struct {
	C1 frontend.Variable
	C2 frontend.Variable
}

type BallotCiphertexts struct {
	// Field ciphertexts (ElGamal over scalar field)
	EidC ElGamalCiphertext

	// B1 (keys) encrypted
	PkAnchorX_C ElGamalCiphertext
	PkAnchorY_C ElGamalCiphertext
	PkVoteX_C   ElGamalCiphertext
	PkVoteY_C   ElGamalCiphertext

	// B2 choices encrypted (one-hot * weight)
	ChoiceC []ElGamalCiphertext

	// Encrypted proofs and indices
	PosRegC     ElGamalCiphertext
	PathRegC    []ElGamalCiphertext
	LeafIndexC  ElGamalCiphertext
	PathWeightC []ElGamalCiphertext

	// Encrypted registered weight
	WeightC ElGamalCiphertext

	// B3 (anchor signature) encrypted
	B3_RX_C ElGamalCiphertext
	B3_RY_C ElGamalCiphertext
	B3_S_C  ElGamalCiphertext

	// B4 (vote signature) encrypted
	B4_RX_C ElGamalCiphertext
	B4_RY_C ElGamalCiphertext
	B4_S_C  ElGamalCiphertext
}

/* ======================== Phase 2: Ballot Views ======================== */

// FilteredBallot represents A2[i] = v_i · A1[i]
type FilteredBallot struct {
	// Decrypted and filtered fields (all multiplied by v_i)
	Eid       frontend.Variable
	PkAnchorX frontend.Variable
	PkAnchorY frontend.Variable
	PkVoteX   frontend.Variable
	PkVoteY   frontend.Variable
	Choice    []frontend.Variable
	PosReg    frontend.Variable
	Weight    frontend.Variable

	B3_RX frontend.Variable
	B3_RY frontend.Variable
	B3_S  frontend.Variable
	B4_RX frontend.Variable
	B4_RY frontend.Variable
	B4_S  frontend.Variable
}

// SortedByVoterBallot represents A★ (sorted by pk_anchor, then posReg)
// This is the final sorted view, combining what was A3 and A4
// Same structure as FilteredBallot, but reordered lexicographically by (pk_anchor, posReg)
type SortedByVoterBallot = FilteredBallot

/* ============================== Circuit IO ============================== */

type CastIronCircuit struct {
	// Public context
	ElectionID       frontend.Variable `gnark:",public"`
	VoterRollRoot    frontend.Variable `gnark:",public"`
	RegistrationRoot frontend.Variable `gnark:",public"`

	// ElGamal pub params (public)
	ElGamalG frontend.Variable `gnark:",public"`
	ElGamalH frontend.Variable `gnark:",public"`

	// Phase 1: A1 = Bulletin board (encrypted, public)
	BulletinBoard []BallotCiphertexts `gnark:",public"`

	// ElGamal secret key (secret)
	ElGamalSk frontend.Variable `gnark:",secret"`

	// Phase 1 Output: per-ballot validity (secret)
	ValidityBits []frontend.Variable `gnark:",secret"`

	// Phase 2 Outputs:
	// A2 = Filtered ballots (v_i · decrypted, secret)
	FilteredBallots []FilteredBallot `gnark:",secret"`

	// A★ = Sorted by (pk_anchor, posReg) lexicographically (ascending, secret)
	// This combines what were previously A3 and A4 into a single sorted view
	SortedByVoterBallots []SortedByVoterBallot `gnark:",secret"`

	// Phase 2 Final Output: Tally vector (public)
	// T[j] = total votes for choice j (sum over all kept ballots)
	Tally []frontend.Variable `gnark:",public"`
}

/* ============================== ElGamal helpers ============================= */

const (
	poseidonWidth         = 2
	poseidonFullRounds    = 6
	poseidonPartialRounds = 50
)

const elgamalExpBits = 254

func expByBits(api frontend.API, base, exp frontend.Variable) frontend.Variable {
	bits := api.ToBinary(exp, elgamalExpBits)
	result := frontend.Variable(1)
	basePow := base
	for _, bit := range bits {
		mul := api.Mul(result, basePow)
		result = api.Select(bit, mul, result)
		basePow = api.Mul(basePow, basePow)
	}
	return result
}

func elgamalDecryptScalar(api frontend.API, c1, c2, sk frontend.Variable) frontend.Variable {
	shared := expByBits(api, c1, sk)
	return api.Mul(c2, api.Inverse(shared))
}

func newPoseidonHasher(api frontend.API) stdhash.FieldHasher {
	perm, err := poseidonstd.NewPoseidon2FromParameters(api, poseidonWidth, poseidonFullRounds, poseidonPartialRounds)
	if err != nil {
		panic(err)
	}
	return stdhash.NewMerkleDamgardHasher(api, perm, 0)
}

/* ============================== Messages ============================== */

func buildMsgB3(api frontend.API, eid, pkVx, pkVy, pkAx, pkAy frontend.Variable) frontend.Variable {
	h := newPoseidonHasher(api)
	h.Write(eid)
	h.Write(pkVx)
	h.Write(pkVy)
	h.Write(pkAx)
	h.Write(pkAy)
	return h.Sum()
}

func buildMsgB4(
	api frontend.API,
	eid, mrkRoot, regRoot frontend.Variable,
	pkAx, pkAy, pkVx, pkVy frontend.Variable,
	posReg frontend.Variable,
	b2 []frontend.Variable,
	weight frontend.Variable,
	b3Rx, b3Ry, b3S frontend.Variable,
) frontend.Variable {
	h := newPoseidonHasher(api)
	h.Write(eid)
	h.Write(mrkRoot)
	h.Write(regRoot)

	// B1 (no path)
	h.Write(pkAx)
	h.Write(pkAy)
	h.Write(pkVx)
	h.Write(pkVy)
	h.Write(posReg)

	// B2 (no path)
	for _, v := range b2 {
		h.Write(v)
	}
	h.Write(weight)

	// B3
	h.Write(b3Rx)
	h.Write(b3Ry)
	h.Write(b3S)
	return h.Sum()
}

/* ========================== Soft predicates (bits) ========================== */

// eqBit returns 1 iff a==b else 0
func eqBit(api frontend.API, a, b frontend.Variable) frontend.Variable {
	return api.IsZero(api.Sub(a, b)) // 1 if zero, 0 otherwise
}

// pointEqBit: 1 iff P==Q (both coords equal)
func pointEqBit(api frontend.API, px, py, qx, qy frontend.Variable) frontend.Variable {
	xb := eqBit(api, px, qx)
	yb := eqBit(api, py, qy)
	return api.Mul(xb, yb)
}

// boolAll returns AND of all bits in xs
func boolAll(api frontend.API, xs ...frontend.Variable) frontend.Variable {
	if len(xs) == 0 {
		return 1
	}
	acc := xs[0]
	for i := 1; i < len(xs); i++ {
		acc = api.Mul(acc, xs[i])
	}
	return acc
}

// singleChoiceBit: 1 iff exactly one entry in vec is nonzero
func singleChoiceBit(api frontend.API, vec []frontend.Variable) frontend.Variable {
	sumZ := frontend.Variable(0)
	for _, v := range vec {
		z := api.Sub(1, api.IsZero(v)) // 1 iff v != 0
		sumZ = api.Add(sumZ, z)
	}
	return eqBit(api, sumZ, 1)
}

// sumEqualsBit: 1 iff sum(vec) == target
func sumEqualsBit(api frontend.API, vec []frontend.Variable, target frontend.Variable) frontend.Variable {
	sum := frontend.Variable(0)
	for _, v := range vec {
		sum = api.Add(sum, v)
	}
	return eqBit(api, sum, target)
}

// voterRollBit: 1 iff Merkle(root, path) verifies for leaf = Poseidon(pkAx, pkAy, weight).
// SOFT verification: returns 0/1 without asserting (no proof failure on invalid Merkle proof)
func voterRollBit(
	api frontend.API,
	root frontend.Variable,
	path []frontend.Variable,
	leafIndex frontend.Variable,
	pkAx, pkAy, weight frontend.Variable,
) frontend.Variable {
	// Compute expected leaf value
	hLeaf := newPoseidonHasher(api)
	hLeaf.Write(pkAx, pkAy, weight)
	computedLeaf := hLeaf.Sum()

	// Verify that path[0] == computedLeaf (binds the key to this proof)
	leafOk := eqBit(api, path[0], computedLeaf)

	// Soft Merkle verification matching gnark's library behavior:
	// 1. Hash path[0] with leafSum (single element hash)
	h := newPoseidonHasher(api)
	h.Write(path[0])
	sum := h.Sum()

	// 2. Fold up the tree
	depth := len(path) - 1
	if depth > 0 {
		binLeaf := api.ToBinary(leafIndex, depth)
		for i := 1; i < len(path); i++ {
			// Match gnark's Select logic (lines 87-89 of verify.go)
			d1 := api.Select(binLeaf[i-1], path[i], sum)
			d2 := api.Select(binLeaf[i-1], sum, path[i])
			h.Reset()
			h.Write(d1, d2)
			sum = h.Sum()
		}
	}

	// 3. Check if computed root matches
	rootOk := eqBit(api, sum, root)

	// Both must match: correct leaf and valid Merkle path
	return api.Mul(leafOk, rootOk)
}

// registrationInclusionBit: 1 iff registration Merkle verifies.
// expectedLeaf = Poseidon(tag=0, posReg, Poseidon(b3Rx,b3Ry,b3S))
// SOFT verification: returns 0/1 without asserting
func registrationInclusionBit(
	api frontend.API,
	root frontend.Variable,
	path []frontend.Variable,
	posReg frontend.Variable,
	b3Rx, b3Ry, b3S frontend.Variable,
) frontend.Variable {
	// H(B3)
	hSig := newPoseidonHasher(api)
	hSig.Write(b3Rx, b3Ry, b3S)
	b3Hash := hSig.Sum()

	// expected leaf = Poseidon(0, posReg, H(B3))
	hLeaf := newPoseidonHasher(api)
	hLeaf.Write(0, posReg, b3Hash)
	computedLeaf := hLeaf.Sum()

	// path[0] should be the leaf (this matches gnark-crypto proofs)
	leafOk := eqBit(api, path[0], computedLeaf)

	// start folding from the actual leaf
	h := newPoseidonHasher(api)
	sum := path[0]

	// IMPORTANT CHANGE: use len(path) bits, not len(path)-1
	depth := len(path)
	if depth > 0 {
		// we need as many bits as levels we’re going to walk
		binIndex := api.ToBinary(posReg, depth)
		for i := 1; i < len(path); i++ {
			// if the i-1'th bit is 1, sibling is on the left; otherwise on the right
			left := api.Select(binIndex[i-1], path[i], sum)
			right := api.Select(binIndex[i-1], sum, path[i])

			h.Reset()
			h.Write(left, right)
			sum = h.Sum()
		}
	}

	rootOk := eqBit(api, sum, root)
	return api.Mul(leafOk, rootOk)
}

// eddsaVerifyBit: soft EdDSA verify over BN254 Edwards.
// Returns 1 iff:
//   - R is on the curve
//   - [s]G == R + [h]A
//
// else returns 0.
func eddsaVerifyBit(
	api frontend.API,
	curve twistededwards.Curve,
	sig stdEddsa.Signature,
	msg frontend.Variable,
	pub stdEddsa.PublicKey,
) frontend.Variable {
	// 1. H(R, A, M) with Poseidon
	hPoseidon := newPoseidonHasher(api)
	hPoseidon.Write(sig.R.X, sig.R.Y, pub.A.X, pub.A.Y, msg)
	hRAM := hPoseidon.Sum()

	params := curve.Params()

	// 2. base point from curve params (this is what gnark does)
	base := twistededwards.Point{
		X: params.Base[0],
		Y: params.Base[1],
	}

	// 3. check S <= order  (soft)
	sLeOrder := cmp.IsLessOrEqual(api, sig.S, params.Order)

	// 4. compute [S]B - [h]A
	negA := curve.Neg(pub.A)
	sB := curve.ScalarMul(base, sig.S)   // [S]B
	hNegA := curve.ScalarMul(negA, hRAM) // [-h]A = [h](-A)
	Q := curve.Add(sB, hNegA)            // Q = [S]B - [h]A

	// 5. Q = Q - R   (official:  Q = curve.Add(curve.Neg(Q), sig.R))
	//    we'll do it as Q + (-R)
	negR := curve.Neg(sig.R)
	Q = curve.Add(Q, negR)

	// 6. multiply by cofactor (same pattern as official)
	//    we do it unconditionally, then test if result is identity
	cofactor := params.Cofactor.Uint64()
	switch cofactor {
	case 4:
		Q = curve.Double(curve.Double(Q))
	case 8:
		Q = curve.Double(curve.Double(curve.Double(Q)))
	default:
		// if it's something else, we just won't cofactor-clear;
		// the identity check below will likely fail -> bit=0
	}

	// 7. final check: Q == identity (0,1)
	onId := pointEqBit(api, Q.X, Q.Y, 0, 1)

	// 8. extra safety: reject obviously off-curve R
	//    (since your test sometimes puts random scalars in R for bad sigs)
	//    This keeps the add gadgets happy and makes bad sigs -> 0.
	x2 := api.Mul(sig.R.X, sig.R.X)
	y2 := api.Mul(sig.R.Y, sig.R.Y)
	ax2 := api.Mul(params.A, x2)
	lhs := api.Add(ax2, y2)
	x2y2 := api.Mul(x2, y2)
	dx2y2 := api.Mul(params.D, x2y2)
	rhs := api.Add(1, dx2y2)
	onCurveR := api.IsZero(api.Sub(lhs, rhs))

	// 9. all conditions must hold
	return api.Mul(api.Mul(sLeOrder, onCurveR), onId)
}

/* =============================== Define ================================= */
func (c *CastIronCircuit) Define(api frontend.API) error {
	// curve (for ops only; we avoid any Assert* from gadgets in ballot path)
	curve, err := twistededwards.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}

	n := len(c.BulletinBoard)
	if n == 0 {
		return nil
	}
	numChoices := len(c.BulletinBoard[0].ChoiceC)

	// Prepare output vectors with proper allocation
	if len(c.ValidityBits) != n {
		c.ValidityBits = make([]frontend.Variable, n)
	}

	// Allocate A2 (FilteredBallots) with Choice slices
	if len(c.FilteredBallots) != n {
		c.FilteredBallots = make([]FilteredBallot, n)
	}
	for i := 0; i < n; i++ {
		if len(c.FilteredBallots[i].Choice) != numChoices {
			c.FilteredBallots[i].Choice = make([]frontend.Variable, numChoices)
		}
	}

	// Global key relation (soft): okKey = 1 iff H == G^sk
	okKey := eqBit(api, expByBits(api, c.ElGamalG, c.ElGamalSk), c.ElGamalH)

	/* ======================= Decrypt Once & Process ======================= */
	// Decrypt all ballots once, then use for both validity checks and filtering

	for i := 0; i < n; i++ {
		ct := c.BulletinBoard[i]

		/* 1) Decrypt all fields */
		eidDec := elgamalDecryptScalar(api, ct.EidC.C1, ct.EidC.C2, c.ElGamalSk)
		pkAx := elgamalDecryptScalar(api, ct.PkAnchorX_C.C1, ct.PkAnchorX_C.C2, c.ElGamalSk)
		pkAy := elgamalDecryptScalar(api, ct.PkAnchorY_C.C1, ct.PkAnchorY_C.C2, c.ElGamalSk)
		pkVx := elgamalDecryptScalar(api, ct.PkVoteX_C.C1, ct.PkVoteX_C.C2, c.ElGamalSk)
		pkVy := elgamalDecryptScalar(api, ct.PkVoteY_C.C1, ct.PkVoteY_C.C2, c.ElGamalSk)
		weightDec := elgamalDecryptScalar(api, ct.WeightC.C1, ct.WeightC.C2, c.ElGamalSk)
		posRegDec := elgamalDecryptScalar(api, ct.PosRegC.C1, ct.PosRegC.C2, c.ElGamalSk)
		leafIndexDec := elgamalDecryptScalar(api, ct.LeafIndexC.C1, ct.LeafIndexC.C2, c.ElGamalSk)

		choices := make([]frontend.Variable, numChoices)
		for j := 0; j < numChoices; j++ {
			choices[j] = elgamalDecryptScalar(api, ct.ChoiceC[j].C1, ct.ChoiceC[j].C2, c.ElGamalSk)
		}

		b3Rx := elgamalDecryptScalar(api, ct.B3_RX_C.C1, ct.B3_RX_C.C2, c.ElGamalSk)
		b3Ry := elgamalDecryptScalar(api, ct.B3_RY_C.C1, ct.B3_RY_C.C2, c.ElGamalSk)
		b3S := elgamalDecryptScalar(api, ct.B3_S_C.C1, ct.B3_S_C.C2, c.ElGamalSk)
		b4Rx := elgamalDecryptScalar(api, ct.B4_RX_C.C1, ct.B4_RX_C.C2, c.ElGamalSk)
		b4Ry := elgamalDecryptScalar(api, ct.B4_RY_C.C1, ct.B4_RY_C.C2, c.ElGamalSk)
		b4S := elgamalDecryptScalar(api, ct.B4_S_C.C1, ct.B4_S_C.C2, c.ElGamalSk)

		/* 2) Phase 1: Validity Checks using decrypted values */
		okEid := eqBit(api, eidDec, c.ElectionID)

		// Rebuild keys/signatures for validity checks
		pkAnchor := stdEddsa.PublicKey{A: twistededwards.Point{X: pkAx, Y: pkAy}}
		pkVote := stdEddsa.PublicKey{A: twistededwards.Point{X: pkVx, Y: pkVy}}
		sigB3 := stdEddsa.Signature{R: twistededwards.Point{X: b3Rx, Y: b3Ry}, S: b3S}
		sigB4 := stdEddsa.Signature{R: twistededwards.Point{X: b4Rx, Y: b4Ry}, S: b4S}

		// Soft predicates (bits)
		okOneHot := singleChoiceBit(api, choices)
		okWeight := sumEqualsBit(api, choices, weightDec)
		pathWeightDec := make([]frontend.Variable, len(ct.PathWeightC))
		for j := range ct.PathWeightC {
			pathWeightDec[j] = elgamalDecryptScalar(api, ct.PathWeightC[j].C1, ct.PathWeightC[j].C2, c.ElGamalSk)
		}
		pathRegDec := make([]frontend.Variable, len(ct.PathRegC))
		for j := range ct.PathRegC {
			pathRegDec[j] = elgamalDecryptScalar(api, ct.PathRegC[j].C1, ct.PathRegC[j].C2, c.ElGamalSk)
		}

		okVoterRoll := voterRollBit(api, c.VoterRollRoot, pathWeightDec, leafIndexDec, pkAx, pkAy, weightDec)
		okReg := registrationInclusionBit(api, c.RegistrationRoot, pathRegDec, posRegDec, b3Rx, b3Ry, b3S)

		msgB3 := buildMsgB3(api, c.ElectionID, pkVx, pkVy, pkAx, pkAy)
		okSigB3 := eddsaVerifyBit(api, curve, sigB3, msgB3, pkAnchor)

		msgB4 := buildMsgB4(api, c.ElectionID, c.VoterRollRoot, c.RegistrationRoot,
			pkAx, pkAy, pkVx, pkVy, posRegDec, choices, weightDec, b3Rx, b3Ry, b3S)
		okSigB4 := eddsaVerifyBit(api, curve, sigB4, msgB4, pkVote)

		// Combine all validity checks
		c.ValidityBits[i] = boolAll(api,
			okKey,       // global key relation must hold
			okEid,       // binds to this election
			okOneHot,    // exactly one choice
			okWeight,    // weight matches sum
			okVoterRoll, // voter roll inclusion
			okReg,       // registration inclusion
			okSigB3,     // anchor signature
			okSigB4,     // vote signature
		)
		api.AssertIsBoolean(c.ValidityBits[i])

		/* 3) Phase 2: A2 = Filtered Ballots (v_i · decrypted values) */
		v := c.ValidityBits[i]

		c.FilteredBallots[i].Eid = api.Mul(v, eidDec)
		c.FilteredBallots[i].PkAnchorX = api.Mul(v, pkAx)
		c.FilteredBallots[i].PkAnchorY = api.Mul(v, pkAy)
		c.FilteredBallots[i].PkVoteX = api.Mul(v, pkVx)
		c.FilteredBallots[i].PkVoteY = api.Mul(v, pkVy)
		c.FilteredBallots[i].PosReg = api.Mul(v, posRegDec)
		c.FilteredBallots[i].Weight = api.Mul(v, weightDec)

		for j := 0; j < numChoices; j++ {
			c.FilteredBallots[i].Choice[j] = api.Mul(v, choices[j])
		}

		c.FilteredBallots[i].B3_RX = api.Mul(v, b3Rx)
		c.FilteredBallots[i].B3_RY = api.Mul(v, b3Ry)
		c.FilteredBallots[i].B3_S = api.Mul(v, b3S)
		c.FilteredBallots[i].B4_RX = api.Mul(v, b4Rx)
		c.FilteredBallots[i].B4_RY = api.Mul(v, b4Ry)
		c.FilteredBallots[i].B4_S = api.Mul(v, b4S)
	}

	/* ======================= Phase 2: A2 → A3 (Sort by voter) ======================= */
	// A3 is A2 sorted by pk_anchor (ascending)
	// Need to verify: 1) A3 is sorted and 2) SetEq(A2, A3)

	// Helper: hash a ballot row with domain separation
	const rowDom = 777
	rowHash := func(rb FilteredBallot) frontend.Variable {
		h := newPoseidonHasher(api)
		h.Write(rowDom)
		h.Write(rb.Eid)
		h.Write(rb.PkAnchorX)
		h.Write(rb.PkAnchorY)
		h.Write(rb.PkVoteX)
		h.Write(rb.PkVoteY)
		h.Write(rb.PosReg)
		h.Write(rb.Weight)
		for j := 0; j < numChoices; j++ {
			h.Write(rb.Choice[j])
		}
		h.Write(rb.B3_RX)
		h.Write(rb.B3_RY)
		h.Write(rb.B3_S)
		h.Write(rb.B4_RX)
		h.Write(rb.B4_RY)
		h.Write(rb.B4_S)
		return h.Sum()
	}

	/* ======================= Phase 2: A2 → A★ (Sort by voter + registration) ======================= */
	// A★ = SortedByVoterBallots is sorted lexicographically by (pk_anchor, posReg)
	// This single step combines what were A3 (sort by pk) and A4 (sort by posReg within voter)
	// Need to verify: 1) A★ is globally sorted and 2) SetEq(A2, A★)

	// Get field bit length (254 on BN254)
	fieldBits := int(api.Compiler().FieldBitLen())

	// Range-bind all pk_anchor coordinates and posReg for A★
	for i := 0; i < n; i++ {
		api.ToBinary(c.SortedByVoterBallots[i].PkAnchorX, fieldBits)
		api.ToBinary(c.SortedByVoterBallots[i].PkAnchorY, fieldBits)
		api.ToBinary(c.SortedByVoterBallots[i].PosReg, fieldBits)
	}

	// 1) Verify global lexicographic sortedness: (pkX, pkY, posReg) sorted ascending
	// This enforces: same-voter rows are contiguous AND sorted by posReg within each voter
	// 1) Verify global lexicographic sortedness: (pkX, pkY, posReg) sorted ascending
	for i := 0; i < n-1; i++ {
		x1 := c.SortedByVoterBallots[i].PkAnchorX
		y1 := c.SortedByVoterBallots[i].PkAnchorY
		p1 := c.SortedByVoterBallots[i].PosReg
		x2 := c.SortedByVoterBallots[i+1].PkAnchorX
		y2 := c.SortedByVoterBallots[i+1].PkAnchorY
		p2 := c.SortedByVoterBallots[i+1].PosReg

		// Lexicographic comparison helpers
		// Note: Variables are already range-bound to fieldBits above
		xLT := cmp.IsLess(api, x1, x2)
		xEQ := eqBit(api, x1, x2)
		yLT := cmp.IsLess(api, y1, y2)
		yEQ := eqBit(api, y1, y2)
		pLE := cmp.IsLessOrEqual(api, p1, p2)

		// (x1,y1,p1) ≤_lex (x2,y2,p2)
		sorted := api.Add(
			xLT,
			api.Mul(
				xEQ,
				api.Add(
					yLT,
					api.Mul(yEQ, pLE),
				),
			),
		)
		api.AssertIsEqual(sorted, 1)
	}

	// 2) Verify multiset equality: SetEq(A2, A★) using Fiat-Shamir product check
	// Derive challenge α from public context with domain separation
	const tagA2toAstar = 0xA23 // Domain tag for A2→A★ check
	hAlpha := newPoseidonHasher(api)
	hAlpha.Write(tagA2toAstar, c.ElectionID, c.VoterRollRoot, c.RegistrationRoot)
	alpha := hAlpha.Sum()

	// Product check: ∏(hash(A2[i]) + α) == ∏(hash(A★[i]) + α)
	prodA2 := frontend.Variable(1)
	prodAstar := frontend.Variable(1)

	for i := 0; i < n; i++ {
		h2 := rowHash(c.FilteredBallots[i])
		hStar := rowHash(c.SortedByVoterBallots[i])
		prodA2 = api.Mul(prodA2, api.Add(h2, alpha))
		prodAstar = api.Mul(prodAstar, api.Add(hStar, alpha))
	}

	// Multiset equality: products must match
	api.AssertIsEqual(prodA2, prodAstar)

	/* ======================= Phase 2: Deduplication & Tally ======================= */
	// We are sorted by (pk_anchor, posReg) ASC.
	// To keep the *earliest* registration per voter, we keep the FIRST row of each pk_anchor block.

	keepBits := make([]frontend.Variable, n)
	for i := 0; i < n; i++ {
		if i == 0 {
			// very first row: always start a new block → keep
			keepBits[i] = 1
		} else {
			// compare with previous row (i-1), not next row
			xPrev := c.SortedByVoterBallots[i-1].PkAnchorX
			yPrev := c.SortedByVoterBallots[i-1].PkAnchorY
			xCurr := c.SortedByVoterBallots[i].PkAnchorX
			yCurr := c.SortedByVoterBallots[i].PkAnchorY

			// pkSame = 1 if same anchor as previous
			xSame := api.IsZero(api.Sub(xCurr, xPrev))
			ySame := api.IsZero(api.Sub(yCurr, yPrev))
			pkSame := api.Mul(xSame, ySame)

			// keep_i = 1 iff this starts a new pk block
			keepBits[i] = api.Sub(1, pkSame)
		}
	}

	// Compute tally: T[j] = Σ_i keep_i · A★[i].Choice[j]
	computedTally := make([]frontend.Variable, numChoices)
	for j := 0; j < numChoices; j++ {
		sum := frontend.Variable(0)
		for i := 0; i < n; i++ {
			contribution := api.Mul(keepBits[i], c.SortedByVoterBallots[i].Choice[j])
			sum = api.Add(sum, contribution)
		}
		computedTally[j] = sum
	}

	// Assert that computed tally matches the public tally input
	for j := 0; j < numChoices; j++ {
		api.AssertIsEqual(computedTally[j], c.Tally[j])
	}

	// // Optional: Enforce all ballots are valid (disable for soft validation testing)
	// // Comment out below if you want to allow invalid ballots in the proof:
	// all := frontend.Variable(1)
	// for i := 0; i < n; i++ {
	// 	all = api.Mul(all, c.ValidityBits[i])
	// }
	// api.AssertIsEqual(all, 1) // This will fail the proof if ANY ballot is invalid

	return nil
}
