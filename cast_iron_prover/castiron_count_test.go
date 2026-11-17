package castiron

import (
	"math/bits"
	"os"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"

	"cast_iron/shared"
	"cast_iron/voteropening"
)

func compileCount(t testing.TB, c frontend.Circuit) int {
	t.Helper()
	ccs, err := frontend.Compile(shared.Field, r1cs.NewBuilder, c)
	if err != nil {
		t.Fatal(err)
	}
	return ccs.GetNbConstraints()
}

// TestConstraintCounts prints the size of the tallying circuit on the Figure 4
// grid: n ballots from n voters (weight tree of depth ⌈log₂ n⌉), two choices,
// record trees of 2^10, 2^20 and 2^30 entries.  The per-ballot cost is close to
// constant; it grows by one decryption and one tree level per doubling of n.
// CASTIRON_COUNT_MAX raises the largest n compiled (default 8; each ballot
// needs roughly 100 MB to compile).
func TestConstraintCounts(t *testing.T) {
	maxN := 8
	if v := intListEnv("CASTIRON_COUNT_MAX", nil); len(v) == 1 {
		maxN = v[0]
	}
	for _, depth := range []int{10, 20, 30} {
		prev := 0
		for n := 1; n <= maxN; n *= 2 {
			weightDepth := bits.Len(uint(n - 1))
			total := compileCount(t, NewSkeleton(n, 2, weightDepth, depth))
			t.Logf("|T_R| = 2^%d  n = %4d  weight depth %2d: %10d constraints  (%d per ballot)", depth, n, weightDepth, total, total/n)
			if n > 1 && total <= prev {
				t.Fatalf("constraint count not increasing")
			}
			prev = total
		}
	}
}

// part is a circuit computing one building block on free inputs.
type part struct {
	In []frontend.Variable
	f  func(api frontend.API, in []frontend.Variable)
}

func (p *part) Define(api frontend.API) error { p.f(api, p.In); return nil }

// TestConstraintBreakdown prints the cost of the circuit's building blocks
// (the unit costs in the "Size" section of the README).
func TestConstraintBreakdown(t *testing.T) {
	if os.Getenv("CASTIRON_CURVE") != "" {
		t.Logf("curve: %s", shared.Curve.Name)
	}
	cost := func(nIn int, f func(api frontend.API, in []frontend.Variable)) int {
		return compileCount(t, &part{In: make([]frontend.Variable, nIn), f: f})
	}
	fieldBits := shared.Field.BitLen()

	hash := func(k int) int {
		return cost(k, func(api frontend.API, in []frontend.Variable) {
			h := newPoseidonHasher(api)
			h.Write(in...)
			api.AssertIsEqual(h.Sum(), 0)
		})
	}
	t.Logf("Poseidon2, per absorbed element:            %6d", hash(2)-hash(1))
	t.Logf("Poseidon2, two-to-one (Merkle node):        %6d", hash(2))

	decrypt := func(k int) int {
		return cost(2*k+1, func(api frontend.API, in []frontend.Variable) {
			skBits := api.ToBinary(in[0], fieldBits)
			for i := 0; i < k; i++ {
				api.AssertIsEqual(shared.ElGamalDecryptBits(api, in[1+2*i], in[2+2*i], skBits), 0)
			}
		})
	}
	t.Logf("ElGamal decryption, per encrypted field:    %6d  (+%d once per proof for the bits of sk_T)", decrypt(2)-decrypt(1), 2*decrypt(1)-decrypt(2))

	eddsa := func(k int) int {
		return cost(6*k, func(api frontend.API, in []frontend.Variable) {
			curve, err := twistededwards.NewEdCurve(api, shared.EdwardsCurveID(api))
			if err != nil {
				panic(err)
			}
			ord := newFieldOrder(api)
			for i := 0; i < k; i++ {
				v := in[6*i:]
				api.AssertIsEqual(eddsaVerifyBit(api, curve, ord, v[0], v[1], v[2], v[3], v[4], v[5]), 1)
			}
		})
	}
	t.Logf("EdDSA verification (soft):                  %6d", eddsa(2)-eddsa(1))

	const depth = 30
	opening := func(k int) int {
		return cost(k*(9+depth), func(api frontend.API, in []frontend.Variable) {
			g, err := voteropening.NewFixedBaseGadget(api, openingGadgetOpts, voteropening.ScalarBits)
			if err != nil {
				panic(err)
			}
			for i := 0; i < k; i++ {
				v := in[i*(9+depth):]
				ok, err := registrationOpeningBit(api, g, v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7],
					RecordOpening{Leaf: v[8], Path: v[9 : 9+depth]})
				if err != nil {
					panic(err)
				}
				api.AssertIsEqual(ok, 1)
			}
		})
	}
	path := cost(2+depth, func(api frontend.API, in []frontend.Variable) {
		posBits := api.ToBinary(in[0], fieldBits)
		api.AssertIsEqual(shared.MerkleRootFromPath(api, in[1], in[2:], posBits[:depth]), 0)
	}) - cost(1, func(api frontend.API, in []frontend.Variable) { api.ToBinary(in[0], fieldBits) })
	open := opening(2) - opening(1)
	t.Logf("CTC opening at |T_R| = 2^%d, per ballot:    %6d  (of which record path: %d = %d per level)", depth, open, path, path/depth)
	t.Logf("CTC opening without the record path:        %6d  (nonce hash, [c]G on secp256k1, entry commitment)", open-path)

	const weightDepth, choices = 2, 2
	full := func(n, wd int) int { return compileCount(t, NewSkeleton(n, choices, wd, depth)) }
	perBallot := full(3, weightDepth) - full(2, weightDepth)
	fields := 16 + choices + weightDepth
	rest := perBallot - fields*(decrypt(2)-decrypt(1)) - 2*(eddsa(2)-eddsa(1)) - open - rollCost(t, weightDepth) - messageHashes(t)
	t.Logf("whole circuit, per ballot (weight depth %d):  %6d  (%d encrypted fields)", weightDepth, perBallot, fields)
	t.Logf("each further weight-tree level, per ballot: %6d", (full(2, weightDepth+1)-full(2, weightDepth))/2)
	t.Logf("masking, sorted view, multiset check, scan: %6d  (what remains of the per-ballot cost)", rest)
}

// rollCost is the weight-validity check for a tree of the given depth.
func rollCost(t testing.TB, weightDepth int) int {
	return compileCount(t, &part{In: make([]frontend.Variable, 5+weightDepth), f: func(api frontend.API, in []frontend.Variable) {
		api.AssertIsEqual(voterRollBit(api, in[0], in[1], in[2], in[3], in[4], in[5:]), 1)
	}})
}

// messageHashes is the cost of hashing the two signed messages (σreg's and
// σB's) for two choices.
func messageHashes(t testing.TB) int {
	return compileCount(t, &part{In: make([]frontend.Variable, 5+13), f: func(api frontend.API, in []frontend.Variable) {
		h := newPoseidonHasher(api)
		h.Write(in[:5]...)
		api.AssertIsEqual(h.Sum(), 0)
		h.Reset()
		h.Write(in[5:]...)
		api.AssertIsEqual(h.Sum(), 0)
	}})
}
