package castiron

import (
	"encoding/json"
	"math/big"
	mrand "math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"

	"cast_iron/shared"
)

const testRecord = 1 << 10 // record size of the test-engine tests

func mustSolve(t *testing.T, e *election, a *CastIronCircuit, what string) {
	t.Helper()
	if err := e.solved(a); err != nil {
		t.Fatalf("%s: rejected: %v", what, err)
	}
}

func mustReject(t *testing.T, e *election, a *CastIronCircuit, what string) {
	t.Helper()
	if err := e.solved(a); err == nil {
		t.Fatalf("%s: accepted", what)
	}
}

func wantTally(t *testing.T, a *CastIronCircuit, want ...int64) {
	t.Helper()
	got := tallyInts(a.Tally)
	for j := range want {
		if got[j] != want[j] {
			t.Fatalf("tally %v, want %v", got, want)
		}
	}
}

// flipped returns the election's validity bits with ballot i's bit flipped.
func flipped(e *election, i int) []bool {
	v := e.validity()
	v[i] = !v[i]
	return v
}

/* ------------------------------- Accumulate -------------------------------- */

// One ballot per voter: the result is the weighted sum, and no other result
// is accepted.
func TestHonestElection(t *testing.T) {
	e := newElection(t, 7, 3, []int{1, 2, 3, 4}, testRecord)
	for v, choice := range []int{0, 2, 0, 1} {
		e.cast(e.register(v), choice)
	}
	a := e.assignment()
	wantTally(t, a, 4, 4, 2)
	mustSolve(t, e, a, "honest tally")

	wrong := e.assignment()
	wrong.Tally = []frontend.Variable{5, 4, 1}
	mustReject(t, e, wrong, "wrong result")
}

/* ------------------------------- Deduplicate ------------------------------- */

// A voter who votes again replaces the earlier ballot, wherever other
// voters' ballots fall in between; the prover cannot count the earlier one.
func TestRevoteLatestCounts(t *testing.T) {
	e := newElection(t, 7, 2, []int{1, 1}, testRecord)
	r0, r1 := e.register(0), e.register(1)
	e.cast(r0, 0)
	e.cast(r1, 1)
	e.cast(r0, 1) // voter 0 changes their mind
	a := e.assignment()
	wantTally(t, a, 0, 2)
	mustSolve(t, e, a, "latest ballot counts")

	// Same witness, but the two ballots of voter 0 swapped in the sorted view
	// so that the earlier one would end up as the block's final ballot.
	swapped := e.assignment()
	for i := 0; i+1 < len(swapped.Sorted); i++ {
		s := swapped.Sorted
		if s[i].PkAnchorX.(*big.Int).Cmp(s[i+1].PkAnchorX.(*big.Int)) == 0 {
			s[i], s[i+1] = s[i+1], s[i]
			break
		}
	}
	swapped.Tally = []frontend.Variable{1, 1}
	mustReject(t, e, swapped, "earlier ballot counted via a reordered sorted view")

	stale := e.assignment()
	stale.Tally = []frontend.Variable{1, 1}
	mustReject(t, e, stale, "earlier ballot counted")
}

// The tallier can decrypt a ballot and post a fresh encryption of it.  Such a
// replay carries the original identifier, so it is dropped: replaying an
// overridden ballot after the voter's revote does not bring it back.
func TestReplayedBallotIsIgnored(t *testing.T) {
	e := newElection(t, 7, 2, []int{1, 1}, testRecord)
	r0, r1 := e.register(0), e.register(1)
	first := e.cast(r0, 0)
	e.cast(r1, 0)
	e.cast(r0, 1) // voter 0 revotes
	e.replay(first)
	e.replay(first)
	a := e.assignment()
	wantTally(t, a, 1, 1)
	mustSolve(t, e, a, "replay ignored")

	replayed := e.assignment()
	replayed.Tally = []frontend.Variable{2, 0}
	mustReject(t, e, replayed, "replayed ballot counted")

	// A replay posted ahead of further revotes changes nothing either.
	e2 := newElection(t, 7, 2, []int{5}, testRecord)
	r := e2.register(0)
	b0 := e2.cast(r, 0)
	b1 := e2.cast(r, 1)
	e2.replay(b0)
	e2.cast(r, 0)
	e2.replay(b1)
	a2 := e2.assignment()
	wantTally(t, a2, 5, 0)
	mustSolve(t, e2, a2, "replays interleaved with revotes")
}

// Only ballots cast with the earliest-registered credential count, whatever
// the order of the ballots on the board.
func TestEarliestRegistrationCounts(t *testing.T) {
	e := newElection(t, 7, 2, []int{3, 1}, testRecord)
	real := e.register(0)    // registered first: the voter's true credential
	other := e.register(1)   // another voter
	coerced := e.register(0) // registered later, e.g. under coercion
	e.cast(coerced, 1)
	e.cast(real, 0)
	e.cast(other, 1)
	e.cast(coerced, 1) // cast last, still does not count
	a := e.assignment()
	wantTally(t, a, 3, 1)
	mustSolve(t, e, a, "earliest registration counts")

	later := e.assignment()
	later.Tally = []frontend.Variable{0, 4}
	mustReject(t, e, later, "later registration counted")

	// With only the later credential used, its latest ballot counts.
	e2 := newElection(t, 7, 2, []int{3}, testRecord)
	e2.register(0)
	second := e2.register(0)
	e2.cast(second, 1)
	a2 := e2.assignment()
	wantTally(t, a2, 0, 3)
	mustSolve(t, e2, a2, "sole used registration counts")
}

// Random elections with revotes, replays and several registrations per
// voter: the circuit accepts exactly the reference result.
func TestRandomElections(t *testing.T) {
	rng := mrand.New(mrand.NewSource(1))
	for round := 0; round < 6; round++ {
		nVoters := 1 + rng.Intn(3)
		weights := make([]int, nVoters)
		for i := range weights {
			weights[i] = 1 + rng.Intn(5)
		}
		e := newElection(t, 100+round, 3, weights, testRecord)
		var regs []int
		for v := 0; v < nVoters; v++ {
			for k := 0; k <= rng.Intn(2); k++ {
				regs = append(regs, e.register(v))
			}
		}
		for b := 0; b < 3+rng.Intn(5); b++ {
			switch {
			case len(e.ballots) > 0 && rng.Intn(4) == 0:
				e.replay(rng.Intn(len(e.ballots)))
			case rng.Intn(6) == 0:
				p := e.ballot(regs[rng.Intn(len(regs))], rng.Intn(3))
				p.SigB[2] = shared.RandomScalar()
				e.post(p, false)
			default:
				e.cast(regs[rng.Intn(len(regs))], rng.Intn(3))
			}
		}
		a := e.assignment()
		mustSolve(t, e, a, "random election")
		off := e.assignment()
		off.Tally[0] = new(big.Int).Add(off.Tally[0].(*big.Int), big.NewInt(1))
		mustReject(t, e, off, "random election with a shifted result")
	}
}

/* --------------------------------- Validate -------------------------------- */

// Every way a ballot can fail Validate: the ballot is dropped, the tally still
// proves, and the prover cannot count the ballot anyway.
func TestInvalidBallotsAreDropped(t *testing.T) {
	cases := []struct {
		name   string
		tamper func(e *election, reg int, p *plainBallot)
	}{
		{"other election", func(e *election, reg int, p *plainBallot) { p.Eid = big.NewInt(8) }},
		{"two choices", func(e *election, reg int, p *plainBallot) {
			p.Choices[0], p.Choices[1] = big.NewInt(1), big.NewInt(2)
			e.sign(reg, p)
		}},
		{"choice not equal to weight", func(e *election, reg int, p *plainBallot) {
			p.Choices[0] = big.NewInt(2)
			e.sign(reg, p)
		}},
		{"inflated weight", func(e *election, reg int, p *plainBallot) {
			p.Weight, p.Choices[0] = big.NewInt(100), big.NewInt(100)
			e.sign(reg, p)
		}},
		{"wrong weight-tree path", func(e *election, reg int, p *plainBallot) { p.Path[0] = shared.RandomScalar() }},
		{"wrong weight-tree index", func(e *election, reg int, p *plainBallot) { p.LeafIndex = big.NewInt(0) }},
		{"randomness that does not open the registration", func(e *election, reg int, p *plainBallot) { p.RegRand = shared.RandomScalar() }},
		{"registration position of another transaction", func(e *election, reg int, p *plainBallot) {
			p.PosReg = big.NewInt(0) // voter 0's registration
			e.sign(reg, p)
		}},
		{"empty registration position", func(e *election, reg int, p *plainBallot) {
			p.PosReg = big.NewInt(500)
			e.sign(reg, p)
		}},
		{"voting key not signed by the IC", func(e *election, reg int, p *plainBallot) { p.SigReg = [3]*big.Int{p.SigB[0], p.SigB[1], p.SigB[2]} }},
		{"ballot signature by another key", func(e *election, reg int, p *plainBallot) { e.sign(0, p) }},
		{"signature scalar not below the group order", func(e *election, reg int, p *plainBallot) {
			params, err := twistededwards.GetCurveParams(shared.Curve.Edwards)
			if err != nil {
				panic(err)
			}
			p.SigB[2] = new(big.Int).Add(p.SigB[2], params.Order)
			p.SigB[2].Add(p.SigB[2], params.Order)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newElection(t, 7, 2, []int{1, 3, 2}, testRecord)
			e.cast(e.register(0), 1)
			reg := e.register(1)
			p := e.ballot(reg, 0)
			tc.tamper(e, reg, &p)
			bad := e.post(p, false)
			e.cast(e.register(2), 0)
			a := e.assignment()
			wantTally(t, a, 2, 1)
			mustSolve(t, e, a, "tally without the invalid ballot")
			mustReject(t, e, e.assignmentFor(flipped(e, bad)), "invalid ballot counted")
		})
	}
}

// Ballots are arbitrary ciphertexts: whatever they decrypt to, the relation
// stays satisfiable (a malformed ballot must not be able to block the tally).
func TestMalformedBallotsDoNotBlockTheTally(t *testing.T) {
	huge := new(big.Int).Lsh(big.NewInt(1), 200)
	cases := []struct {
		name   string
		tamper func(p *plainBallot)
	}{
		{"weight-tree index out of range", func(p *plainBallot) { p.LeafIndex = huge }},
		{"registration position out of range", func(p *plainBallot) { p.PosReg = huge }},
		{"voting key not on the curve", func(p *plainBallot) { p.PkVx = shared.RandomScalar() }},
		{"IC key not on the curve", func(p *plainBallot) { p.PkAy = shared.RandomScalar() }},
		{"voting key outside the prime-order subgroup", func(p *plainBallot) {
			// P + (0, −1): on the curve, of even order
			p.PkVx, p.PkVy = new(big.Int).Sub(shared.Field, p.PkVx), new(big.Int).Sub(shared.Field, p.PkVy)
		}},
		{"IC key outside the prime-order subgroup", func(p *plainBallot) {
			p.PkAx, p.PkAy = new(big.Int).Sub(shared.Field, p.PkAx), new(big.Int).Sub(shared.Field, p.PkAy)
		}},
		{"low-order keys", func(p *plainBallot) {
			p.PkVx, p.PkVy = big.NewInt(0), new(big.Int).Sub(shared.Field, big.NewInt(1))
			p.PkAx, p.PkAy = big.NewInt(0), big.NewInt(1)
		}},
		{"signature points not on the curve", func(p *plainBallot) {
			p.SigReg[0], p.SigB[1] = shared.RandomScalar(), shared.RandomScalar()
		}},
		{"all-zero ballot", func(p *plainBallot) {
			z := big.NewInt(0)
			*p = plainBallot{Eid: z, PkVx: z, PkVy: z, PkAx: z, PkAy: z, SigReg: [3]*big.Int{z, z, z}, RegRand: z, PosReg: z,
				LeafIndex: z, Path: []*big.Int{z, z}, Weight: z, Choices: []*big.Int{z, z}, BallotID: z, SigB: [3]*big.Int{z, z, z}}
		}},
		{"random ballot", func(p *plainBallot) {
			r := shared.RandomScalar
			*p = plainBallot{Eid: r(), PkVx: r(), PkVy: r(), PkAx: r(), PkAy: r(), SigReg: [3]*big.Int{r(), r(), r()}, RegRand: r(),
				PosReg: r(), LeafIndex: r(), Path: []*big.Int{r(), r()}, Weight: r(), Choices: []*big.Int{r(), r()}, BallotID: r(),
				SigB: [3]*big.Int{r(), r(), r()}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newElection(t, 7, 2, []int{1, 3, 2}, testRecord)
			e.cast(e.register(0), 1)
			p := e.ballot(e.register(1), 0)
			tc.tamper(&p)
			bad := e.post(p, false)
			e.cast(e.register(2), 0)
			a := e.assignment()
			wantTally(t, a, 2, 1)
			mustSolve(t, e, a, "tally with a malformed ballot on the board")
			if tc.name != "all-zero ballot" { // its row is the masked row either way
				mustReject(t, e, e.assignmentFor(flipped(e, bad)), "malformed ballot counted")
			}
		})
	}
}

/* ------------------------------ malicious tallier --------------------------- */

// The tallier looks up each registration in the public record.  Presenting
// anything but the true record entry is rejected, so the tallier cannot make
// an honest ballot fail Validate and drop it from the result.
func TestTallierCannotDropABallot(t *testing.T) {
	e := newElection(t, 7, 2, []int{1, 3, 2}, testRecord)
	for v, choice := range []int{1, 0, 0} {
		e.cast(e.register(v), choice)
	}
	mustSolve(t, e, e.assignment(), "honest tally")

	tampers := map[string]func(op *RecordOpening){
		"wrong record entry": func(op *RecordOpening) { op.Leaf = shared.RandomScalar() },
		"wrong sibling path": func(op *RecordOpening) { op.Path[3] = shared.RandomScalar() },
		"entry of another position": func(op *RecordOpening) {
			op.Leaf = e.record.Leaf(0)
			for k, s := range e.record.Path(0) {
				op.Path[k] = s
			}
		},
		"empty entry": func(op *RecordOpening) { op.Leaf = shared.EmptyLeaf() },
	}
	for name, tamper := range tampers {
		for _, claim := range [][]bool{flipped(e, 1), e.validity()} {
			a := e.assignmentFor(claim) // claim[1] = false: ballot 1 dropped, result (2, 1) instead of (5, 1)
			op := RecordOpening{Leaf: a.RecordOpenings[1].Leaf, Path: append([]frontend.Variable{}, a.RecordOpenings[1].Path...)}
			tamper(&op)
			a.RecordOpenings[1] = op
			mustReject(t, e, a, name)
		}
	}
}

// pk_T = Enc.DerivePk(sk_T) is part of the relation: no proof with another key,
// in particular not one that decrypts every ballot to garbage and reports an
// empty result.
func TestWrongDecryptionKeyIsRejected(t *testing.T) {
	e := newElection(t, 7, 2, []int{1, 3}, testRecord)
	e.cast(e.register(0), 1)
	e.cast(e.register(1), 0)
	for _, claim := range [][]bool{{false, false}, e.validity()} {
		a := e.assignmentFor(claim)
		a.ElGamalSk = new(big.Int).Add(e.sk, big.NewInt(1))
		mustReject(t, e, a, "wrong decryption key")
	}
}

// B_sorted must be a permutation of B_dec.
func TestSortedViewMustBeAPermutation(t *testing.T) {
	e := newElection(t, 7, 2, []int{1, 3}, testRecord)
	e.cast(e.register(0), 1)
	e.cast(e.register(1), 0)
	mustSolve(t, e, e.assignment(), "honest tally")

	// move a voter's weight to the other choice
	a := e.assignment()
	for i := range a.Sorted {
		if a.Sorted[i].Choice[0].(*big.Int).Sign() != 0 {
			row := a.Sorted[i]
			row.Choice = []frontend.Variable{big.NewInt(0), row.Choice[0]}
			a.Sorted[i] = row
		}
	}
	a.Tally = []frontend.Variable{0, 4}
	mustReject(t, e, a, "altered row")

	// count one voter twice under a second identifier
	b := e.assignment()
	dup := b.Sorted[1]
	dup.Pos = b.Sorted[0].Pos
	b.Sorted[0] = dup
	mustReject(t, e, b, "duplicated row")
}

/* ------------------------------ scenarios, Groth16 -------------------------- */

// JSON scenario format (testdata/): voters with weights, each with
// registrations in record order, each with ballots in posting order.  A
// ballot's flags name the check it is built to fail.
type JSONBallot struct {
	ChoiceIndex     int  `json:"choice_index"`
	GoodAnchorSig   bool `json:"good_anchor_sig"`   // σreg
	GoodVoteSig     bool `json:"good_vote_sig"`     // σB
	GoodVoterMerkle bool `json:"good_voter_merkle"` // π_W
	GoodRegMerkle   bool `json:"good_reg_merkle"`   // CTC opening
}

type JSONRegistration struct {
	Ballots []JSONBallot `json:"ballots"`
}

type JSONVoter struct {
	Weight        int                `json:"weight"`
	Registrations []JSONRegistration `json:"registrations"`
}

type JSONScenario struct {
	ElectionID int         `json:"election_id"`
	NumChoices int         `json:"num_choices"`
	Voters     []JSONVoter `json:"voters"`
}

func electionFromScenario(t testing.TB, scen JSONScenario, recordLeaves int) *election {
	weights := make([]int, len(scen.Voters))
	for i, v := range scen.Voters {
		weights[i] = v.Weight
	}
	e := newElection(t, scen.ElectionID, scen.NumChoices, weights, recordLeaves)
	for vi, v := range scen.Voters {
		for _, jr := range v.Registrations {
			reg := e.register(vi)
			for _, jb := range jr.Ballots {
				p := e.ballot(reg, jb.ChoiceIndex)
				if !jb.GoodAnchorSig {
					p.SigReg = [3]*big.Int{shared.RandomScalar(), shared.RandomScalar(), shared.RandomScalar()}
				}
				if !jb.GoodVoteSig {
					p.SigB = [3]*big.Int{shared.RandomScalar(), shared.RandomScalar(), shared.RandomScalar()}
				}
				if !jb.GoodVoterMerkle {
					p.LeafIndex = new(big.Int).Add(p.LeafIndex, big.NewInt(1))
				}
				if !jb.GoodRegMerkle {
					p.RegRand = shared.RandomScalar()
				}
				e.post(p, jb.GoodAnchorSig && jb.GoodVoteSig && jb.GoodVoterMerkle && jb.GoodRegMerkle)
			}
		}
	}
	return e
}

// TestScenarios runs every testdata/*.json scenario through the test engine.
func TestScenarios(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("testdata", "*.json"))
	if len(files) == 0 {
		t.Skip("no scenario files")
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			var scen JSONScenario
			if err := json.Unmarshal(raw, &scen); err != nil {
				t.Fatal(err)
			}
			e := electionFromScenario(t, scen, testRecord)
			a := e.assignment()
			t.Logf("%d ballots, tally %v", len(e.ballots), tallyInts(a.Tally))
			mustSolve(t, e, a, "scenario")
		})
	}
}

// TestGroth16EndToEnd runs the real pipeline — compile, setup, prove, verify —
// over a 2^30-entry record on a small election with a revote, a replay, a
// second registration and an invalid ballot.
func TestGroth16EndToEnd(t *testing.T) {
	e := newElection(t, 7, 2, []int{1, 2, 4}, 1<<30)
	r0, r1 := e.register(0), e.register(1)
	first := e.cast(r0, 0)
	e.cast(r1, 1)
	e.cast(r0, 1)
	e.replay(first)
	e.cast(e.register(1), 0) // later registration of voter 1: ignored
	p := e.ballot(e.register(2), 0)
	p.SigB[2] = shared.RandomScalar()
	e.post(p, false)

	a := e.assignment()
	wantTally(t, a, 0, 3)
	res := proveGroth16(t, e, 1)
	t.Logf("%d ballots: %d constraints, proof %s, verification %s", len(e.ballots), res.constraints, res.proofs[0], res.verify)
}
