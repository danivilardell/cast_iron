package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	tedwardsCrypto "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/consensys/gnark-crypto/hash"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"

	"cast_iron/shared"
	"cast_iron/voteropening"
)

/* ----------------------------- Proof system ----------------------------- */

type ProofSystem int

const (
	Groth16 ProofSystem = iota
	Plonk
)

func (ps ProofSystem) String() string {
	if ps == Plonk {
		return "plonk"
	}
	return "groth16"
}

// simulatedBlockchainLeaves determines the total number of leaves in the
// registration Merkle tree. We only materialize the registration leaves and
// lazily fill the rest so we can simulate a massive chain without storing it.
const simulatedBlockchainLeaves = 1 << 32

/* ---------------------------- JSON structures ---------------------------- */

type JSONBallot struct {
	ChoiceIndex     int  `json:"choice_index"`
	GoodAnchorSig   bool `json:"good_anchor_sig"`
	GoodVoteSig     bool `json:"good_vote_sig"`
	GoodVoterMerkle bool `json:"good_voter_merkle"`
	GoodRegMerkle   bool `json:"good_reg_merkle"`
}

type JSONRegistration struct {
	NumBallots int          `json:"num_ballots"`
	Ballots    []JSONBallot `json:"ballots"`
}

type JSONVoter struct {
	Weight           int                `json:"weight"`
	NumRegistrations int                `json:"num_registrations"`
	Registrations    []JSONRegistration `json:"registrations"`
}

type JSONScenario struct {
	ElectionID int         `json:"election_id"`
	NumChoices int         `json:"num_choices"`
	Voters     []JSONVoter `json:"voters"`
}

/* ---------------------- small helpers we need ------------------------- */

// random scalar in BN254
func randomScalar() *big.Int {
	r, _ := rand.Int(rand.Reader, ecc.BN254.ScalarField())
	return r
}

func bytesToBig(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}

/* ---------------------- Poseidon helpers (same as simple fix) ---------- */

func poseidonHashFieldsTest(vals ...*big.Int) *big.Int {
	return poseidonHashFields(vals...)
}

/* ---------------------- custom Merkle: voter-roll ---------------------- */
/*
circuit voterRollBit does:
- leaf = Poseidon(pkAx, pkAy, weight)
- sum = Poseidon(path[0])      // unary hash!
- then folds with Poseidon(left,right)

So we build a tree whose level-0 nodes are Poseidon(leaf), but our proof’s path[0]
is the *raw* leaf (so the circuit can hash path[0] itself).
*/
func buildUnaryMerkleTest(leaves []*big.Int) (*big.Int, [][]*big.Int) {
	n := len(leaves)
	if n == 0 {
		return big.NewInt(0), nil
	}

	level0 := make([]*big.Int, n)
	for i := range leaves {
		level0[i] = poseidonHashFieldsTest(leaves[i])
	}

	levels := [][]*big.Int{level0}
	curr := level0
	for len(curr) > 1 {
		next := make([]*big.Int, 0, (len(curr)+1)/2)
		for i := 0; i < len(curr); i += 2 {
			if i+1 < len(curr) {
				next = append(next, poseidonHashFieldsTest(curr[i], curr[i+1]))
			} else {
				next = append(next, poseidonHashFieldsTest(curr[i], curr[i]))
			}
		}
		levels = append(levels, next)
		curr = next
	}
	root := levels[len(levels)-1][0]

	// proofs
	proofs := make([][]*big.Int, n)
	for i := 0; i < n; i++ {
		idx := i
		path := []*big.Int{leaves[i]} // circuit wants leaf here
		for lvl := 0; lvl < len(levels)-1; lvl++ {
			nodes := levels[lvl]
			var sib *big.Int
			if idx%2 == 0 {
				if idx+1 < len(nodes) {
					sib = nodes[idx+1]
				} else {
					sib = nodes[idx]
				}
			} else {
				sib = nodes[idx-1]
			}
			path = append(path, sib)
			idx = idx / 2
		}
		proofs[i] = path
	}

	return root, proofs
}

/* ---------------------- custom Merkle: registration -------------------- */
/*
circuit registrationInclusionBit does:
- leaf = Poseidon(0, posReg, H(B3))
- sum = path[0]            // no unary hash
- then folds with Poseidon(left,right), using bits of posReg

So we build a plain Poseidon Merkle over those leaves and put leaf at path[0].
*/
func buildPlainMerkleTest(leaves []*big.Int, totalLeaves int) (*big.Int, [][]*big.Int) {
	root, sib := shared.BuildPlainMerkle(leaves, totalLeaves)
	proofs := make([][]*big.Int, len(leaves))
	for i := range leaves {
		proofs[i] = append([]*big.Int{leaves[i]}, sib[i]...)
	}
	return root, proofs
}

/* ----------------------------- scenario build ---------------------------- */

// circuitKeyTag versions the cached proving keys in keys/: keys generated for
// earlier versions of the circuit are not valid for the current one.
const circuitKeyTag = "open1"

// plainBallot is the cleartext content of one ballot (as the circuit decrypts it).
type plainBallot struct {
	PkAx, PkAy *big.Int
	PkVx, PkVy *big.Int
	PosReg     *big.Int
	Choices    []*big.Int
	Weight     *big.Int
	B3_Rx      *big.Int
	B3_Ry      *big.Int
	B3_S       *big.Int
	B4_Rx      *big.Int
	B4_Ry      *big.Int
	B4_S       *big.Int
}

// scenarioBuild is everything derived from a JSON scenario: the circuit
// skeleton (for compilation), the full assignment and the expected outputs.
type scenarioBuild struct {
	skeleton      *CastIronCircuit
	assignment    CastIronCircuit
	numBallots    int
	numChoices    int
	expectedTally []frontend.Variable

	eid                    *big.Int
	voterRootBI, regRootBI *big.Int
	plain                  []plainBallot
	validity               []bool // circuit-computed validity, as expected by the witness views
	openings               []RecordOpening
	recordDepth            int
}

func compileCircuit(t testing.TB, skeleton *CastIronCircuit, ps ProofSystem) constraint.ConstraintSystem {
	t.Helper()
	var builder frontend.NewBuilder = r1cs.NewBuilder
	if ps == Plonk {
		builder = scs.NewBuilder
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, skeleton)
	if err != nil {
		t.Fatal(err)
	}
	return ccs
}

func boolsToVars(bs []bool) []frontend.Variable {
	out := make([]frontend.Variable, len(bs))
	for i, b := range bs {
		if b {
			out[i] = 1
		} else {
			out[i] = 0
		}
	}
	return out
}

// deriveViews computes the filtered rows (A2), the sorted view (A★) and the
// expected tally for the given validity flags, applying the same rules as the
// circuit (invalid rows are zeroed; the first row of every pk_anchor block is kept).
func deriveViews(plain []plainBallot, validity []bool, eid *big.Int, numChoices int) ([]FilteredBallot, []SortedByVoterBallot, []frontend.Variable) {
	numBallots := len(plain)
	filtered := make([]FilteredBallot, numBallots)
	for i, pb := range plain {
		filtered[i].Choice = make([]frontend.Variable, numChoices)
		if validity[i] {
			filtered[i].Eid = eid
			filtered[i].PkAnchorX = pb.PkAx
			filtered[i].PkAnchorY = pb.PkAy
			filtered[i].PkVoteX = pb.PkVx
			filtered[i].PkVoteY = pb.PkVy
			filtered[i].PosReg = pb.PosReg
			filtered[i].Weight = pb.Weight
			for j := 0; j < numChoices; j++ {
				filtered[i].Choice[j] = pb.Choices[j]
			}
			filtered[i].B3_RX = pb.B3_Rx
			filtered[i].B3_RY = pb.B3_Ry
			filtered[i].B3_S = pb.B3_S
			filtered[i].B4_RX = pb.B4_Rx
			filtered[i].B4_RY = pb.B4_Ry
			filtered[i].B4_S = pb.B4_S
		} else {
			zero := big.NewInt(0)
			filtered[i].Eid = zero
			filtered[i].PkAnchorX = zero
			filtered[i].PkAnchorY = zero
			filtered[i].PkVoteX = zero
			filtered[i].PkVoteY = zero
			filtered[i].PosReg = zero
			filtered[i].Weight = zero
			for j := 0; j < numChoices; j++ {
				filtered[i].Choice[j] = zero
			}
			filtered[i].B3_RX = zero
			filtered[i].B3_RY = zero
			filtered[i].B3_S = zero
			filtered[i].B4_RX = zero
			filtered[i].B4_RY = zero
			filtered[i].B4_S = zero
		}
	}

	sorted := make([]SortedByVoterBallot, numBallots)
	for i := 0; i < numBallots; i++ {
		sorted[i] = SortedByVoterBallot{
			Eid:       filtered[i].Eid,
			PkAnchorX: filtered[i].PkAnchorX,
			PkAnchorY: filtered[i].PkAnchorY,
			PkVoteX:   filtered[i].PkVoteX,
			PkVoteY:   filtered[i].PkVoteY,
			PosReg:    filtered[i].PosReg,
			Weight:    filtered[i].Weight,
			Choice:    append([]frontend.Variable{}, filtered[i].Choice...),
			B3_RX:     filtered[i].B3_RX,
			B3_RY:     filtered[i].B3_RY,
			B3_S:      filtered[i].B3_S,
			B4_RX:     filtered[i].B4_RX,
			B4_RY:     filtered[i].B4_RY,
			B4_S:      filtered[i].B4_S,
		}
	}
	sort.Slice(sorted, func(i, j int) bool {
		ix := sorted[i].PkAnchorX.(*big.Int)
		jx := sorted[j].PkAnchorX.(*big.Int)
		if c := ix.Cmp(jx); c != 0 {
			return c < 0
		}
		iy := sorted[i].PkAnchorY.(*big.Int)
		jy := sorted[j].PkAnchorY.(*big.Int)
		if c := iy.Cmp(jy); c != 0 {
			return c < 0
		}
		ip := sorted[i].PosReg.(*big.Int)
		jp := sorted[j].PosReg.(*big.Int)
		return ip.Cmp(jp) < 0
	})

	tally := make([]frontend.Variable, numChoices)
	for j := 0; j < numChoices; j++ {
		tally[j] = big.NewInt(0)
	}
	for i := 0; i < numBallots; i++ {
		keep := i == 0
		if i > 0 {
			xPrev := sorted[i-1].PkAnchorX.(*big.Int)
			yPrev := sorted[i-1].PkAnchorY.(*big.Int)
			xCurr := sorted[i].PkAnchorX.(*big.Int)
			yCurr := sorted[i].PkAnchorY.(*big.Int)
			keep = xCurr.Cmp(xPrev) != 0 || yCurr.Cmp(yPrev) != 0
		}
		if keep {
			for j := 0; j < numChoices; j++ {
				cj := sorted[i].Choice[j].(*big.Int)
				tally[j] = new(big.Int).Add(tally[j].(*big.Int), cj)
			}
		}
	}
	return filtered, sorted, tally
}

// assignmentFor returns a full assignment in which the ballots are treated
// according to the given validity flags (views and tally are recomputed).
func (sb *scenarioBuild) assignmentFor(validity []bool) CastIronCircuit {
	filtered, sorted, tally := deriveViews(sb.plain, validity, sb.eid, sb.numChoices)
	a := sb.assignment
	a.ValidityBits = boolsToVars(validity)
	a.FilteredBallots = filtered
	a.SortedByVoterBallots = sorted
	a.Tally = tally
	a.RecordOpenings = append([]RecordOpening{}, sb.openings...)
	return a
}

// buildScenario generates keys, the voter roll, the registrations with their
// CTC openings and the (lazily built, numBlockchainLeaves-entry) record tree
// whose root is the public RegistrationRoot, the ballots, and the full witness.
func buildScenario(t testing.TB, scen JSONScenario, numBlockchainLeaves int) *scenarioBuild {
	t.Helper()
	if scen.NumChoices <= 0 {
		t.Fatal("num_choices must be > 0")
	}

	eid := big.NewInt(int64(scen.ElectionID))
	numChoices := scen.NumChoices

	// ElGamal params
	elgSk, elgG, elgH := elgamalKeygen()

	// per-voter EdDSA keys
	type voterKeys struct {
		anchorSk *eddsa.PrivateKey
		anchorPk *eddsa.PublicKey
		voteSk   *eddsa.PrivateKey
		votePk   *eddsa.PublicKey
		weight   *big.Int
	}
	allVoters := make([]voterKeys, len(scen.Voters))
	for i, v := range scen.Voters {
		anchorSk, _ := eddsa.GenerateKey(rand.Reader)
		anchorPk := anchorSk.Public().(*eddsa.PublicKey)
		voteSk, _ := eddsa.GenerateKey(rand.Reader)
		votePk := voteSk.Public().(*eddsa.PublicKey)
		allVoters[i] = voterKeys{
			anchorSk: anchorSk,
			anchorPk: anchorPk,
			voteSk:   voteSk,
			votePk:   votePk,
			weight:   big.NewInt(int64(v.Weight)),
		}
	}

	// voter-roll Merkle (custom, to match circuit)
	voterLeaves := make([]*big.Int, len(scen.Voters))
	for i := range scen.Voters {
		voterLeaves[i] = poseidonHashFields(
			fieldToBigInt(allVoters[i].anchorPk.A.X),
			fieldToBigInt(allVoters[i].anchorPk.A.Y),
			big.NewInt(int64(scen.Voters[i].Weight)),
		)
	}
	voterRootBI, voterProofs := buildUnaryMerkleTest(voterLeaves)

	// registrations: B3 = σreg signatures and their CTC openings.  Registration
	// pos is the transaction at position pos of the record; its ECDSA
	// r-component rσ = x([c]G) with c = H(σreg ∥ r) (voteropening's relation),
	// and the record tree leaf is Poseidon(1, pos, rσ_hi, rσ_lo).
	type regEntry struct {
		VoterIdx int
		RegIdx   int
		B3       struct {
			Rx *big.Int
			Ry *big.Int
			S  *big.Int
		}
		R    *big.Int // commitment randomness (goes into the ballot, encrypted)
		Rsig *big.Int // record entry
	}
	var regEntries []regEntry
	for vi, v := range scen.Voters {
		for ri := range v.Registrations {
			msgB3 := poseidonHashBytes(
				eid,
				fieldToBigInt(allVoters[vi].votePk.A.X),
				fieldToBigInt(allVoters[vi].votePk.A.Y),
				fieldToBigInt(allVoters[vi].anchorPk.A.X),
				fieldToBigInt(allVoters[vi].anchorPk.A.Y),
			)
			B3_sig, _ := allVoters[vi].anchorSk.Sign(msgB3, hash.POSEIDON2_BN254.New())
			var B3_R tedwardsCrypto.PointAffine
			B3_R.SetBytes(B3_sig[:32])
			B3_S := new(big.Int).SetBytes(B3_sig[32:])

			var e regEntry
			e.VoterIdx = vi
			e.RegIdx = ri
			e.B3.Rx = fieldToBigInt(B3_R.X)
			e.B3.Ry = fieldToBigInt(B3_R.Y)
			e.B3.S = B3_S
			for {
				r := shared.RandomScalar()
				o, err := voteropening.ComputeOpening(e.B3.Rx, e.B3.Ry, e.B3.S, r)
				if err == nil {
					e.R, e.Rsig = r, o.Rsig
					break
				}
			}
			regEntries = append(regEntries, e)
		}
	}
	regLeaves := make([]*big.Int, len(regEntries))
	for pos, re := range regEntries {
		hi, lo := new(big.Int).Rsh(re.Rsig, 128), new(big.Int).And(re.Rsig, new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1)))
		regLeaves[pos] = shared.EntryCommitmentNative(big.NewInt(int64(pos)), hi, lo)
	}
	if numBlockchainLeaves < len(regLeaves) {
		t.Fatalf("numBlockchainLeaves (%d) must be >= registrations (%d)", numBlockchainLeaves, len(regLeaves))
	}
	regRootBI, regProofs := buildPlainMerkleTest(regLeaves, numBlockchainLeaves)
	recordDepth := shared.MerkleHeight(numBlockchainLeaves)

	// ballots
	var allBallotCts []BallotCiphertexts
	var validity []bool
	var plain []plainBallot
	var openings []RecordOpening

	for regPos, re := range regEntries {
		vIdx := re.VoterIdx
		v := scen.Voters[vIdx]
		vkeys := allVoters[vIdx]
		jsonReg := v.Registrations[re.RegIdx]
		pkAx := fieldToBigInt(vkeys.anchorPk.A.X)
		pkAy := fieldToBigInt(vkeys.anchorPk.A.Y)
		pkVx := fieldToBigInt(vkeys.votePk.A.X)
		pkVy := fieldToBigInt(vkeys.votePk.A.Y)
		posReg := big.NewInt(int64(regPos))

		for _, jb := range jsonReg.Ballots {
			// choice vector (one-hot * weight)
			choices := make([]*big.Int, numChoices)
			for i := range choices {
				if i == jb.ChoiceIndex {
					choices[i] = big.NewInt(int64(v.Weight))
				} else {
					choices[i] = big.NewInt(0)
				}
			}

			// B4 message (must match circuit buildMsgB4)
			msgB4Fields := []*big.Int{eid, voterRootBI, regRootBI, pkAx, pkAy, pkVx, pkVy, posReg}
			msgB4Fields = append(msgB4Fields, choices...)
			msgB4Fields = append(msgB4Fields, vkeys.weight, re.B3.Rx, re.B3.Ry, re.B3.S)
			msgB4 := poseidonHashBytes(msgB4Fields...)

			B4_sig, _ := vkeys.voteSk.Sign(msgB4, hash.POSEIDON2_BN254.New())
			var B4_R tedwardsCrypto.PointAffine
			B4_R.SetBytes(B4_sig[:32])
			B4_S := new(big.Int).SetBytes(B4_sig[32:])

			// maybe corrupt sigs
			B3_Rx, B3_Ry, B3_S := re.B3.Rx, re.B3.Ry, re.B3.S
			if !jb.GoodAnchorSig {
				B3_Rx, B3_Ry, B3_S = randomScalar(), randomScalar(), randomScalar()
			}
			B4_Rx := fieldToBigInt(B4_R.X)
			B4_Ry := fieldToBigInt(B4_R.Y)
			B4s := B4_S
			if !jb.GoodVoteSig {
				B4_Rx, B4_Ry, B4s = randomScalar(), randomScalar(), randomScalar()
			}

			// ElGamal encryption (per-field)
			enc := func(m *big.Int) ElGamalCiphertext {
				c1, c2 := elgamalEncryptScalar(m, elgG, elgH)
				return ElGamalCiphertext{C1: c1, C2: c2}
			}
			ct := BallotCiphertexts{}
			ct.EidC = enc(eid)
			ct.PkAnchorX_C = enc(pkAx)
			ct.PkAnchorY_C = enc(pkAy)
			ct.PkVoteX_C = enc(pkVx)
			ct.PkVoteY_C = enc(pkVy)
			ct.ChoiceC = make([]ElGamalCiphertext, numChoices)
			for i := 0; i < numChoices; i++ {
				ct.ChoiceC[i] = enc(choices[i])
			}
			ct.B3_RX_C = enc(B3_Rx)
			ct.B3_RY_C = enc(B3_Ry)
			ct.B3_S_C = enc(B3_S)
			ct.B4_RX_C = enc(B4_Rx)
			ct.B4_RY_C = enc(B4_Ry)
			ct.B4_S_C = enc(B4s)

			// voter Merkle path (maybe bad)
			ct.PathWeightC = make([]ElGamalCiphertext, len(voterProofs[vIdx]))
			for i, node := range voterProofs[vIdx] {
				val := node
				if !jb.GoodVoterMerkle {
					val = randomScalar()
				}
				ct.PathWeightC[i] = enc(val)
			}
			ct.LeafIndexC = enc(big.NewInt(int64(vIdx)))
			ct.WeightC = enc(vkeys.weight)
			ct.PosRegC = enc(posReg)
			// commitment randomness (a bad registration carries randomness
			// that does not open the record entry)
			regRand := re.R
			if !jb.GoodRegMerkle {
				regRand = randomScalar()
			}
			ct.RegRandC = enc(regRand)
			allBallotCts = append(allBallotCts, ct)

			// tallier witness: the record entry and path at posReg
			hi, lo := new(big.Int).Rsh(re.Rsig, 128), new(big.Int).And(re.Rsig, new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1)))
			path := make([]frontend.Variable, recordDepth)
			for k := range path {
				path[k] = regProofs[regPos][k+1] // regProofs[..][0] is the leaf
			}
			openings = append(openings, RecordOpening{RsigHi: hi, RsigLo: lo, Path: path})

			validity = append(validity, jb.GoodAnchorSig && jb.GoodVoteSig && jb.GoodVoterMerkle && jb.GoodRegMerkle)
			cp := make([]*big.Int, len(choices))
			for i := range choices {
				cp[i] = new(big.Int).Set(choices[i])
			}
			plain = append(plain, plainBallot{
				PkAx: pkAx, PkAy: pkAy, PkVx: pkVx, PkVy: pkVy,
				PosReg: posReg, Choices: cp, Weight: vkeys.weight,
				B3_Rx: B3_Rx, B3_Ry: B3_Ry, B3_S: B3_S,
				B4_Rx: B4_Rx, B4_Ry: B4_Ry, B4_S: B4s,
			})
		}
	}

	numBallots := len(allBallotCts)
	if numBallots == 0 {
		t.Fatal("scenario produced 0 ballots")
	}

	sb := &scenarioBuild{
		numBallots:  numBallots,
		numChoices:  numChoices,
		eid:         eid,
		voterRootBI: voterRootBI,
		regRootBI:   regRootBI,
		plain:       plain,
		validity:    validity,
		openings:    openings,
		recordDepth: recordDepth,
	}
	sb.skeleton = NewSkeleton(numBallots, numChoices, len(allBallotCts[0].PathWeightC), recordDepth)
	sb.assignment = CastIronCircuit{
		ElectionID:       eid,
		VoterRollRoot:    voterRootBI,
		RegistrationRoot: regRootBI,
		ElGamalG:         elgG,
		ElGamalH:         elgH,
		BulletinBoard:    allBallotCts,
		ElGamalSk:        elgSk,
	}
	sb.assignment = sb.assignmentFor(validity)
	sb.expectedTally = sb.assignment.Tally
	return sb
}

/* ----------------------------- the actual test --------------------------- */

// runScenario runs the full scenario with the default simulatedBlockchainLeaves using Groth16.
func runScenario(t testing.TB, scen JSONScenario) (time.Duration, time.Duration, int, []frontend.Variable) {
	proofTimes, verifyTime, numBallots, expectedTally := runScenarioWithBlockchainLeavesProveRepeats(t, scen, simulatedBlockchainLeaves, 1, Groth16)
	return proofTimes[0], verifyTime, numBallots, expectedTally
}

// runScenarioWithBlockchainLeaves runs the full scenario with one prove using Groth16.
func runScenarioWithBlockchainLeaves(t testing.TB, scen JSONScenario, numBlockchainLeaves int) (time.Duration, time.Duration, int, []frontend.Variable) {
	proofTimes, verifyTime, numBallots, expectedTally := runScenarioWithBlockchainLeavesProveRepeats(t, scen, numBlockchainLeaves, 1, Groth16)
	return proofTimes[0], verifyTime, numBallots, expectedTally
}

// runScenarioWithBlockchainLeavesProveRepeats runs the full scenario and executes Prove numProveRepeats times
// (setup is done once). Returns all proof durations.
func runScenarioWithBlockchainLeavesProveRepeats(t testing.TB, scen JSONScenario, numBlockchainLeaves, numProveRepeats int, ps ProofSystem) ([]time.Duration, time.Duration, int, []frontend.Variable) {
	t.Helper()
	totalStart := time.Now()
	sb := buildScenario(t, scen, numBlockchainLeaves)
	numBallots := sb.numBallots

	phaseStart := time.Now()
	ccs := compileCircuit(t, sb.skeleton, ps)
	t.Logf("prep: circuit compile: %s", time.Since(phaseStart))

	witness, err := frontend.NewWitness(&sb.assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	pub, err := witness.Public()
	if err != nil {
		t.Fatal(err)
	}
	phaseStart = time.Now()

	proofTimes := make([]time.Duration, 0, numProveRepeats)
	var verifyTime time.Duration

	switch ps {
	case Plonk:
		keyName := circuitKeyName("plonk", sb.skeleton)
		plonkPk, plonkVk, loaded := loadPlonkKeys(t, keyName)
		if loaded {
			t.Logf("prep: setup (cached): %s", time.Since(phaseStart))
		} else {
			srs, srsLagrange, srsErr := unsafekzg.NewSRS(ccs)
			if srsErr != nil {
				t.Fatal(srsErr)
			}
			plonkPk, plonkVk, err = plonk.Setup(ccs, srs, srsLagrange)
			if err != nil {
				t.Fatal(err)
			}
			if err := savePlonkKeys(keyName, plonkPk, plonkVk); err != nil {
				t.Fatalf("save plonk keys: %v", err)
			}
			t.Logf("prep: setup: %s", time.Since(phaseStart))
		}
		t.Logf("prep: total before prove: %s", time.Since(totalStart))

		var lastProof plonk.Proof
		for i := 0; i < numProveRepeats; i++ {
			phaseStart = time.Now()
			lastProof, err = plonk.Prove(ccs, plonkPk, witness)
			if err != nil {
				fmt.Println("prove failed:", err)
				_ = os.WriteFile("prove_err.txt", []byte(err.Error()), 0644)
				t.Fatal(err)
			}
			proofTimes = append(proofTimes, time.Since(phaseStart))
		}
		startVerify := time.Now()
		if err := plonk.Verify(lastProof, plonkVk, pub); err != nil {
			t.Fatal("verify failed:", err)
		}
		verifyTime = time.Since(startVerify)

	default: // Groth16
		keyName := circuitKeyName("groth16", sb.skeleton)
		groth16Pk, groth16Vk, loaded := loadGroth16Keys(t, keyName)
		if loaded {
			t.Logf("prep: setup (cached): %s", time.Since(phaseStart))
		} else {
			groth16Pk, groth16Vk, err = groth16.Setup(ccs)
			if err != nil {
				t.Fatal(err)
			}
			if err := saveGroth16Keys(keyName, groth16Pk, groth16Vk); err != nil {
				t.Fatalf("save groth16 keys: %v", err)
			}
			t.Logf("prep: setup: %s", time.Since(phaseStart))
		}
		t.Logf("prep: total before prove: %s", time.Since(totalStart))

		var lastProof groth16.Proof
		for i := 0; i < numProveRepeats; i++ {
			phaseStart = time.Now()
			lastProof, err = groth16.Prove(ccs, groth16Pk, witness)
			if err != nil {
				fmt.Println("prove failed:", err)
				_ = os.WriteFile("prove_err.txt", []byte(err.Error()), 0644)
				t.Fatal(err)
			}
			proofTimes = append(proofTimes, time.Since(phaseStart))
		}
		startVerify := time.Now()
		if err := groth16.Verify(lastProof, groth16Vk, pub); err != nil {
			t.Fatal("verify failed:", err)
		}
		verifyTime = time.Since(startVerify)
	}

	return proofTimes, verifyTime, numBallots, sb.expectedTally
}

// circuitKeyName identifies the cached keys by everything that determines the
// compiled circuit: ballots, choices and voter-roll path length (the circuit no
// longer depends on the registration-tree size), plus the circuit version tag.
func circuitKeyName(system string, skeleton *CastIronCircuit) string {
	return fmt.Sprintf("%s_%s_%d_ballots_%d_choices_pw%d_rd%d", system, circuitKeyTag,
		len(skeleton.BulletinBoard), len(skeleton.Tally), len(skeleton.BulletinBoard[0].PathWeightC), len(skeleton.RecordOpenings[0].Path))
}

func keyPaths(base string) (string, string) {
	return filepath.Join("keys", base+"_pk.bin"), filepath.Join("keys", base+"_vk.bin")
}

func loadGroth16Keys(t testing.TB, keyName string) (groth16.ProvingKey, groth16.VerifyingKey, bool) {
	t.Helper()
	pkPath, vkPath := keyPaths(keyName)

	pkFile, err := os.Open(pkPath)
	if err != nil {
		return nil, nil, false
	}
	defer pkFile.Close()
	vkFile, err := os.Open(vkPath)
	if err != nil {
		return nil, nil, false
	}
	defer vkFile.Close()

	pk := groth16.NewProvingKey(ecc.BN254)
	if _, err := pk.ReadFrom(pkFile); err != nil {
		return nil, nil, false
	}
	vk := groth16.NewVerifyingKey(ecc.BN254)
	if _, err := vk.ReadFrom(vkFile); err != nil {
		return nil, nil, false
	}
	return pk, vk, true
}

func saveGroth16Keys(keyName string, pk groth16.ProvingKey, vk groth16.VerifyingKey) error {
	pkPath, vkPath := keyPaths(keyName)
	if err := os.MkdirAll(filepath.Dir(pkPath), 0o755); err != nil {
		return err
	}

	pkFile, err := os.Create(pkPath)
	if err != nil {
		return err
	}
	if _, err := pk.WriteTo(pkFile); err != nil {
		_ = pkFile.Close()
		return err
	}
	if err := pkFile.Close(); err != nil {
		return err
	}

	vkFile, err := os.Create(vkPath)
	if err != nil {
		return err
	}
	if _, err := vk.WriteTo(vkFile); err != nil {
		_ = vkFile.Close()
		return err
	}
	return vkFile.Close()
}

/* -------------------- PLONK key persistence -------------------- */

func loadPlonkKeys(t testing.TB, keyName string) (plonk.ProvingKey, plonk.VerifyingKey, bool) {
	t.Helper()
	pkPath, vkPath := keyPaths(keyName)

	pkFile, err := os.Open(pkPath)
	if err != nil {
		return nil, nil, false
	}
	defer pkFile.Close()
	vkFile, err := os.Open(vkPath)
	if err != nil {
		return nil, nil, false
	}
	defer vkFile.Close()

	pk := plonk.NewProvingKey(ecc.BN254)
	if _, err := pk.ReadFrom(pkFile); err != nil {
		return nil, nil, false
	}
	vk := plonk.NewVerifyingKey(ecc.BN254)
	if _, err := vk.ReadFrom(vkFile); err != nil {
		return nil, nil, false
	}
	return pk, vk, true
}

func savePlonkKeys(keyName string, pk plonk.ProvingKey, vk plonk.VerifyingKey) error {
	pkPath, vkPath := keyPaths(keyName)
	if err := os.MkdirAll(filepath.Dir(pkPath), 0o755); err != nil {
		return err
	}

	pkFile, err := os.Create(pkPath)
	if err != nil {
		return err
	}
	if _, err := pk.WriteTo(pkFile); err != nil {
		_ = pkFile.Close()
		return err
	}
	if err := pkFile.Close(); err != nil {
		return err
	}

	vkFile, err := os.Create(vkPath)
	if err != nil {
		return err
	}
	if _, err := vk.WriteTo(vkFile); err != nil {
		_ = vkFile.Close()
		return err
	}
	return vkFile.Close()
}

func TestCastIronFromJSON(t *testing.T) {
	var raw []byte
	var err error
	paths := []string{"testdata/castiron_scenario_large.json", "testdata/castiron_scenario.json"}
	for _, p := range paths {
		raw, err = os.ReadFile(p)
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Skip("no scenario file, skipping:", err)
	}

	var scen JSONScenario
	if err := json.Unmarshal(raw, &scen); err != nil {
		t.Fatal(err)
	}

	proofTime, verifyTime, numBallots, expectedTally := runScenario(t, scen)

	fmt.Printf("✅ JSON scenario proof verified with %d ballots\n", numBallots)
	fmt.Printf("Proof time: %s, verify time: %s\n", proofTime, verifyTime)
	for j := 0; j < len(expectedTally); j++ {
		fmt.Printf("Choice[%d] = %v\n", j, expectedTally[j])
	}
}
