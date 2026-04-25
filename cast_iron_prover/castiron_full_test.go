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
	if totalLeaves <= 0 {
		return big.NewInt(0), nil
	}
	if totalLeaves < len(leaves) {
		panic("totalLeaves must be >= number of provided leaves")
	}

	// build a complete binary tree with treeLeaves = next power of two >= totalLeaves
	treeLeaves := 1
	height := 0
	for treeLeaves < totalLeaves {
		treeLeaves <<= 1
		height++
	}

	type nodeKey struct {
		level int
		idx   int
	}

	leafValues := make(map[int]*big.Int, len(leaves))
	for idx, leaf := range leaves {
		leafValues[idx] = leaf
	}

	defaultNodes := make([]*big.Int, height+1)
	defaultNodes[0] = poseidonHashFields(big.NewInt(0), big.NewInt(0), big.NewInt(0))
	for lvl := 1; lvl <= height; lvl++ {
		defaultNodes[lvl] = poseidonHashFields(defaultNodes[lvl-1], defaultNodes[lvl-1])
	}

	cache := make(map[nodeKey]*big.Int)
	var nodeValue func(level, idx int) *big.Int
	nodeValue = func(level, idx int) *big.Int {
		key := nodeKey{level: level, idx: idx}
		if val, ok := cache[key]; ok {
			return val
		}

		var out *big.Int
		if level == 0 {
			if leaf, ok := leafValues[idx]; ok {
				out = leaf
			} else if idx < totalLeaves {
				// deterministic filler leaf inside the logical tree
				out = poseidonHashFields(big.NewInt(0), big.NewInt(int64(idx)), big.NewInt(0))
			} else {
				out = defaultNodes[0]
			}
		} else {
			size := 1 << level
			start := idx * size
			if start >= len(leaves) {
				out = defaultNodes[level]
			} else {
				left := nodeValue(level-1, idx*2)
				right := nodeValue(level-1, idx*2+1)
				out = poseidonHashFields(left, right)
			}
		}

		cache[key] = out
		return out
	}

	root := nodeValue(height, 0)

	proofs := make([][]*big.Int, len(leaves))
	for i := range leaves {
		idx := i
		path := make([]*big.Int, height+1)
		path[0] = nodeValue(0, idx)
		for lvl := 0; lvl < height; lvl++ {
			sibIdx := idx ^ 1
			path[lvl+1] = nodeValue(lvl, sibIdx)
			idx >>= 1
		}
		proofs[i] = path
	}

	return root, proofs
}

/* ----------------------------- the actual test --------------------------- */

func compileCircuit(t testing.TB, scen JSONScenario, ballotExample BallotCiphertexts, pathRegLen, pathWeightLen int, numChoices int, ps ProofSystem) constraint.ConstraintSystem {
	t.Helper()
	var circuit CastIronCircuit
	circuit.BulletinBoard = make([]BallotCiphertexts, len(scen.Voters)*scen.Voters[0].NumRegistrations*scen.Voters[0].Registrations[0].NumBallots)
	for i := range circuit.BulletinBoard {
		circuit.BulletinBoard[i].ChoiceC = make([]ElGamalCiphertext, numChoices)
		circuit.BulletinBoard[i].PathRegC = make([]ElGamalCiphertext, pathRegLen)
		circuit.BulletinBoard[i].PathWeightC = make([]ElGamalCiphertext, pathWeightLen)
	}
	circuit.ValidityBits = make([]frontend.Variable, len(circuit.BulletinBoard))
	circuit.FilteredBallots = make([]FilteredBallot, len(circuit.BulletinBoard))
	circuit.SortedByVoterBallots = make([]SortedByVoterBallot, len(circuit.BulletinBoard))
	for i := 0; i < len(circuit.BulletinBoard); i++ {
		circuit.FilteredBallots[i].Choice = make([]frontend.Variable, numChoices)
		circuit.SortedByVoterBallots[i].Choice = make([]frontend.Variable, numChoices)
	}
	circuit.Tally = make([]frontend.Variable, numChoices)

	var builder frontend.NewBuilder = r1cs.NewBuilder
	if ps == Plonk {
		builder = scs.NewBuilder
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, &circuit)
	if err != nil {
		t.Fatal(err)
	}
	return ccs
}

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
	if scen.NumChoices <= 0 {
		t.Fatal("num_choices must be > 0")
	}

	eid := big.NewInt(int64(scen.ElectionID))
	numChoices := scen.NumChoices

	totalStart := time.Now()
	phaseStart := time.Now()
	// 2) ElGamal params
	elgSk, elgG, elgH := elgamalKeygen()
	phaseStart = time.Now()

	// 3) per-voter EdDSA keys
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
	phaseStart = time.Now()

	// 4) build voter-roll Merkle (custom, to match circuit)
	voterLeaves := make([]*big.Int, len(scen.Voters))
	for i := range scen.Voters {
		voterLeaves[i] = poseidonHashFields(
			fieldToBigInt(allVoters[i].anchorPk.A.X),
			fieldToBigInt(allVoters[i].anchorPk.A.Y),
			big.NewInt(int64(scen.Voters[i].Weight)),
		)
	}
	voterRootBI, voterProofs := buildUnaryMerkleTest(voterLeaves)
	phaseStart = time.Now()

	// 5) flatten registrations and build registration Merkle (custom)
	type regEntry struct {
		VoterIdx int
		RegIdx   int
		B3       struct {
			Rx *big.Int
			Ry *big.Int
			S  *big.Int
		}
	}

	var regEntries []regEntry
	for vi, v := range scen.Voters {
		for ri := range v.Registrations {
			// B3 message = Poseidon(eid, pkVote, pkAnchor)
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
			regEntries = append(regEntries, e)
		}
	}

	// build leaves: leaf = Poseidon(0, pos, H(B3)) with pos = index in regEntries
	regLeaves := make([]*big.Int, len(regEntries))
	for pos, re := range regEntries {
		hB3 := poseidonHashFields(re.B3.Rx, re.B3.Ry, re.B3.S)
		regLeaves[pos] = poseidonHashFields(big.NewInt(0), big.NewInt(int64(pos)), hB3)
	}
	if numBlockchainLeaves < len(regLeaves) {
		t.Fatalf("numBlockchainLeaves (%d) must be >= registrations (%d)", numBlockchainLeaves, len(regLeaves))
	}
	regRootBI, regProofs := buildPlainMerkleTest(regLeaves, numBlockchainLeaves)
	phaseStart = time.Now()

	// 6) build ballots (flatten)
	var allBallotCts []BallotCiphertexts
	var ballotValidityFlags []bool
	var plainBallots []struct {
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

	for regPos, re := range regEntries {
		vIdx := re.VoterIdx
		v := scen.Voters[vIdx]
		vkeys := allVoters[vIdx]
		jsonReg := v.Registrations[re.RegIdx]

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
			msgB4Fields := []*big.Int{
				eid,
				voterRootBI,
				regRootBI,
				fieldToBigInt(vkeys.anchorPk.A.X),
				fieldToBigInt(vkeys.anchorPk.A.Y),
				fieldToBigInt(vkeys.votePk.A.X),
				fieldToBigInt(vkeys.votePk.A.Y),
				big.NewInt(int64(regPos)),
			}
			for _, c := range choices {
				msgB4Fields = append(msgB4Fields, c)
			}
			msgB4Fields = append(msgB4Fields, vkeys.weight, re.B3.Rx, re.B3.Ry, re.B3.S)
			msgB4 := poseidonHashBytes(msgB4Fields...)

			B4_sig, _ := vkeys.voteSk.Sign(msgB4, hash.POSEIDON2_BN254.New())
			var B4_R tedwardsCrypto.PointAffine
			B4_R.SetBytes(B4_sig[:32])
			B4_S := new(big.Int).SetBytes(B4_sig[32:])

			// maybe corrupt sigs
			B3_Rx := re.B3.Rx
			B3_Ry := re.B3.Ry
			B3_S := re.B3.S
			if !jb.GoodAnchorSig {
				B3_Rx = randomScalar()
				B3_Ry = randomScalar()
				B3_S = randomScalar()
			}
			B4_Rx := fieldToBigInt(B4_R.X)
			B4_Ry := fieldToBigInt(B4_R.Y)
			B4s := B4_S
			if !jb.GoodVoteSig {
				B4_Rx = randomScalar()
				B4_Ry = randomScalar()
				B4s = randomScalar()
			}

			// ElGamal encryption (per-field)
			ct := BallotCiphertexts{}
			c1, c2 := elgamalEncryptScalar(eid, elgG, elgH)
			ct.EidC = ElGamalCiphertext{C1: c1, C2: c2}
			c1, c2 = elgamalEncryptScalar(fieldToBigInt(vkeys.anchorPk.A.X), elgG, elgH)
			ct.PkAnchorX_C = ElGamalCiphertext{C1: c1, C2: c2}
			c1, c2 = elgamalEncryptScalar(fieldToBigInt(vkeys.anchorPk.A.Y), elgG, elgH)
			ct.PkAnchorY_C = ElGamalCiphertext{C1: c1, C2: c2}
			c1, c2 = elgamalEncryptScalar(fieldToBigInt(vkeys.votePk.A.X), elgG, elgH)
			ct.PkVoteX_C = ElGamalCiphertext{C1: c1, C2: c2}
			c1, c2 = elgamalEncryptScalar(fieldToBigInt(vkeys.votePk.A.Y), elgG, elgH)
			ct.PkVoteY_C = ElGamalCiphertext{C1: c1, C2: c2}
			ct.ChoiceC = make([]ElGamalCiphertext, numChoices)
			for i := 0; i < numChoices; i++ {
				c1, c2 = elgamalEncryptScalar(choices[i], elgG, elgH)
				ct.ChoiceC[i] = ElGamalCiphertext{C1: c1, C2: c2}
			}
			c1, c2 = elgamalEncryptScalar(B3_Rx, elgG, elgH)
			ct.B3_RX_C = ElGamalCiphertext{C1: c1, C2: c2}
			c1, c2 = elgamalEncryptScalar(B3_Ry, elgG, elgH)
			ct.B3_RY_C = ElGamalCiphertext{C1: c1, C2: c2}
			c1, c2 = elgamalEncryptScalar(B3_S, elgG, elgH)
			ct.B3_S_C = ElGamalCiphertext{C1: c1, C2: c2}
			c1, c2 = elgamalEncryptScalar(B4_Rx, elgG, elgH)
			ct.B4_RX_C = ElGamalCiphertext{C1: c1, C2: c2}
			c1, c2 = elgamalEncryptScalar(B4_Ry, elgG, elgH)
			ct.B4_RY_C = ElGamalCiphertext{C1: c1, C2: c2}
			c1, c2 = elgamalEncryptScalar(B4s, elgG, elgH)
			ct.B4_S_C = ElGamalCiphertext{C1: c1, C2: c2}

			// voter Merkle path (maybe bad)
			ct.PathWeightC = make([]ElGamalCiphertext, len(voterProofs[vIdx]))
			for i, node := range voterProofs[vIdx] {
				val := node
				if !jb.GoodVoterMerkle {
					val = randomScalar()
				}
				c1, c2 = elgamalEncryptScalar(val, elgG, elgH)
				ct.PathWeightC[i] = ElGamalCiphertext{C1: c1, C2: c2}
			}
			c1, c2 = elgamalEncryptScalar(big.NewInt(int64(vIdx)), elgG, elgH)
			ct.LeafIndexC = ElGamalCiphertext{C1: c1, C2: c2}
			c1, c2 = elgamalEncryptScalar(vkeys.weight, elgG, elgH)
			ct.WeightC = ElGamalCiphertext{C1: c1, C2: c2}

			// registration Merkle path (maybe bad)
			ct.PathRegC = make([]ElGamalCiphertext, len(regProofs[regPos]))
			for i, node := range regProofs[regPos] {
				val := node
				if !jb.GoodRegMerkle {
					val = randomScalar()
				}
				c1, c2 = elgamalEncryptScalar(val, elgG, elgH)
				ct.PathRegC[i] = ElGamalCiphertext{C1: c1, C2: c2}
			}
			c1, c2 = elgamalEncryptScalar(big.NewInt(int64(regPos)), elgG, elgH)
			ct.PosRegC = ElGamalCiphertext{C1: c1, C2: c2}

			allBallotCts = append(allBallotCts, ct)

			isValid := jb.GoodAnchorSig && jb.GoodVoteSig && jb.GoodVoterMerkle && jb.GoodRegMerkle
			ballotValidityFlags = append(ballotValidityFlags, isValid)

			plainBallots = append(plainBallots, struct {
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
			}{
				PkAx:   fieldToBigInt(vkeys.anchorPk.A.X),
				PkAy:   fieldToBigInt(vkeys.anchorPk.A.Y),
				PkVx:   fieldToBigInt(vkeys.votePk.A.X),
				PkVy:   fieldToBigInt(vkeys.votePk.A.Y),
				PosReg: big.NewInt(int64(regPos)),
				Choices: func() []*big.Int {
					cp := make([]*big.Int, len(choices))
					for i := range choices {
						cp[i] = new(big.Int).Set(choices[i])
					}
					return cp
				}(),
				Weight: vkeys.weight,
				B3_Rx:  B3_Rx,
				B3_Ry:  B3_Ry,
				B3_S:   B3_S,
				B4_Rx:  B4_Rx,
				B4_Ry:  B4_Ry,
				B4_S:   B4s,
			})
		}
	}
	phaseStart = time.Now()

	numBallots := len(allBallotCts)
	if numBallots == 0 {
		t.Fatal("scenario produced 0 ballots")
	}

	// 6.1 filtered (A2)
	maskedFiltered := make([]FilteredBallot, numBallots)
	for i, pb := range plainBallots {
		if ballotValidityFlags[i] {
			maskedFiltered[i].Eid = eid
			maskedFiltered[i].PkAnchorX = pb.PkAx
			maskedFiltered[i].PkAnchorY = pb.PkAy
			maskedFiltered[i].PkVoteX = pb.PkVx
			maskedFiltered[i].PkVoteY = pb.PkVy
			maskedFiltered[i].PosReg = pb.PosReg
			maskedFiltered[i].Weight = pb.Weight
			maskedFiltered[i].Choice = make([]frontend.Variable, numChoices)
			for j := 0; j < numChoices; j++ {
				maskedFiltered[i].Choice[j] = pb.Choices[j]
			}
			maskedFiltered[i].B3_RX = pb.B3_Rx
			maskedFiltered[i].B3_RY = pb.B3_Ry
			maskedFiltered[i].B3_S = pb.B3_S
			maskedFiltered[i].B4_RX = pb.B4_Rx
			maskedFiltered[i].B4_RY = pb.B4_Ry
			maskedFiltered[i].B4_S = pb.B4_S
		} else {
			maskedFiltered[i].Eid = big.NewInt(0)
			maskedFiltered[i].PkAnchorX = big.NewInt(0)
			maskedFiltered[i].PkAnchorY = big.NewInt(0)
			maskedFiltered[i].PkVoteX = big.NewInt(0)
			maskedFiltered[i].PkVoteY = big.NewInt(0)
			maskedFiltered[i].PosReg = big.NewInt(0)
			maskedFiltered[i].Weight = big.NewInt(0)
			maskedFiltered[i].Choice = make([]frontend.Variable, numChoices)
			for j := 0; j < numChoices; j++ {
				maskedFiltered[i].Choice[j] = big.NewInt(0)
			}
			maskedFiltered[i].B3_RX = big.NewInt(0)
			maskedFiltered[i].B3_RY = big.NewInt(0)
			maskedFiltered[i].B3_S = big.NewInt(0)
			maskedFiltered[i].B4_RX = big.NewInt(0)
			maskedFiltered[i].B4_RY = big.NewInt(0)
			maskedFiltered[i].B4_S = big.NewInt(0)
		}
	}
	phaseStart = time.Now()

	// 6.2 sorted view A★
	sortedView := make([]SortedByVoterBallot, numBallots)
	for i := 0; i < numBallots; i++ {
		sortedView[i] = SortedByVoterBallot{
			Eid:       maskedFiltered[i].Eid,
			PkAnchorX: maskedFiltered[i].PkAnchorX,
			PkAnchorY: maskedFiltered[i].PkAnchorY,
			PkVoteX:   maskedFiltered[i].PkVoteX,
			PkVoteY:   maskedFiltered[i].PkVoteY,
			PosReg:    maskedFiltered[i].PosReg,
			Weight:    maskedFiltered[i].Weight,
			Choice:    append([]frontend.Variable{}, maskedFiltered[i].Choice...),
			B3_RX:     maskedFiltered[i].B3_RX,
			B3_RY:     maskedFiltered[i].B3_RY,
			B3_S:      maskedFiltered[i].B3_S,
			B4_RX:     maskedFiltered[i].B4_RX,
			B4_RY:     maskedFiltered[i].B4_RY,
			B4_S:      maskedFiltered[i].B4_S,
		}
	}
	sort.Slice(sortedView, func(i, j int) bool {
		ix := sortedView[i].PkAnchorX.(*big.Int)
		jx := sortedView[j].PkAnchorX.(*big.Int)
		if ix.Cmp(jx) < 0 {
			return true
		}
		if ix.Cmp(jx) > 0 {
			return false
		}
		iy := sortedView[i].PkAnchorY.(*big.Int)
		jy := sortedView[j].PkAnchorY.(*big.Int)
		if iy.Cmp(jy) < 0 {
			return true
		}
		if iy.Cmp(jy) > 0 {
			return false
		}
		ip := sortedView[i].PosReg.(*big.Int)
		jp := sortedView[j].PosReg.(*big.Int)
		return ip.Cmp(jp) <= 0
	})
	phaseStart = time.Now()

	// 6.3 tally
	expectedTally := make([]frontend.Variable, numChoices)
	for j := 0; j < numChoices; j++ {
		expectedTally[j] = big.NewInt(0)
	}

	for i := 0; i < numBallots; i++ {
		keep := false
		if i == 0 {
			// very first row always starts a new pk block
			keep = true
		} else {
			// compare with previous row (i-1)
			xPrev := sortedView[i-1].PkAnchorX.(*big.Int)
			yPrev := sortedView[i-1].PkAnchorY.(*big.Int)
			xCurr := sortedView[i].PkAnchorX.(*big.Int)
			yCurr := sortedView[i].PkAnchorY.(*big.Int)

			// start of a new pk block?
			pkChanges := xCurr.Cmp(xPrev) != 0 || yCurr.Cmp(yPrev) != 0
			if pkChanges {
				keep = true
			}
		}

		if keep {
			for j := 0; j < numChoices; j++ {
				cj := sortedView[i].Choice[j].(*big.Int)
				cur := expectedTally[j].(*big.Int)
				expectedTally[j] = new(big.Int).Add(cur, cj)
			}
		}
	}
	phaseStart = time.Now()

	// secret validity bits for witness
	validity := make([]frontend.Variable, numBallots)
	for i := 0; i < numBallots; i++ {
		if ballotValidityFlags[i] {
			validity[i] = 1
		} else {
			validity[i] = 0
		}
	}
	phaseStart = time.Now()

	// 7) circuit skeleton
	var circuit CastIronCircuit
	circuit.BulletinBoard = make([]BallotCiphertexts, numBallots)
	circuit.ValidityBits = make([]frontend.Variable, numBallots)
	circuit.FilteredBallots = make([]FilteredBallot, numBallots)
	circuit.SortedByVoterBallots = make([]SortedByVoterBallot, numBallots)
	circuit.Tally = make([]frontend.Variable, numChoices)

	for i := 0; i < numBallots; i++ {
		circuit.BulletinBoard[i].ChoiceC = make([]ElGamalCiphertext, numChoices)
		circuit.BulletinBoard[i].PathRegC = make([]ElGamalCiphertext, len(allBallotCts[i].PathRegC))
		circuit.BulletinBoard[i].PathWeightC = make([]ElGamalCiphertext, len(allBallotCts[i].PathWeightC))
		circuit.FilteredBallots[i].Choice = make([]frontend.Variable, numChoices)
		circuit.SortedByVoterBallots[i].Choice = make([]frontend.Variable, numChoices)
	}
	phaseStart = time.Now()

	ccs := compileCircuit(t, scen, allBallotCts[0], len(allBallotCts[0].PathRegC), len(allBallotCts[0].PathWeightC), numChoices, ps)
	t.Logf("prep: circuit compile: %s", time.Since(phaseStart))
	phaseStart = time.Now()

	// 8) witness
	assignment := CastIronCircuit{
		ElectionID:           eid,
		VoterRollRoot:        voterRootBI,
		RegistrationRoot:     regRootBI,
		BulletinBoard:        allBallotCts,
		ElGamalG:             elgG,
		ElGamalH:             elgH,
		ElGamalSk:            elgSk,
		ValidityBits:         validity,
		FilteredBallots:      maskedFiltered,
		SortedByVoterBallots: sortedView,
		Tally:                expectedTally,
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	phaseStart = time.Now()
	pub, err := witness.Public()
	if err != nil {
		t.Fatal(err)
	}
	phaseStart = time.Now()

	proofTimes := make([]time.Duration, 0, numProveRepeats)
	var verifyTime time.Duration

	switch ps {
	case Plonk:
		plonkPk, plonkVk, loaded := loadPlonkKeys(t, numBallots, numBlockchainLeaves)
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
			if err := savePlonkKeys(numBallots, numBlockchainLeaves, plonkPk, plonkVk); err != nil {
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
		groth16Pk, groth16Vk, loaded := loadGroth16Keys(t, numBallots, numBlockchainLeaves)
		if loaded {
			t.Logf("prep: setup (cached): %s", time.Since(phaseStart))
		} else {
			groth16Pk, groth16Vk, err = groth16.Setup(ccs)
			if err != nil {
				t.Fatal(err)
			}
			if err := saveGroth16Keys(numBallots, numBlockchainLeaves, groth16Pk, groth16Vk); err != nil {
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

	return proofTimes, verifyTime, numBallots, expectedTally
}

func groth16KeyPaths(numBallots, numBlockchainLeaves int) (string, string) {
	base := fmt.Sprintf("groth16_%d_ballots_%d_leaves", numBallots, numBlockchainLeaves)
	return filepath.Join("keys", base+"_pk.bin"), filepath.Join("keys", base+"_vk.bin")
}

func loadGroth16Keys(t testing.TB, numBallots, numBlockchainLeaves int) (groth16.ProvingKey, groth16.VerifyingKey, bool) {
	t.Helper()
	pkPath, vkPath := groth16KeyPaths(numBallots, numBlockchainLeaves)

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

func saveGroth16Keys(numBallots, numBlockchainLeaves int, pk groth16.ProvingKey, vk groth16.VerifyingKey) error {
	pkPath, vkPath := groth16KeyPaths(numBallots, numBlockchainLeaves)
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

func plonkKeyPaths(numBallots, numBlockchainLeaves int) (string, string) {
	base := fmt.Sprintf("plonk_%d_ballots_%d_leaves", numBallots, numBlockchainLeaves)
	return filepath.Join("keys", base+"_pk.bin"), filepath.Join("keys", base+"_vk.bin")
}

func loadPlonkKeys(t testing.TB, numBallots, numBlockchainLeaves int) (plonk.ProvingKey, plonk.VerifyingKey, bool) {
	t.Helper()
	pkPath, vkPath := plonkKeyPaths(numBallots, numBlockchainLeaves)

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

func savePlonkKeys(numBallots, numBlockchainLeaves int, pk plonk.ProvingKey, vk plonk.VerifyingKey) error {
	pkPath, vkPath := plonkKeyPaths(numBallots, numBlockchainLeaves)
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
