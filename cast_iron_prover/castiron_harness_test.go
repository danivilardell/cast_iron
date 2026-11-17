package castiron

// Test harness: builds elections (keys, weight tree, covert registrations and
// the record tree, encrypted ballots), assembles the tallier's witness, and
// computes the expected result with a reference implementation of
// Deduplicate/Accumulate written from the paper's definition rather than from
// the circuit.

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	tedwards381 "github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards"
	eddsa381 "github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards/eddsa"
	tedwards254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	eddsa254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"

	"cast_iron/shared"
	"cast_iron/voteropening"
)

/* -------------------------------- EdDSA keys ------------------------------- */

// edKeys is an EdDSA key pair on the twisted Edwards curve of the proving
// field (Baby Jubjub for BN254, Jubjub for BLS12-381), with the public key as
// coordinates and a signer returning (R.x, R.y, S) — the form the circuit
// consumes.  Signatures hash with the circuit's Poseidon2 instance.
type edKeys struct {
	pkX, pkY *big.Int
	sign     func(msg *big.Int) [3]*big.Int
}

func newEdKeys() edKeys {
	msgBytes := func(m *big.Int) []byte { return m.FillBytes(make([]byte, 32)) }
	switch shared.Curve.ID {
	case ecc.BN254:
		sk, err := eddsa254.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		pk := sk.Public().(*eddsa254.PublicKey)
		return edKeys{
			pkX: pk.A.X.BigInt(new(big.Int)),
			pkY: pk.A.Y.BigInt(new(big.Int)),
			sign: func(msg *big.Int) [3]*big.Int {
				sig, err := sk.Sign(msgBytes(msg), shared.NewNativePoseidon())
				if err != nil {
					panic(err)
				}
				var R tedwards254.PointAffine
				if _, err := R.SetBytes(sig[:32]); err != nil {
					panic(err)
				}
				return [3]*big.Int{R.X.BigInt(new(big.Int)), R.Y.BigInt(new(big.Int)), new(big.Int).SetBytes(sig[32:])}
			},
		}
	case ecc.BLS12_381:
		sk, err := eddsa381.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		pk := sk.Public().(*eddsa381.PublicKey)
		return edKeys{
			pkX: pk.A.X.BigInt(new(big.Int)),
			pkY: pk.A.Y.BigInt(new(big.Int)),
			sign: func(msg *big.Int) [3]*big.Int {
				sig, err := sk.Sign(msgBytes(msg), shared.NewNativePoseidon())
				if err != nil {
					panic(err)
				}
				var R tedwards381.PointAffine
				if _, err := R.SetBytes(sig[:32]); err != nil {
					panic(err)
				}
				return [3]*big.Int{R.X.BigInt(new(big.Int)), R.Y.BigInt(new(big.Int)), new(big.Int).SetBytes(sig[32:])}
			},
		}
	}
	panic("unsupported curve " + shared.Curve.Name)
}

/* -------------------------------- weight tree ------------------------------ */

// buildWeightTree builds T_W over the leaves L_i = Poseidon(IC_i.pk, w_i) as
// voterRollBit folds it: level-0 nodes are Poseidon(L_i), a node without a
// right sibling is paired with itself.  It returns the root and every leaf's
// sibling path (leaf level first).
func buildWeightTree(leaves []*big.Int) (root *big.Int, paths [][]*big.Int) {
	level := make([]*big.Int, len(leaves))
	for i, l := range leaves {
		level[i] = shared.PoseidonMD(l)
	}
	paths = make([][]*big.Int, len(leaves))
	idx := make([]int, len(leaves))
	for i := range idx {
		idx[i] = i
	}
	for len(level) > 1 {
		sibling := func(i int) *big.Int {
			if i^1 < len(level) {
				return level[i^1]
			}
			return level[i]
		}
		for i := range paths {
			paths[i] = append(paths[i], sibling(idx[i]))
			idx[i] /= 2
		}
		next := make([]*big.Int, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			next = append(next, shared.PoseidonMD(level[i], sibling(i)))
		}
		level = next
	}
	return level[0], paths
}

/* --------------------------------- election -------------------------------- */

type voter struct {
	anchor edKeys // inalienable credential IC
	weight *big.Int
}

// registration is one covert self-registration (paper Section 5.1): a fresh
// voting credential bound to the voter's IC by σreg and committed to with a
// CTC at record position pos.
type registration struct {
	voter int
	vote  edKeys
	sig   [3]*big.Int // σreg
	r     *big.Int    // commitment randomness
	pos   uint64      // t_reg
}

// plainBallot is the cleartext (B1, B2, σB) of one ballot.
type plainBallot struct {
	Eid        *big.Int
	PkVx, PkVy *big.Int    // pk_i
	PkAx, PkAy *big.Int    // IC.pk
	SigReg     [3]*big.Int // σreg
	RegRand    *big.Int    // r
	PosReg     *big.Int    // t_reg
	LeafIndex  *big.Int    // π_W
	Path       []*big.Int
	Weight     *big.Int
	Choices    []*big.Int // ν: one-hot · w
	BallotID   *big.Int   // id_B
	SigB       [3]*big.Int
}

type postedBallot struct {
	plain plainBallot
	valid bool // the validity bit Validate must compute
	ct    BallotCiphertexts
}

type election struct {
	t          testing.TB
	eid        *big.Int
	numChoices int
	sk, g, h   *big.Int // tallier's ElGamal key
	voters     []voter
	rollRoot   *big.Int
	rollPaths  [][]*big.Int
	record     *shared.RecordTree
	regs       []registration
	nextPos    uint64
	ballots    []postedBallot // BB′
}

// newElection sets up an election: tallier key, one IC per weight, the weight
// tree, and an empty record of recordLeaves positions.
func newElection(t testing.TB, eid, numChoices int, weights []int, recordLeaves int) *election {
	t.Helper()
	e := &election{t: t, eid: big.NewInt(int64(eid)), numChoices: numChoices}
	e.sk, e.g, e.h = shared.ElGamalKeygen()
	leaves := make([]*big.Int, len(weights))
	for i, w := range weights {
		v := voter{anchor: newEdKeys(), weight: big.NewInt(int64(w))}
		e.voters = append(e.voters, v)
		leaves[i] = shared.PoseidonMD(v.anchor.pkX, v.anchor.pkY, v.weight)
	}
	e.rollRoot, e.rollPaths = buildWeightTree(leaves)
	e.record = shared.NewRecordTree(shared.MerkleHeight(recordLeaves))
	return e
}

// register makes voter v self-register a fresh voting credential at the next
// free record position and returns the registration's index.
func (e *election) register(v int) int {
	pos := e.nextPos
	e.nextPos++
	return e.registerAt(v, pos)
}

// registerAt is register with an explicit record position.
func (e *election) registerAt(v int, pos uint64) int {
	vt := e.voters[v]
	reg := registration{voter: v, vote: newEdKeys(), pos: pos}
	reg.sig = vt.anchor.sign(shared.PoseidonMD(e.eid, reg.vote.pkX, reg.vote.pkY, vt.anchor.pkX, vt.anchor.pkY))
	msg := voteropening.RegistrationMessage(reg.vote.pkX, reg.vote.pkY, reg.sig[0], reg.sig[1], reg.sig[2])
	for {
		r := shared.RandomScalar()
		o, err := voteropening.ComputeOpeningMsg(msg, r)
		if err != nil {
			continue // resample (probability ≈ 2^-128)
		}
		reg.r = r
		e.record.Set(pos, shared.EntryCommitmentNative(new(big.Int).SetUint64(pos), o.RsigHi, o.RsigLo))
		break
	}
	e.regs = append(e.regs, reg)
	return len(e.regs) - 1
}

// ballot returns registration reg's ballot for choice, with a fresh
// identifier, signed.
func (e *election) ballot(reg, choice int) plainBallot {
	r := e.regs[reg]
	v := e.voters[r.voter]
	p := plainBallot{
		Eid:  e.eid,
		PkVx: r.vote.pkX, PkVy: r.vote.pkY,
		PkAx: v.anchor.pkX, PkAy: v.anchor.pkY,
		SigReg:    r.sig,
		RegRand:   r.r,
		PosReg:    new(big.Int).SetUint64(r.pos),
		LeafIndex: big.NewInt(int64(r.voter)),
		Path:      append([]*big.Int{}, e.rollPaths[r.voter]...),
		Weight:    v.weight,
		Choices:   make([]*big.Int, e.numChoices),
		BallotID:  shared.RandomScalar(),
	}
	for j := range p.Choices {
		p.Choices[j] = big.NewInt(0)
	}
	p.Choices[choice] = v.weight
	e.sign(reg, &p)
	return p
}

// sign (re)computes σB over p with registration reg's voting key.
func (e *election) sign(reg int, p *plainBallot) {
	msg := []*big.Int{e.eid, p.PkAx, p.PkAy, p.PkVx, p.PkVy, p.PosReg}
	msg = append(msg, p.Choices...)
	msg = append(msg, p.Weight, p.SigReg[0], p.SigReg[1], p.SigReg[2], p.BallotID)
	p.SigB = e.regs[reg].vote.sign(shared.PoseidonMD(msg...))
}

// post encrypts p under the tallier's key and appends it to BB′.  valid is the
// validity bit the circuit must compute for it.  It returns the ballot's index.
func (e *election) post(p plainBallot, valid bool) int {
	enc := func(m *big.Int) ElGamalCiphertext {
		c1, c2 := shared.ElGamalEncryptScalar(m, e.g, e.h)
		return ElGamalCiphertext{C1: c1, C2: c2}
	}
	ct := BallotCiphertexts{
		EidC:      enc(p.Eid),
		PkVoteX_C: enc(p.PkVx), PkVoteY_C: enc(p.PkVy),
		PkAnchorX_C: enc(p.PkAx), PkAnchorY_C: enc(p.PkAy),
		B3_RX_C: enc(p.SigReg[0]), B3_RY_C: enc(p.SigReg[1]), B3_S_C: enc(p.SigReg[2]),
		RegRandC:   enc(p.RegRand),
		PosRegC:    enc(p.PosReg),
		LeafIndexC: enc(p.LeafIndex),
		WeightC:    enc(p.Weight),
		BallotIDC:  enc(p.BallotID),
		B4_RX_C:    enc(p.SigB[0]), B4_RY_C: enc(p.SigB[1]), B4_S_C: enc(p.SigB[2]),
	}
	for _, s := range p.Path {
		ct.PathWeightC = append(ct.PathWeightC, enc(s))
	}
	for _, c := range p.Choices {
		ct.ChoiceC = append(ct.ChoiceC, enc(c))
	}
	e.ballots = append(e.ballots, postedBallot{plain: p, valid: valid, ct: ct})
	return len(e.ballots) - 1
}

// cast posts registration reg's honest ballot for choice.
func (e *election) cast(reg, choice int) int { return e.post(e.ballot(reg, choice), true) }

// replay posts a fresh encryption of ballot i's plaintext — what a tallier,
// who can decrypt, is able to put on the board (paper Section 5.2).
func (e *election) replay(i int) int { return e.post(e.ballots[i].plain, e.ballots[i].valid) }

func (e *election) validity() []bool {
	v := make([]bool, len(e.ballots))
	for i, b := range e.ballots {
		v[i] = b.valid
	}
	return v
}

/* --------------------------- reference tally (spec) ------------------------ */

// referenceTally is Deduplicate followed by Accumulate, as defined in paper
// Section 5.3: among the valid ballots, group by registration (IC.pk, t_reg)
// and drop every ballot whose identifier appeared at an earlier position in
// its group; for each IC.pk take the group with the smallest t_reg and, in it,
// the ballot with the largest position; add up the chosen ballots' weights.
func (e *election) referenceTally(valid []bool) []*big.Int {
	type group struct {
		pk, reg string
		posReg  *big.Int
		ballots []int // positions, increasing
		ids     map[string]bool
	}
	groups := map[string]*group{}
	for t, b := range e.ballots {
		if !valid[t] {
			continue
		}
		pk := b.plain.PkAx.String() + "," + b.plain.PkAy.String()
		key := pk + "@" + b.plain.PosReg.String()
		g := groups[key]
		if g == nil {
			g = &group{pk: pk, posReg: b.plain.PosReg, ids: map[string]bool{}}
			groups[key] = g
		}
		if id := b.plain.BallotID.String(); !g.ids[id] {
			g.ids[id] = true
			g.ballots = append(g.ballots, t)
		}
	}
	earliest := map[string]*group{}
	for _, g := range groups {
		if cur := earliest[g.pk]; cur == nil || g.posReg.Cmp(cur.posReg) < 0 {
			earliest[g.pk] = g
		}
	}
	tally := make([]*big.Int, e.numChoices)
	for j := range tally {
		tally[j] = new(big.Int)
	}
	for _, g := range earliest {
		final := e.ballots[g.ballots[len(g.ballots)-1]].plain
		for j := range tally {
			tally[j].Add(tally[j], final.Choices[j])
		}
	}
	return tally
}

/* ---------------------------------- witness -------------------------------- */

func (e *election) skeleton() *CastIronCircuit {
	return NewSkeleton(len(e.ballots), e.numChoices, len(e.rollPaths[0]), e.record.Height())
}

// sortedRows returns B_sorted for the given validity bits: the masked rows in
// increasing (IC.pk, t_reg, id_B, t) order.
func (e *election) sortedRows(valid []bool) []Row {
	type row struct {
		key    [4]*big.Int
		pos    int
		choice []*big.Int
	}
	zero := new(big.Int)
	rows := make([]row, len(e.ballots))
	for i, b := range e.ballots {
		rows[i] = row{key: [4]*big.Int{zero, zero, zero, zero}, pos: i + 1, choice: make([]*big.Int, e.numChoices)}
		for j := range rows[i].choice {
			rows[i].choice[j] = zero
		}
		if valid[i] {
			rows[i].key = [4]*big.Int{b.plain.PkAx, b.plain.PkAy, b.plain.PosReg, b.plain.BallotID}
			copy(rows[i].choice, b.plain.Choices)
		}
	}
	sort.Slice(rows, func(a, b int) bool {
		for k := range rows[a].key {
			if c := rows[a].key[k].Cmp(rows[b].key[k]); c != 0 {
				return c < 0
			}
		}
		return rows[a].pos < rows[b].pos
	})
	out := make([]Row, len(rows))
	for i, r := range rows {
		out[i] = Row{PkAnchorX: r.key[0], PkAnchorY: r.key[1], PosReg: r.key[2], BallotID: r.key[3], Pos: r.pos,
			Choice: make([]frontend.Variable, e.numChoices)}
		for j := range r.choice {
			out[i].Choice[j] = r.choice[j]
		}
	}
	return out
}

// assignment returns the public inputs and the honest tallier's witness.
func (e *election) assignment() *CastIronCircuit { return e.assignmentFor(e.validity()) }

// assignmentFor is assignment for a tallier that treats the ballots as valid
// according to the given bits (the sorted view and the result follow from
// them); the circuit must reject it unless the bits are the true ones.
func (e *election) assignmentFor(valid []bool) *CastIronCircuit {
	if len(e.ballots) == 0 {
		e.t.Fatal("no ballots")
	}
	a := &CastIronCircuit{
		ElectionID:       e.eid,
		VoterRollRoot:    e.rollRoot,
		RegistrationRoot: e.record.Root(),
		ElGamalG:         e.g,
		ElGamalH:         e.h,
		ElGamalSk:        e.sk,
		Sorted:           e.sortedRows(valid),
	}
	limit := new(big.Int).Lsh(big.NewInt(1), uint(e.record.Height()))
	for _, b := range e.ballots {
		a.BulletinBoard = append(a.BulletinBoard, b.ct)
		// The tallier looks up the record at the ballot's t_reg (nothing to
		// look up if t_reg is not a record position).
		op := RecordOpening{Leaf: 0, Path: make([]frontend.Variable, e.record.Height())}
		for k := range op.Path {
			op.Path[k] = 0
		}
		if b.plain.PosReg.Cmp(limit) < 0 {
			pos := b.plain.PosReg.Uint64()
			op.Leaf = e.record.Leaf(pos)
			for k, s := range e.record.Path(pos) {
				op.Path[k] = s
			}
		}
		a.RecordOpenings = append(a.RecordOpenings, op)
	}
	for _, x := range e.referenceTally(valid) {
		a.Tally = append(a.Tally, x)
	}
	return a
}

// solved runs the circuit on the assignment with gnark's test engine.
func (e *election) solved(a *CastIronCircuit) error {
	return test.IsSolved(e.skeleton(), a, shared.Field)
}

func tallyInts(xs []frontend.Variable) []int64 {
	out := make([]int64, len(xs))
	for i, x := range xs {
		out[i] = x.(*big.Int).Int64()
	}
	return out
}

/* ----------------------------- synthetic elections -------------------------- */

// syntheticElection is the Figure 4 workload: n voters of weight 1, each with
// one registration and one ballot, two choices.
func syntheticElection(t testing.TB, n, recordLeaves int) *election {
	weights := make([]int, n)
	for i := range weights {
		weights[i] = 1
	}
	e := newElection(t, 1000+n, 2, weights, recordLeaves)
	for i := 0; i < n; i++ {
		e.cast(e.register(i), i%2)
	}
	return e
}

/* ------------------------------ Groth16 prove/verify ------------------------ */

// circuitKeyTag versions cached proving keys: keys generated for another
// revision of the circuit are not valid for this one.
const circuitKeyTag = "v2"

type proveResult struct {
	constraints    int
	compile, setup time.Duration
	proofs         []time.Duration
	verify         time.Duration
}

// proveGroth16 compiles the election's circuit, runs the Groth16 setup, proves
// `repeats` times and verifies the last proof.  Keys are cached on disk only
// if CASTIRON_KEYS names a directory (useful for the hours-long setups of the
// large runs; a 4,096-ballot proving key is over 100 GB).
func proveGroth16(t testing.TB, e *election, repeats int) proveResult {
	t.Helper()
	var res proveResult
	start := time.Now()
	ccs, err := frontend.Compile(shared.Field, r1cs.NewBuilder, e.skeleton())
	if err != nil {
		t.Fatal(err)
	}
	res.compile, res.constraints = time.Since(start), ccs.GetNbConstraints()
	t.Logf("prep: circuit compile: %s (%d constraints)", res.compile, res.constraints)

	witness, err := frontend.NewWitness(e.assignment(), shared.Field)
	if err != nil {
		t.Fatal(err)
	}
	public, err := witness.Public()
	if err != nil {
		t.Fatal(err)
	}

	start = time.Now()
	pk, vk := groth16Keys(t, ccs, e.skeleton())
	res.setup = time.Since(start)
	t.Logf("prep: setup: %s", res.setup)

	var proof groth16.Proof
	for i := 0; i < repeats; i++ {
		start = time.Now()
		if proof, err = groth16.Prove(ccs, pk, witness); err != nil {
			t.Fatal("prove failed: ", err)
		}
		res.proofs = append(res.proofs, time.Since(start))
	}
	start = time.Now()
	if err := groth16.Verify(proof, vk, public); err != nil {
		t.Fatal("verify failed: ", err)
	}
	res.verify = time.Since(start)
	return res
}

func groth16Keys(t testing.TB, ccs constraint.ConstraintSystem, sk *CastIronCircuit) (groth16.ProvingKey, groth16.VerifyingKey) {
	t.Helper()
	dir := os.Getenv("CASTIRON_KEYS")
	base := fmt.Sprintf("groth16_%s_%s_%d_ballots_%d_choices_wd%d_rd%d", shared.Curve.Name, circuitKeyTag,
		len(sk.BulletinBoard), len(sk.Tally), len(sk.BulletinBoard[0].PathWeightC), len(sk.RecordOpenings[0].Path))
	pkPath, vkPath := filepath.Join(dir, base+"_pk.bin"), filepath.Join(dir, base+"_vk.bin")
	if dir != "" {
		pk, vk := groth16.NewProvingKey(shared.Curve.ID), groth16.NewVerifyingKey(shared.Curve.ID)
		if readFrom(pkPath, pk) == nil && readFrom(vkPath, vk) == nil {
			t.Logf("prep: loaded cached keys %s", base)
			return pk, vk
		}
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	if dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := writeTo(pkPath, pk); err != nil {
			t.Fatal(err)
		}
		if err := writeTo(vkPath, vk); err != nil {
			t.Fatal(err)
		}
	}
	return pk, vk
}

func readFrom(path string, dst io.ReaderFrom) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = dst.ReadFrom(f)
	return err
}

func writeTo(path string, src io.WriterTo) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if _, err := src.WriteTo(f); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
