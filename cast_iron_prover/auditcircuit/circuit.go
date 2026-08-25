package auditcircuit

import (
	"fmt"

	"github.com/consensys/gnark/frontend"

	"cast_iron/shared"
)

// Ciphertext is a multiplicative-ElGamal ciphertext over the scalar field,
// the same encoding as the tallying circuit's ElGamalCiphertext.
type Ciphertext struct {
	C1 frontend.Variable
	C2 frontend.Variable
}

// Ballot is the audit circuit's view of one bulletin-board entry: the
// registration fields (the same ciphertexts the tallying circuit decrypts to
// build tupleHash_i) and the encrypted opening proof π_open.
type Ballot struct {
	PkAnchorX_C Ciphertext
	PkAnchorY_C Ciphertext
	PosRegC     Ciphertext
	B3_RX_C     Ciphertext
	B3_RY_C     Ciphertext
	B3_S_C      Ciphertext
	// ProofC carries π_open, one ciphertext per proof field.  Layout: see
	// Config.ProofFields and the InnerVerifier in use.
	ProofC []Ciphertext
}

// RecordOpening is the tallier's private witness for one ballot: the record
// entry at position posReg (the ECDSA r-component of the transaction, split in
// two 128-bit halves as in the voter circuit) and its sibling path in the
// record tree.
type RecordOpening struct {
	RsigHi frontend.Variable
	RsigLo frontend.Variable
	Path   []frontend.Variable // siblings, leaf level first (RecordDepth elements)
}

// Config parametrises the circuit.
type Config struct {
	// ProofFields is the number of scalar-field elements π_open is encoded in
	// (12 for one point-coordinate per element of a BLS12-377 Groth16 proof
	// with one commitment: A, B (4), C, commitment, PoK).
	ProofFields int
	// RecordDepth is the height of the record tree (⌈log₂ #entries⌉).
	RecordDepth int
	// Verifier verifies the decrypted π_open; nil means "no verification,
	// b_i = 1" (accounting only).
	Verifier InnerVerifier
}

// Circuit is the audit circuit.  Public inputs first (gnark schema order).
type Circuit struct {
	// Public context, identical to the tallying circuit's.
	ElectionID    frontend.Variable `gnark:",public"`
	VoterRollRoot frontend.Variable `gnark:",public"`
	RecordRoot    frontend.Variable `gnark:",public"` // = the tallying circuit's RegistrationRoot = Mrk.Root(T_R)
	ElGamalG      frontend.Variable `gnark:",public"`
	ElGamalH      frontend.Variable `gnark:",public"`
	CReg          frontend.Variable `gnark:",public"`
	BulletinBoard []Ballot          `gnark:",public"`

	// Private witness.
	ElGamalSk frontend.Variable
	Records   []RecordOpening

	cfg Config
}

// NewCircuit returns a circuit skeleton for n ballots.
func NewCircuit(cfg Config, n int) *Circuit {
	c := &Circuit{cfg: cfg}
	c.BulletinBoard = make([]Ballot, n)
	c.Records = make([]RecordOpening, n)
	for i := range c.BulletinBoard {
		c.BulletinBoard[i].ProofC = make([]Ciphertext, cfg.ProofFields)
		c.Records[i].Path = make([]frontend.Variable, cfg.RecordDepth)
	}
	return c
}

// Config returns the circuit's configuration.
func (c *Circuit) Config() Config { return c.cfg }

// Define implements frontend.Circuit.
func (c *Circuit) Define(api frontend.API) error {
	n := len(c.BulletinBoard)
	if len(c.Records) != n {
		return fmt.Errorf("Records must have one entry per ballot (got %d, want %d)", len(c.Records), n)
	}
	dec := func(ct Ciphertext) frontend.Variable {
		return shared.ElGamalDecryptScalar(api, ct.C1, ct.C2, c.ElGamalSk)
	}

	// Global key relation (soft, as in the tallying circuit): the two circuits
	// provably decrypt under the same key only if both check H = G^sk.
	okKey := shared.EqBit(api, shared.ExpByBits(api, c.ElGamalG, c.ElGamalSk), c.ElGamalH)

	// Accumulator challenge from the shared public context.
	alpha := shared.CRegAlpha(api, c.ElectionID, c.VoterRollRoot, c.RecordRoot)
	acc := frontend.Variable(1)

	fieldBits := api.Compiler().FieldBitLen()
	for i := 0; i < n; i++ {
		bt := c.BulletinBoard[i]
		rec := c.Records[i]
		if len(rec.Path) != c.cfg.RecordDepth {
			return fmt.Errorf("ballot %d: record path has %d elements, want %d", i, len(rec.Path), c.cfg.RecordDepth)
		}
		if len(bt.ProofC) != c.cfg.ProofFields {
			return fmt.Errorf("ballot %d: %d proof ciphertexts, want %d", i, len(bt.ProofC), c.cfg.ProofFields)
		}

		// 1) Decrypt the registration fields and the proof.
		pkAx := dec(bt.PkAnchorX_C)
		pkAy := dec(bt.PkAnchorY_C)
		posReg := dec(bt.PosRegC)
		b3Rx := dec(bt.B3_RX_C)
		b3Ry := dec(bt.B3_RY_C)
		b3S := dec(bt.B3_S_C)
		proof := make([]frontend.Variable, len(bt.ProofC))
		for j := range bt.ProofC {
			proof[j] = dec(bt.ProofC[j])
		}

		// 2) Registration tuple hash, identical to the tallying circuit.
		hB3 := shared.HashB3(api, b3Rx, b3Ry, b3S)
		tupleHash := shared.RegTupleHash(api, pkAx, pkAy, posReg, hB3)

		// 3) Record entry: EntryCommitment (the voter proof's second public
		// input) must be the leaf at position posReg of the record tree.
		// Both the index range and the root comparison are soft.
		entry := shared.EntryCommitment(api, posReg, rec.RsigHi, rec.RsigLo)
		posBits := api.ToBinary(posReg, fieldBits)
		high := frontend.Variable(0)
		for k := c.cfg.RecordDepth; k < fieldBits; k++ {
			high = api.Add(high, posBits[k])
		}
		inRange := api.IsZero(high)
		root := shared.MerkleRootFromPath(api, entry, rec.Path, posBits[:c.cfg.RecordDepth])
		rootOk := shared.EqBit(api, root, c.RecordRoot)

		// 4) Verify π_open (soft).
		vOk := frontend.Variable(1)
		if c.cfg.Verifier != nil {
			vOk = c.cfg.Verifier.VerifyBit(api, proof, tupleHash, entry)
		}

		// 5) b_i and accumulator step (same formula as the tallying circuit).
		b := api.Mul(api.Mul(okKey, inRange), api.Mul(rootOk, vOk))
		acc = shared.CRegStep(api, acc, tupleHash, b, alpha)
	}
	api.AssertIsEqual(acc, c.CReg)
	return nil
}
