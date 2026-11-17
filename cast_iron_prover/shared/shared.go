// Package shared holds what the tallying circuit, its witness builder and the
// registration client must agree on bit for bit: the proving curve, the
// Poseidon2 instance, ElGamal over the scalar field and the record Merkle
// tree.  In-circuit gadgets sit next to their native counterparts.
package shared

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	poseidonbls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/poseidon2"
	poseidonbn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	gnarkhash "github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/frontend"
	stdhash "github.com/consensys/gnark/std/hash"
	poseidonstd "github.com/consensys/gnark/std/permutation/poseidon2"
)

// Poseidon2 parameters of every Cast Iron hash.
const (
	PoseidonWidth         = 2
	PoseidonFullRounds    = 6
	PoseidonPartialRounds = 50
)

/* ------------------------------- proving curve ----------------------------- */

// CurveConfig describes the pairing curve the circuit is compiled over: its
// scalar field (the circuit's native field) and the twisted Edwards curve
// defined over it that carries the EdDSA signatures.
type CurveConfig struct {
	Name    string
	ID      ecc.ID
	Field   *big.Int
	Edwards tedwards.ID
}

var curves = map[string]CurveConfig{
	// Groth16 over BN254 (default): Baby Jubjub for EdDSA.  The scalar field's
	// two-adicity of 28 caps one proof at 2^28 constraints.
	"bn254": {Name: "bn254", ID: ecc.BN254, Field: ecc.BN254.ScalarField(), Edwards: tedwards.BN254},
	// Groth16 over BLS12-381: Jubjub for EdDSA; two-adicity 32, i.e. up to 2^32
	// constraints in one proof (used for the single-proof large-ballot runs).
	"bls12381": {Name: "bls12381", ID: ecc.BLS12_381, Field: ecc.BLS12_381.ScalarField(), Edwards: tedwards.BLS12_381},
}

// Curve is the proving curve, selected by CASTIRON_CURVE (bn254 | bls12381,
// default bn254).
var Curve = func() CurveConfig {
	name := strings.ToLower(strings.TrimSpace(os.Getenv("CASTIRON_CURVE")))
	if name == "" {
		name = "bn254"
	}
	c, ok := curves[name]
	if !ok {
		panic(fmt.Sprintf("CASTIRON_CURVE=%q: unsupported curve (bn254 | bls12381)", name))
	}
	return c
}()

// Field is the scalar field the circuit is compiled over.
var Field = Curve.Field

// EdwardsCurveID returns the twisted Edwards curve matching the field the
// circuit is being compiled over.
func EdwardsCurveID(api frontend.API) tedwards.ID {
	q := api.Compiler().Field()
	for _, c := range curves {
		if c.Field.Cmp(q) == 0 {
			return c.Edwards
		}
	}
	panic("circuit compiled over an unsupported field")
}

/* --------------------------------- Poseidon -------------------------------- */

// NewPoseidonHasher returns the Merkle–Damgård Poseidon2 hasher used by the
// circuit (initial state 0, one permutation per absorbed element).
func NewPoseidonHasher(api frontend.API) stdhash.FieldHasher {
	perm, err := poseidonstd.NewPoseidon2FromParameters(api, PoseidonWidth, PoseidonFullRounds, PoseidonPartialRounds)
	if err != nil {
		panic(err)
	}
	return stdhash.NewMerkleDamgardHasher(api, perm, 0)
}

// NewNativePoseidon returns gnark-crypto's Merkle–Damgård Poseidon2 hasher
// over Curve's scalar field with the circuit's parameters (both curves'
// defaults are width 2, 6 full / 50 partial rounds, so this is byte for byte
// NewPoseidonHasher); it is also the hash handed to the native EdDSA signer.
func NewNativePoseidon() gnarkhash.StateStorer {
	switch Curve.ID {
	case ecc.BN254:
		return poseidonbn254.NewMerkleDamgardHasher()
	case ecc.BLS12_381:
		return poseidonbls12381.NewMerkleDamgardHasher()
	}
	panic("unsupported curve " + Curve.Name)
}

// PoseidonMD hashes field elements exactly like NewPoseidonHasher (each
// element absorbed as its 32-byte big-endian encoding, as fr.Element.Bytes()).
func PoseidonMD(vals ...*big.Int) *big.Int {
	h := NewNativePoseidon()
	for _, v := range vals {
		b := new(big.Int).Mod(v, Field).FillBytes(make([]byte, 32))
		if _, err := h.Write(b); err != nil {
			panic(err)
		}
	}
	return new(big.Int).SetBytes(h.Sum(nil))
}

// RandomScalar samples a uniform scalar-field element.
func RandomScalar() *big.Int {
	r, err := rand.Int(rand.Reader, Field)
	if err != nil {
		panic(err)
	}
	return r
}

/* --------------------------------- ElGamal --------------------------------- */

// ExpBits computes base^e for e = Σ bits[i]·2^i (bits boolean, little-endian)
// by square-and-multiply: three constraints per bit.
func ExpBits(api frontend.API, base frontend.Variable, bits []frontend.Variable) frontend.Variable {
	result := frontend.Variable(1)
	pow := base
	for i, bit := range bits {
		result = api.Select(bit, api.Mul(result, pow), result)
		if i < len(bits)-1 {
			pow = api.Mul(pow, pow)
		}
	}
	return result
}

// ElGamalDecryptBits decrypts the multiplicative-ElGamal ciphertext (c1, c2)
// over the scalar field, m = c2 / c1^sk, with sk given by its bits so that one
// decomposition of sk serves every ciphertext.  c1 must be nonzero, which the
// proof of plaintext knowledge checked by FILTER guarantees (c1 = g^r).
func ElGamalDecryptBits(api frontend.API, c1, c2 frontend.Variable, skBits []frontend.Variable) frontend.Variable {
	return api.Mul(c2, api.Inverse(ExpBits(api, c1, skBits)))
}

// ElGamalKeygen samples a tallier key pair for multiplicative ElGamal over the
// scalar field with generator 5.
func ElGamalKeygen() (sk, g, h *big.Int) {
	sk = RandomScalar()
	g = big.NewInt(5)
	h = new(big.Int).Exp(g, sk, Field)
	return sk, g, h
}

// ElGamalEncryptScalar encrypts m under (g, h): (g^r, m·h^r).
func ElGamalEncryptScalar(m, g, h *big.Int) (c1, c2 *big.Int) {
	r := RandomScalar()
	c1 = new(big.Int).Exp(g, r, Field)
	hr := new(big.Int).Exp(h, r, Field)
	c2 = new(big.Int).Mul(m, hr)
	c2.Mod(c2, Field)
	return c1, c2
}

/* ------------------------------- record tree ------------------------------- */

// EntryDomainTag is the domain tag of the record-entry commitment
// Poseidon(EntryDomainTag, posReg, rσ_hi, rσ_lo), the record tree leaf of a
// transaction.
const EntryDomainTag = 1

// EntryCommitmentNative computes the record tree leaf for the transaction at
// position posReg with ECDSA r-component rσ (as two 128-bit halves).
func EntryCommitmentNative(posReg, rsigHi, rsigLo *big.Int) *big.Int {
	return PoseidonMD(big.NewInt(EntryDomainTag), posReg, rsigHi, rsigLo)
}

// EntryCommitment is the in-circuit counterpart of EntryCommitmentNative.
func EntryCommitment(api frontend.API, posReg, rsigHi, rsigLo frontend.Variable) frontend.Variable {
	h := NewPoseidonHasher(api)
	h.Write(EntryDomainTag, posReg, rsigHi, rsigLo)
	return h.Sum()
}

// MerkleRootFromPath folds a leaf up a Poseidon Merkle tree: at level k the
// node is hashed with its sibling path[k], on the left if indexBits[k] = 1 and
// on the right otherwise.  It returns the computed root.
func MerkleRootFromPath(api frontend.API, leaf frontend.Variable, path []frontend.Variable, indexBits []frontend.Variable) frontend.Variable {
	h := NewPoseidonHasher(api)
	sum := leaf
	for k := range path {
		left := api.Select(indexBits[k], path[k], sum)
		right := api.Select(indexBits[k], sum, path[k])
		h.Reset()
		h.Write(left, right)
		sum = h.Sum()
	}
	return sum
}

// MerkleHeight returns ⌈log₂ leaves⌉.
func MerkleHeight(leaves int) int {
	h := 0
	for tl := 1; tl < leaves; tl <<= 1 {
		h++
	}
	return h
}

// RecordTree is T_R = Mrk.Build(TS.Read()): a complete binary Poseidon tree of
// the given height whose leaf at position t commits to the record entry M[t].
// It is stored sparsely (positions never Set hold EmptyLeaf), so a 2^30-entry
// record costs only as much as the positions an election touches.
type RecordTree struct {
	height int
	leaves map[uint64]*big.Int
	set    []uint64   // sorted positions of leaves, rebuilt lazily
	empty  []*big.Int // empty[l] = root of an all-empty subtree of height l
	nodes  map[[2]uint64]*big.Int
}

// EmptyLeaf is the leaf of a record position holding no entry.
func EmptyLeaf() *big.Int {
	return PoseidonMD(big.NewInt(0), big.NewInt(0), big.NewInt(0))
}

// NewRecordTree returns an empty record tree with 2^height positions.
func NewRecordTree(height int) *RecordTree {
	if height < 0 || height > 62 {
		panic("record tree height out of range")
	}
	t := &RecordTree{height: height, leaves: map[uint64]*big.Int{}, empty: make([]*big.Int, height+1)}
	t.empty[0] = EmptyLeaf()
	for l := 1; l <= height; l++ {
		t.empty[l] = PoseidonMD(t.empty[l-1], t.empty[l-1])
	}
	return t
}

// Height returns the tree height (the length of every sibling path).
func (t *RecordTree) Height() int { return t.height }

// Set stores leaf at position pos.
func (t *RecordTree) Set(pos uint64, leaf *big.Int) {
	if pos>>uint(t.height) != 0 {
		panic("record position out of range")
	}
	t.leaves[pos] = leaf
	t.set, t.nodes = nil, nil
}

// Root returns Mrk.Root(T_R).
func (t *RecordTree) Root() *big.Int { return t.node(t.height, 0) }

// Leaf returns the leaf at position pos.
func (t *RecordTree) Leaf(pos uint64) *big.Int { return t.node(0, pos) }

// Path returns the sibling path of position pos, leaf level first.
func (t *RecordTree) Path(pos uint64) []*big.Int {
	path := make([]*big.Int, t.height)
	for l := 0; l < t.height; l++ {
		path[l] = t.node(l, (pos>>uint(l))^1)
	}
	return path
}

func (t *RecordTree) node(level int, idx uint64) *big.Int {
	if t.set == nil {
		t.set = make([]uint64, 0, len(t.leaves))
		for p := range t.leaves {
			t.set = append(t.set, p)
		}
		sort.Slice(t.set, func(i, j int) bool { return t.set[i] < t.set[j] })
		t.nodes = map[[2]uint64]*big.Int{}
	}
	lo, hi := idx<<uint(level), (idx+1)<<uint(level)
	k := sort.Search(len(t.set), func(i int) bool { return t.set[i] >= lo })
	if k == len(t.set) || t.set[k] >= hi {
		return t.empty[level]
	}
	if level == 0 {
		return t.leaves[idx]
	}
	key := [2]uint64{uint64(level), idx}
	if v, ok := t.nodes[key]; ok {
		return v
	}
	v := PoseidonMD(t.node(level-1, 2*idx), t.node(level-1, 2*idx+1))
	t.nodes[key] = v
	return v
}
