// Package shared holds the gadgets and constants that the tallying circuit
// (circuit 1) and the audit circuit (circuit 2) must agree on bit-for-bit:
// the Poseidon2 instance, the ElGamal decryption gadget, the registration
// tuple hash and the CReg accumulator, together with their native (off-circuit)
// counterparts used to build witnesses and fixtures.
//
// Both circuits are compiled over the BN254 scalar field; every function here
// is field-agnostic in gnark terms but the native helpers use gnark-crypto's
// BN254 Poseidon2 and must be kept in sync with the circuit's parameters.
package shared

import (
	"crypto/rand"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	poseidonbn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/frontend"
	stdhash "github.com/consensys/gnark/std/hash"
	poseidonstd "github.com/consensys/gnark/std/permutation/poseidon2"
)

// Poseidon2 parameters shared by all Cast Iron circuits (and by
// voteropening/circuit.go, which duplicates them on purpose).
const (
	PoseidonWidth         = 2
	PoseidonFullRounds    = 6
	PoseidonPartialRounds = 50
)

// ElGamalExpBits is the bit length of the ElGamal exponent (the tallier key).
const ElGamalExpBits = 254

// Domain tags of the registration-opening accumulator.
const (
	// RegTupleDomainTag is the `dom` field of the registration tuple hash
	// Poseidon(dom, pkAx, pkAy, posReg, H(B3)); the voter opening circuit takes
	// it as its witness Dom.
	RegTupleDomainTag = 0xC7C
	// TagCRegAlpha is the domain tag of the CReg challenge derivation
	// alphaReg = Poseidon(TagCRegAlpha, eid, voterRollRoot, recordRoot).
	TagCRegAlpha = 0xC7CA
)

/* ------------------------------- in-circuit ------------------------------- */

// NewPoseidonHasher returns the Merkle–Damgård Poseidon2 hasher used by every
// Cast Iron circuit (initial state 0, one permutation per absorbed element).
func NewPoseidonHasher(api frontend.API) stdhash.FieldHasher {
	perm, err := poseidonstd.NewPoseidon2FromParameters(api, PoseidonWidth, PoseidonFullRounds, PoseidonPartialRounds)
	if err != nil {
		panic(err)
	}
	return stdhash.NewMerkleDamgardHasher(api, perm, 0)
}

// ExpByBits computes base^exp with a 254-bit square-and-multiply.
func ExpByBits(api frontend.API, base, exp frontend.Variable) frontend.Variable {
	bits := api.ToBinary(exp, ElGamalExpBits)
	result := frontend.Variable(1)
	basePow := base
	for _, bit := range bits {
		mul := api.Mul(result, basePow)
		result = api.Select(bit, mul, result)
		basePow = api.Mul(basePow, basePow)
	}
	return result
}

// ElGamalDecryptScalar decrypts the multiplicative-ElGamal ciphertext (c1, c2)
// over the scalar field: m = c2 / c1^sk.
func ElGamalDecryptScalar(api frontend.API, c1, c2, sk frontend.Variable) frontend.Variable {
	shared := ExpByBits(api, c1, sk)
	return api.Mul(c2, api.Inverse(shared))
}

// EqBit returns 1 iff a == b, 0 otherwise (soft predicate).
func EqBit(api frontend.API, a, b frontend.Variable) frontend.Variable {
	return api.IsZero(api.Sub(a, b))
}

// HashB3 computes H(B3) = Poseidon(B3.Rx, B3.Ry, B3.S), the hash of the
// registration signature σreg.
func HashB3(api frontend.API, rx, ry, s frontend.Variable) frontend.Variable {
	h := NewPoseidonHasher(api)
	h.Write(rx, ry, s)
	return h.Sum()
}

// RegTupleHash computes the registration tuple hash bound by the voter opening
// proofs: Poseidon(RegTupleDomainTag, pkAx, pkAy, posReg, H(B3)).  It must stay
// byte-for-byte identical to voteropening's TupleHash.
func RegTupleHash(api frontend.API, pkAx, pkAy, posReg, hB3 frontend.Variable) frontend.Variable {
	h := NewPoseidonHasher(api)
	h.Write(RegTupleDomainTag, pkAx, pkAy, posReg, hB3)
	return h.Sum()
}

// CRegAlpha derives the accumulator challenge from the public context.
func CRegAlpha(api frontend.API, eid, voterRollRoot, recordRoot frontend.Variable) frontend.Variable {
	h := NewPoseidonHasher(api)
	h.Write(TagCRegAlpha, eid, voterRollRoot, recordRoot)
	return h.Sum()
}

// CRegStep returns acc · (Poseidon(tupleHash, regOk) + alpha), one step of the
// accumulator CReg = ∏_i (Poseidon(tupleHash_i, RegOk_i) + alphaReg).
func CRegStep(api frontend.API, acc, tupleHash, regOk, alpha frontend.Variable) frontend.Variable {
	h := NewPoseidonHasher(api)
	h.Write(tupleHash, regOk)
	return api.Mul(acc, api.Add(h.Sum(), alpha))
}

/* --------------------------------- native --------------------------------- */

// Field is the scalar field both circuits are compiled over.
var Field = ecc.BN254.ScalarField()

// FieldToBigInt converts a BN254 scalar-field element to a big.Int.
func FieldToBigInt(e fr.Element) *big.Int {
	b := e.Bytes()
	return new(big.Int).SetBytes(b[:])
}

// PoseidonMD hashes field elements exactly like NewPoseidonHasher.
func PoseidonMD(vals ...*big.Int) *big.Int {
	h := poseidonbn254.NewMerkleDamgardHasher()
	for _, v := range vals {
		var e fr.Element
		e.SetBigInt(v)
		b := e.Bytes()
		if _, err := h.Write(b[:]); err != nil {
			panic(err)
		}
	}
	return new(big.Int).SetBytes(h.Sum(nil))
}

// HashB3Native mirrors HashB3.
func HashB3Native(rx, ry, s *big.Int) *big.Int { return PoseidonMD(rx, ry, s) }

// RegTupleHashNative mirrors RegTupleHash (and voteropening's TupleHash).
func RegTupleHashNative(pkAx, pkAy, posReg, hB3 *big.Int) *big.Int {
	return PoseidonMD(big.NewInt(RegTupleDomainTag), pkAx, pkAy, posReg, hB3)
}

// CRegAlphaNative mirrors CRegAlpha.
func CRegAlphaNative(eid, voterRollRoot, recordRoot *big.Int) *big.Int {
	return PoseidonMD(big.NewInt(TagCRegAlpha), eid, voterRollRoot, recordRoot)
}

// ComputeCReg mirrors the accumulator ∏_i (Poseidon(tupleHash_i, regOk_i) + alpha).
func ComputeCReg(alpha *big.Int, tupleHashes []*big.Int, regOk []bool) *big.Int {
	acc := big.NewInt(1)
	for i, th := range tupleHashes {
		bit := big.NewInt(0)
		if regOk[i] {
			bit = big.NewInt(1)
		}
		term := PoseidonMD(th, bit)
		term.Add(term, alpha)
		acc.Mul(acc, term)
		acc.Mod(acc, Field)
	}
	return acc
}

// RandomScalar samples a uniform scalar-field element.
func RandomScalar() *big.Int {
	r, err := rand.Int(rand.Reader, Field)
	if err != nil {
		panic(err)
	}
	return r
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

// ElGamalDecryptNative mirrors ElGamalDecryptScalar.
func ElGamalDecryptNative(c1, c2, sk *big.Int) *big.Int {
	s := new(big.Int).Exp(c1, sk, Field)
	s.ModInverse(s, Field)
	m := new(big.Int).Mul(c2, s)
	return m.Mod(m, Field)
}

/* ----------------------------- record Merkle tree ----------------------------- */

// EntryDomainTag is the domain tag of the record-entry commitment
// Poseidon(EntryDomainTag, posReg, rσ_hi, rσ_lo) — the EntryCommitment public
// input of the voter opening circuit (voteropening/circuit.go, entryDomainTag).
const EntryDomainTag = 1

// EntryCommitmentNative mirrors voteropening's EntryCommitment: the record
// tree leaf for the transaction at position posReg with ECDSA r-component rσ.
func EntryCommitmentNative(posReg, rsigHi, rsigLo *big.Int) *big.Int {
	return PoseidonMD(big.NewInt(EntryDomainTag), posReg, rsigHi, rsigLo)
}

// EntryCommitment is the in-circuit counterpart of EntryCommitmentNative.
func EntryCommitment(api frontend.API, posReg, rsigHi, rsigLo frontend.Variable) frontend.Variable {
	h := NewPoseidonHasher(api)
	h.Write(EntryDomainTag, posReg, rsigHi, rsigLo)
	return h.Sum()
}

// MerkleRootFromPath folds a leaf up a plain Poseidon Merkle tree (the layout
// of BuildPlainMerkle): at level k the node is hashed with its sibling
// path[k], on the left if indexBits[k] = 1 and on the right otherwise.  It
// returns the computed root (callers compare it softly or assert it).
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

// BuildPlainMerkle builds a complete Poseidon Merkle tree with
// 2^⌈log₂ totalLeaves⌉ leaves lazily: leaves[i] sits at position i, positions
// i < totalLeaves without a provided leaf hold the deterministic filler
// Poseidon(0, i, 0) (standing in for unrelated transactions), and positions
// beyond totalLeaves hold Poseidon(0, 0, 0).  It returns the root and, for each
// provided leaf, its sibling path (leaf level first, height elements).
func BuildPlainMerkle(leaves []*big.Int, totalLeaves int) (root *big.Int, paths [][]*big.Int) {
	if totalLeaves <= 0 {
		return big.NewInt(0), nil
	}
	if totalLeaves < len(leaves) {
		panic("totalLeaves must be >= number of provided leaves")
	}
	treeLeaves, height := 1, 0
	for treeLeaves < totalLeaves {
		treeLeaves <<= 1
		height++
	}
	type nodeKey struct{ level, idx int }
	leafValues := make(map[int]*big.Int, len(leaves))
	for idx, leaf := range leaves {
		leafValues[idx] = leaf
	}
	defaultNodes := make([]*big.Int, height+1)
	defaultNodes[0] = PoseidonMD(big.NewInt(0), big.NewInt(0), big.NewInt(0))
	for lvl := 1; lvl <= height; lvl++ {
		defaultNodes[lvl] = PoseidonMD(defaultNodes[lvl-1], defaultNodes[lvl-1])
	}
	cache := make(map[nodeKey]*big.Int)
	var nodeValue func(level, idx int) *big.Int
	nodeValue = func(level, idx int) *big.Int {
		key := nodeKey{level, idx}
		if v, ok := cache[key]; ok {
			return v
		}
		var out *big.Int
		if level == 0 {
			if leaf, ok := leafValues[idx]; ok {
				out = leaf
			} else if idx < totalLeaves {
				out = PoseidonMD(big.NewInt(0), big.NewInt(int64(idx)), big.NewInt(0))
			} else {
				out = defaultNodes[0]
			}
		} else {
			start := idx * (1 << level)
			if start >= len(leaves) {
				out = defaultNodes[level]
			} else {
				out = PoseidonMD(nodeValue(level-1, 2*idx), nodeValue(level-1, 2*idx+1))
			}
		}
		cache[key] = out
		return out
	}
	root = nodeValue(height, 0)
	paths = make([][]*big.Int, len(leaves))
	for i := range leaves {
		idx := i
		path := make([]*big.Int, height)
		for lvl := 0; lvl < height; lvl++ {
			path[lvl] = nodeValue(lvl, idx^1)
			idx >>= 1
		}
		paths[i] = path
	}
	return root, paths
}

// MerkleHeight returns ⌈log₂ totalLeaves⌉, the path length of BuildPlainMerkle.
func MerkleHeight(totalLeaves int) int {
	h := 0
	for tl := 1; tl < totalLeaves; tl <<= 1 {
		h++
	}
	return h
}
