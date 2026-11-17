package voteropening

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"

	"cast_iron/shared"
)

func TestExceptionalScalars(t *testing.T) {
	for _, nbBits := range []int{254, 256} {
		for w := 3; w <= 12; w++ {
			exc, err := ExceptionalScalars(w, nbBits)
			if err != nil {
				t.Logf("w=%d nbBits=%d: unsupported (%v)", w, nbBits, err)
				continue
			}
			t.Logf("w=%d nbBits=%d: %d exceptional scalar(s)", w, nbBits, len(exc))
			for _, c := range exc {
				t.Logf("    c = %s (%d bits)", c.Text(16), c.BitLen())
			}
			if len(exc) > 2 {
				t.Fatalf("w=%d nbBits=%d: too many exceptional scalars (%d)", w, nbBits, len(exc))
			}
		}
	}
	// The configuration used by the tallying circuit must be supported.
	if _, err := ExceptionalScalars(DefaultWindow, ScalarBits); err != nil {
		t.Fatal(err)
	}
}

// fixedBaseTestCircuit exercises the fixed-base multiplication alone: it
// checks [Σ Bits_i 2^i]G = (X, Y).
type fixedBaseTestCircuit struct {
	Bits []frontend.Variable
	X, Y emulated.Element[Fp] `gnark:",public"`
	opts FixedBaseOptions
}

func (c *fixedBaseTestCircuit) Define(api frontend.API) error {
	for _, b := range c.Bits {
		api.AssertIsBoolean(b)
	}
	curve, err := sw_emulated.New[Fp, Fr](api, sw_emulated.GetSecp256k1Params())
	if err != nil {
		return err
	}
	P, err := fixedBaseMul(api, curve, c.Bits, c.opts)
	if err != nil {
		return err
	}
	fp, err := emulated.NewField[Fp](api)
	if err != nil {
		return err
	}
	fp.AssertIsEqual(&P.X, &c.X)
	fp.AssertIsEqual(&P.Y, &c.Y)
	return nil
}

func bigBits(v *big.Int, nb int) []frontend.Variable {
	out := make([]frontend.Variable, nb)
	for i := range out {
		out[i] = v.Bit(i)
	}
	return out
}

func pointAssignment(c *big.Int, nbBits int) *fixedBaseTestCircuit {
	var P secp256k1.G1Affine
	P.ScalarMultiplicationBase(c)
	return &fixedBaseTestCircuit{
		Bits: bigBits(c, nbBits),
		X:    emulated.ValueOf[Fp](P.X.BigInt(new(big.Int))),
		Y:    emulated.ValueOf[Fp](P.Y.BigInt(new(big.Int))),
	}
}

// TestFixedBaseGadget checks the windowed multiplication against gnark-crypto
// on edge scalars (and checks that the listed exceptional scalars indeed fail).
func TestFixedBaseGadget(t *testing.T) {
	const w, nbBits = 8, 256
	n := secpOrder
	scalars := []*big.Int{
		big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(255), big.NewInt(256), big.NewInt(257),
		new(big.Int).Sub(n, big.NewInt(1)), new(big.Int).Sub(n, big.NewInt(2)),
		pow2(255), new(big.Int).Sub(pow2(254), big.NewInt(1)), new(big.Int).Sub(pow2(256), n), // 2^256 mod n
	}
	for i := 0; i < 3; i++ {
		scalars = append(scalars, randScalar())
	}
	exc, err := ExceptionalScalars(w, nbBits)
	if err != nil {
		t.Fatal(err)
	}
	circuit := &fixedBaseTestCircuit{Bits: make([]frontend.Variable, nbBits), opts: FixedBaseOptions{Window: w}}
	for _, c := range scalars {
		if c.Sign() == 0 || c.Cmp(n) >= 0 {
			t.Fatalf("bad test scalar %s", c)
		}
		if err := test.IsSolved(circuit, pointAssignment(c, nbBits), shared.Field); err != nil {
			t.Fatalf("scalar %s: %v", c.Text(16), err)
		}
	}
	// wrong point must fail
	{
		a := pointAssignment(big.NewInt(5), nbBits)
		a.Bits = bigBits(big.NewInt(6), nbBits)
		if err := test.IsSolved(circuit, a, shared.Field); err == nil {
			t.Fatal("expected failure for wrong point")
		}
	}
	// exceptional scalars: the honest prover hits a 0/0 in the addition formula
	for _, c := range exc {
		if err := test.IsSolved(circuit, pointAssignment(c, nbBits), shared.Field); err == nil {
			t.Fatalf("exceptional scalar %s unexpectedly solvable", c.Text(16))
		} else {
			t.Logf("exceptional scalar %s fails as predicted: %v", c.Text(16), firstLine(err.Error()))
		}
		// neighbours are fine
		for _, d := range []int64{-1, 1} {
			cc := new(big.Int).Add(c, big.NewInt(d))
			if err := test.IsSolved(circuit, pointAssignment(cc, nbBits), shared.Field); err != nil {
				t.Fatalf("neighbour %s of exceptional scalar: %v", cc.Text(16), err)
			}
		}
	}
}

func randScalar() *big.Int {
	for {
		v := shared.RandomScalar()
		v.Lsh(v, 2)
		v.Add(v, shared.RandomScalar())
		v.Mod(v, secpOrder)
		if v.Sign() != 0 {
			return v
		}
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// openingTestCircuit is the gadget as the tallying circuit uses it: from the
// two Poseidon outputs to the soft bit [c ≠ 0 ∧ x([c]G) = rσ].
type openingTestCircuit struct {
	Ok             frontend.Variable `gnark:",public"`
	H1, H2         frontend.Variable
	RsigHi, RsigLo frontend.Variable
}

func (c *openingTestCircuit) Define(api frontend.API) error {
	g, err := NewFixedBaseGadget(api, FixedBaseOptions{Window: DefaultWindow}, ScalarBits)
	if err != nil {
		return err
	}
	bits, nonzero := g.NonceBitsWide(c.H1, c.H2)
	P, err := g.MulBits(bits)
	if err != nil {
		return err
	}
	hi, lo := g.XHalves(P)
	same := api.Mul(api.IsZero(api.Sub(hi, c.RsigHi)), api.IsZero(api.Sub(lo, c.RsigLo)))
	api.AssertIsEqual(api.Mul(nonzero, same), c.Ok)
	return nil
}

// TestGadgetMatchesNative checks that the in-circuit relation accepts exactly
// the openings ComputeOpening produces.
func TestGadgetMatchesNative(t *testing.T) {
	o := RandomOpening()
	circuit := &openingTestCircuit{}
	good := &openingTestCircuit{Ok: 1, H1: o.H1, H2: o.H2, RsigHi: o.RsigHi, RsigLo: o.RsigLo}
	if err := test.IsSolved(circuit, good, shared.Field); err != nil {
		t.Fatalf("valid opening rejected: %v", err)
	}
	bad := &openingTestCircuit{Ok: 1, H1: o.H1, H2: o.H2, RsigHi: o.RsigHi, RsigLo: new(big.Int).Add(o.RsigLo, big.NewInt(1))}
	if err := test.IsSolved(circuit, bad, shared.Field); err == nil {
		t.Fatal("wrong rσ accepted as valid")
	}
	bad.Ok = 0
	if err := test.IsSolved(circuit, bad, shared.Field); err != nil {
		t.Fatalf("wrong rσ must give Ok = 0: %v", err)
	}
	other := &openingTestCircuit{Ok: 1, H1: shared.RandomScalar(), H2: o.H2, RsigHi: o.RsigHi, RsigLo: o.RsigLo}
	if err := test.IsSolved(circuit, other, shared.Field); err == nil {
		t.Fatal("wrong hash accepted as valid")
	}
}

// TestNativeECDSA checks that the nonce/opening pipeline is consistent with an
// ordinary ECDSA verifier: a signature made with nonce c has r = x([c]G).
func TestNativeECDSA(t *testing.T) {
	o := RandomOpening()
	sk := randScalar()
	var pk secp256k1.G1Affine
	pk.ScalarMultiplicationBase(sk)
	msg := randScalar()
	r, s, err := SignWithNonce(sk, msg, o.C)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyECDSA(&pk, msg, r, s) {
		t.Fatal("signature does not verify")
	}
	if r.Cmp(o.Rsig) != 0 {
		t.Fatalf("r-component %s != x([c]G) %s", r.Text(16), o.Rsig.Text(16))
	}
}

// TestMatchesPythonClient replays the cross-language vectors of the Python
// CTC client (ctc/tests/vectors.json): the Poseidon2 hash, the nonce
// derivation and the record-tree leaf must agree in both implementations, or
// registrations made with the client could not be opened by the circuit.
func TestMatchesPythonClient(t *testing.T) {
	if shared.Curve.Name != "bn254" {
		t.Skip("the Python client hashes over the BN254 scalar field")
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "ctc", "tests", "vectors.json"))
	if err != nil {
		t.Skip("ctc/tests/vectors.json not found:", err)
	}
	var vec struct {
		PoseidonMD []struct {
			In  []string `json:"in"`
			Out string   `json:"out"`
		} `json:"poseidon_md"`
		Openings []map[string]string `json:"openings"`
	}
	if err := json.Unmarshal(raw, &vec); err != nil {
		t.Fatal(err)
	}
	big10 := func(s string) *big.Int {
		v, ok := new(big.Int).SetString(s, 10)
		if !ok {
			t.Fatalf("bad integer %q", s)
		}
		return v
	}
	if len(vec.PoseidonMD) == 0 || len(vec.Openings) == 0 {
		t.Fatal("no vectors")
	}
	for i, v := range vec.PoseidonMD {
		in := make([]*big.Int, len(v.In))
		for j := range v.In {
			in[j] = big10(v.In[j])
		}
		if got := shared.PoseidonMD(in...); got.Cmp(big10(v.Out)) != 0 {
			t.Fatalf("poseidon_md[%d]: got %s, want %s", i, got, v.Out)
		}
	}
	for i, v := range vec.Openings {
		o, err := ComputeOpening(big10(v["rx"]), big10(v["ry"]), big10(v["s"]), big10(v["r"]))
		if err != nil {
			t.Fatalf("openings[%d]: %v", i, err)
		}
		for name, got := range map[string]*big.Int{"h1": o.H1, "h2": o.H2, "c": o.C, "rsig": o.Rsig, "rsig_hi": o.RsigHi, "rsig_lo": o.RsigLo} {
			if got.Cmp(big10(v[name])) != 0 {
				t.Fatalf("openings[%d].%s: got %s, want %s", i, name, got, v[name])
			}
		}
		if got := shared.EntryCommitmentNative(big10(v["pos"]), o.RsigHi, o.RsigLo); got.Cmp(big10(v["leaf"])) != 0 {
			t.Fatalf("openings[%d].leaf: got %s, want %s", i, got, v["leaf"])
		}
	}
}
