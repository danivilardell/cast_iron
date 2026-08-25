package voteropening

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
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
	// The default configuration must be supported.
	if _, err := ExceptionalScalars(DefaultConfig().Window, DefaultConfig().ScalarBits()); err != nil {
		t.Fatal(err)
	}
}

// TestFixedBaseGadget checks the windowed gadget against gnark-crypto on edge
// scalars (and checks that the listed exceptional scalars indeed fail).
func TestFixedBaseGadget(t *testing.T) {
	const w, nbBits = 8, 256
	n := secpOrder
	scalars := []*big.Int{
		big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(255), big.NewInt(256), big.NewInt(257),
		new(big.Int).Sub(n, big.NewInt(1)), new(big.Int).Sub(n, big.NewInt(2)),
		pow2(255), new(big.Int).Sub(pow2(254), big.NewInt(1)), new(big.Int).Sub(pow2(256), n), // 2^256 mod n
	}
	for i := 0; i < 3; i++ {
		c, _ := randScalar()
		scalars = append(scalars, c)
	}
	exc, err := ExceptionalScalars(w, nbBits)
	if err != nil {
		t.Fatal(err)
	}
	circuit := &fixedBaseTestCircuit{Bits: make([]frontend.Variable, nbBits), opts: FixedBaseOptions{Window: w, Lookup: LookupTensor}}
	for _, c := range scalars {
		if c.Sign() == 0 || c.Cmp(n) >= 0 {
			t.Fatalf("bad test scalar %s", c)
		}
		var P secp256k1.G1Affine
		P.ScalarMultiplicationBase(c)
		assignment := &fixedBaseTestCircuit{
			Bits: bigBits(c, nbBits),
			X:    emulated.ValueOf[Fp](P.X.BigInt(new(big.Int))),
			Y:    emulated.ValueOf[Fp](P.Y.BigInt(new(big.Int))),
		}
		if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err != nil {
			t.Fatalf("scalar %s: %v", c.Text(16), err)
		}
	}
	// wrong point must fail
	{
		var P secp256k1.G1Affine
		P.ScalarMultiplicationBase(big.NewInt(5))
		assignment := &fixedBaseTestCircuit{
			Bits: bigBits(big.NewInt(6), nbBits),
			X:    emulated.ValueOf[Fp](P.X.BigInt(new(big.Int))),
			Y:    emulated.ValueOf[Fp](P.Y.BigInt(new(big.Int))),
		}
		if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err == nil {
			t.Fatal("expected failure for wrong point")
		}
	}
	// exceptional scalars: the honest prover hits a 0/0 in the addition formula
	for _, c := range exc {
		var P secp256k1.G1Affine
		P.ScalarMultiplicationBase(c)
		assignment := &fixedBaseTestCircuit{
			Bits: bigBits(c, nbBits),
			X:    emulated.ValueOf[Fp](P.X.BigInt(new(big.Int))),
			Y:    emulated.ValueOf[Fp](P.Y.BigInt(new(big.Int))),
		}
		if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err == nil {
			t.Fatalf("exceptional scalar %s unexpectedly solvable", c.Text(16))
		} else {
			t.Logf("exceptional scalar %s fails as predicted: %v", c.Text(16), firstLine(err.Error()))
		}
		// neighbours are fine
		for _, d := range []int64{-1, 1} {
			cc := new(big.Int).Add(c, big.NewInt(d))
			var Q secp256k1.G1Affine
			Q.ScalarMultiplicationBase(cc)
			assignment := &fixedBaseTestCircuit{
				Bits: bigBits(cc, nbBits),
				X:    emulated.ValueOf[Fp](Q.X.BigInt(new(big.Int))),
				Y:    emulated.ValueOf[Fp](Q.Y.BigInt(new(big.Int))),
			}
			if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err != nil {
				t.Fatalf("neighbour %s of exceptional scalar: %v", cc.Text(16), err)
			}
		}
	}
}

func randScalar() (*big.Int, error) {
	for {
		v := RandomFr()
		v.Lsh(v, 2)
		v.Add(v, RandomFr())
		v.Mod(v, secpOrder)
		if v.Sign() != 0 {
			return v, nil
		}
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// TestNativeECDSA checks that the nonce/opening pipeline is consistent with an
// ordinary ECDSA verifier: a signature made with nonce c has r = x([c]G).
func TestNativeECDSA(t *testing.T) {
	o := RandomOpening(DefaultConfig())
	sk, _ := randScalar()
	var pk secp256k1.G1Affine
	pk.ScalarMultiplicationBase(sk)
	msg, _ := randScalar()
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

func allConfigs() []Config {
	return []Config{
		{Hash: HashWide, Mul: MulWindowed, Window: 7, Lookup: LookupTensor},
		{Curve: ecc.BLS12_377, Hash: HashWide, Mul: MulWindowed, Window: 7, Lookup: LookupTensor},
		{Curve: ecc.BLS12_377, Hash: HashNarrow, Mul: MulWindowed, Window: 7, Lookup: LookupTensor},
		{Hash: HashNarrow, Mul: MulWindowed, Window: 7, Lookup: LookupTensor},
		{Hash: HashWide, Mul: MulWindowed, Window: 6, Lookup: LookupTensor},
		{Hash: HashWide, Mul: MulWindowed, Window: 8, Lookup: LookupTensor},
		{Hash: HashWide, Mul: MulWindowed, Window: 7, Lookup: LookupDecoder},
		{Hash: HashWide, Mul: MulWindowed, Window: 7, Lookup: LookupTensor, CheckTableLimbs: true},
		{Hash: HashWide, Mul: MulWindowed, Window: 8, Lookup: LookupDecoder, CheckTableLimbs: true},
		{Hash: HashWide, Mul: MulGnarkGLV},
		{Hash: HashNarrow, Mul: MulGnarkGLV},
		{Hash: HashWide, Mul: MulGnarkDoubleAdd},
		{Hash: HashNarrow, Mul: MulGnarkDoubleAdd},
	}
}

// TestCircuitSolves checks valid and tampered witnesses with the test engine
// for every configuration.
func TestCircuitSolves(t *testing.T) {
	for _, cfg := range allConfigs() {
		cfg := cfg
		t.Run(cfg.String(), func(t *testing.T) {
			circuit := NewCircuit(cfg)
			o := RandomOpening(cfg)
			rf := func() *big.Int { return RandomFieldElement(cfg) }
			if err := test.IsSolved(circuit, o.Assignment(), cfg.Field()); err != nil {
				t.Fatalf("valid witness rejected: %v", err)
			}
			tamper := map[string]func(a *Circuit){
				"R":               func(a *Circuit) { a.R = rf() },
				"RsigLo":          func(a *Circuit) { a.RsigLo = new(big.Int).Add(toBig(a.RsigLo), big.NewInt(1)) },
				"RsigHi":          func(a *Circuit) { a.RsigHi = new(big.Int).Add(toBig(a.RsigHi), big.NewInt(1)) },
				"SigS":            func(a *Circuit) { a.SigS = rf() },
				"TupleHash":       func(a *Circuit) { a.TupleHash = rf() },
				"EntryCommitment": func(a *Circuit) { a.EntryCommitment = rf() },
				"PosReg":          func(a *Circuit) { a.PosReg = rf() },
			}
			for name, f := range tamper {
				a := o.Assignment()
				f(a)
				if err := test.IsSolved(circuit, a, cfg.Field()); err == nil {
					t.Fatalf("tampered %s accepted", name)
				}
			}
		})
	}
}

func toBig(v frontend.Variable) *big.Int { return v.(*big.Int) }

// TestGroth16EndToEnd compiles the default configuration, runs setup, proves
// and verifies, and checks that a tampered witness cannot be proven.
func TestGroth16EndToEnd(t *testing.T) {
	cfg := DefaultConfig()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, NewCircuit(cfg))
	if err != nil {
		t.Fatal(err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	o := RandomOpening(cfg)
	w, err := frontend.NewWitness(o.Assignment(), ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := groth16.Prove(ccs, pk, w)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := w.Public()
	if err != nil {
		t.Fatal(err)
	}
	if err := groth16.Verify(proof, vk, pub); err != nil {
		t.Fatal(err)
	}
	// wrong public input must not verify
	bad := o.Assignment()
	bad.EntryCommitment = RandomFr()
	badW, _ := frontend.NewWitness(bad, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err := groth16.Verify(proof, vk, badW); err == nil {
		t.Fatal("proof verified against wrong public input")
	}
	// tampered witness must not prove
	bad = o.Assignment()
	bad.R = RandomFr()
	badFull, _ := frontend.NewWitness(bad, ecc.BN254.ScalarField())
	if _, err := groth16.Prove(ccs, pk, badFull); err == nil {
		t.Fatal("tampered witness produced a proof")
	}
}

// TestConstraintBreakdown compiles every configuration (plus the no-EC
// baseline) and records the R1CS sizes and a profiler report for the default
// configuration in results/breakdown.txt.
func TestConstraintBreakdown(t *testing.T) {
	var sb strings.Builder
	line := func(format string, a ...interface{}) {
		s := fmt.Sprintf(format, a...)
		t.Log(s)
		sb.WriteString(s + "\n")
	}
	line("R1CS constraint counts (BN254, gnark v0.14.0)")
	line("%-45s %12s %10s %10s %10s", "config", "constraints", "public", "secret", "internal")
	cfgs := allConfigs()
	cfgs = append(cfgs,
		Config{Hash: HashWide, Mul: MulWindowed, Window: 7, OmitScalarMul: true},
		Config{Hash: HashNarrow, Mul: MulWindowed, Window: 7, OmitScalarMul: true},
	)
	for _, cfg := range cfgs {
		ccs, err := frontend.Compile(cfg.Field(), r1cs.NewBuilder, NewCircuit(cfg))
		if err != nil {
			t.Fatalf("%s: %v", cfg, err)
		}
		line("%-45s %12d %10d %10d %10d", cfg, ccs.GetNbConstraints(), ccs.GetNbPublicVariables(), ccs.GetNbSecretVariables(), ccs.GetNbInternalVariables())
	}
	// profiler report for the default configuration
	p := profile.Start(profile.WithNoOutput())
	if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, NewCircuit(DefaultConfig())); err != nil {
		t.Fatal(err)
	}
	p.Stop()
	line("\nProfiler (constraints by call tree) for %s:\n%s", DefaultConfig(), p.Top())
	if err := os.MkdirAll("results", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("results", "breakdown.txt"), []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}
