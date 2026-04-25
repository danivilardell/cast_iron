package main

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	tedwardsCrypto "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

// ----------------------------------------------------
// Circuit definition
// ----------------------------------------------------

type ElGamalDecryptCircuit struct {
	// Public inputs
	Gx, Gy   frontend.Variable `gnark:",public"`
	Hx, Hy   frontend.Variable `gnark:",public"`
	C1x, C1y frontend.Variable `gnark:",public"`
	C2x, C2y frontend.Variable `gnark:",public"`
	Mx, My   frontend.Variable `gnark:",public"`

	// Private witness
	X frontend.Variable
}

// Define enforces H = [x]G and M = C2 - [x]C1 with proper curve and subgroup checks.
func (c *ElGamalDecryptCircuit) Define(api frontend.API) error {
	curve, err := twistededwards.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}

	G := twistededwards.Point{X: c.Gx, Y: c.Gy}
	H := twistededwards.Point{X: c.Hx, Y: c.Hy}
	C1 := twistededwards.Point{X: c.C1x, Y: c.C1y}
	C2 := twistededwards.Point{X: c.C2x, Y: c.C2y}
	M := twistededwards.Point{X: c.Mx, Y: c.My}

	// Security: Verify all public points are on the curve
	curve.AssertIsOnCurve(G)
	curve.AssertIsOnCurve(H)
	curve.AssertIsOnCurve(C1)
	curve.AssertIsOnCurve(C2)
	curve.AssertIsOnCurve(M)

	// Security: BabyJubJub has cofactor 8. Apply cofactor clearing by multiplying
	// all points by the cofactor to eliminate any small-subgroup components.
	// This ensures all points are in the prime-order subgroup.
	cofactor := 8

	G = curve.ScalarMul(G, cofactor)
	H = curve.ScalarMul(H, cofactor)
	C1 = curve.ScalarMul(C1, cofactor)
	C2 = curve.ScalarMul(C2, cofactor)
	M = curve.ScalarMul(M, cofactor)

	// After cofactor clearing, verify none of the points are the identity
	// (which would indicate they were purely in the small subgroup)
	api.AssertIsDifferent(G.X, 0)
	api.AssertIsDifferent(H.X, 0)
	api.AssertIsDifferent(C1.X, 0)
	api.AssertIsDifferent(C2.X, 0)
	api.AssertIsDifferent(M.X, 0)

	// 1) Verify H = [x]G (using cofactor-cleared points)
	xG := curve.ScalarMul(G, c.X)
	api.AssertIsEqual(xG.X, H.X)
	api.AssertIsEqual(xG.Y, H.Y)

	// 2) Verify M = C2 - [x]C1 (using cofactor-cleared points)
	xC1 := curve.ScalarMul(C1, c.X)
	negxC1 := curve.Neg(xC1)
	rhs := curve.Add(C2, negxC1)
	api.AssertIsEqual(rhs.X, M.X)
	api.AssertIsEqual(rhs.Y, M.Y)

	return nil
}

type Ciphertext struct {
	C1, C2 tedwardsCrypto.PointAffine
}

func keygen() (sk *big.Int, pk tedwardsCrypto.PointAffine) {
	sk, _ = rand.Int(rand.Reader, ecc.BN254.ScalarField())
	params := tedwardsCrypto.GetEdwardsCurve()
	pk.ScalarMultiplication(&params.Base, sk)
	return sk, pk
}

func encrypt(pk tedwardsCrypto.PointAffine, msg tedwardsCrypto.PointAffine) Ciphertext {
	r, _ := rand.Int(rand.Reader, ecc.BN254.ScalarField())

	params := tedwardsCrypto.GetEdwardsCurve()

	// C1 = [r]G
	var C1 tedwardsCrypto.PointAffine
	C1.ScalarMultiplication(&params.Base, r)

	// rH = [r]pk
	var rH tedwardsCrypto.PointAffine
	rH.ScalarMultiplication(&pk, r)

	// C2 = M + rH
	var C2 tedwardsCrypto.PointAffine
	C2.Add(&msg, &rH)

	return Ciphertext{C1, C2}
}

func decrypt(sk *big.Int, ct Ciphertext) tedwardsCrypto.PointAffine {
	// M = C2 - [x]C1
	var xC1 tedwardsCrypto.PointAffine
	xC1.ScalarMultiplication(&ct.C1, sk)
	xC1.Neg(&xC1)

	var M tedwardsCrypto.PointAffine
	M.Add(&ct.C2, &xC1)
	return M
}

func main() {
	fmt.Println("🔹 Generating ElGamal keys...")
	sk, pk := keygen()
	fmt.Println("   Secret key:", sk)

	// Message as a curve point (use twisted Edwards generator for demo)
	params := tedwardsCrypto.GetEdwardsCurve()
	msg := params.Base

	fmt.Println("🔹 Encrypting message...")
	ct := encrypt(pk, msg)
	fmt.Println("   Ciphertext computed.")

	fmt.Println("🔹 Decrypting...")
	mDec := decrypt(sk, ct)
	if !mDec.Equal(&msg) {
		panic("❌ Decryption failed (plaintext mismatch)")
	}
	fmt.Println("   ✓ Plaintext matches after decryption")

	// Build circuit & witness
	var circuit ElGamalDecryptCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}
	fmt.Printf("✓ Circuit compiled with %d constraints\n", ccs.GetNbConstraints())

	pkGroth, vkGroth, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}

	assignment := ElGamalDecryptCircuit{
		Gx: params.Base.X, Gy: params.Base.Y,
		Hx: pk.X, Hy: pk.Y,
		C1x: ct.C1.X, C1y: ct.C1.Y,
		C2x: ct.C2.X, C2y: ct.C2.Y,
		Mx: msg.X, My: msg.Y,
		X: sk,
	}

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	proof, err := groth16.Prove(ccs, pkGroth, witness)
	if err != nil {
		panic(err)
	}
	err = groth16.Verify(proof, vkGroth, publicWitness)
	if err != nil {
		fmt.Println("❌ Proof verification failed:", err)
	} else {
		fmt.Println("✅ ZK proof verified successfully (ElGamal decryption correct)")
	}
}
