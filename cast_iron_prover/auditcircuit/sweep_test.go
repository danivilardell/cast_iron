package auditcircuit

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// TestProverTimeSweep measures Groth16 proving time of the audit circuit
// (mock verifier, 12 proof ciphertexts, record depth AC_DEPTH) for the
// ballot counts in AC_COUNTS (default 1,2,4,…,512), AC_REPEATS proofs each,
// and writes plots/audit_prover_time.csv (AC_CSV to override) after every
// size.  Enable with AC_SWEEP=1.
func TestProverTimeSweep(t *testing.T) {
	if os.Getenv("AC_SWEEP") == "" {
		t.Skip("set AC_SWEEP=1")
	}
	depth := envInt("AC_DEPTH", 33)
	repeats := envInt("AC_REPEATS", 5)
	counts := []int{1, 2, 4, 8, 16, 32, 64, 128, 256, 512}
	if v := strings.TrimSpace(os.Getenv("AC_COUNTS")); v != "" {
		counts = nil
		for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' }) {
			n, err := strconv.Atoi(f)
			if err != nil {
				t.Fatal(err)
			}
			counts = append(counts, n)
		}
	}
	csvPath := os.Getenv("AC_CSV")
	if csvPath == "" {
		csvPath = filepath.Join("..", "plots", "audit_prover_time.csv")
	}
	cfg := Config{ProofFields: 12, RecordDepth: depth, Verifier: MockVerifier{Fields: 12}}

	type row struct {
		n, attempt  int
		constraints int
		seconds     float64
		setupSec    float64
		compileSec  float64
	}
	var rows []row
	write := func() {
		if err := os.MkdirAll(filepath.Dir(csvPath), 0o755); err != nil {
			t.Fatal(err)
		}
		f, err := os.Create(csvPath)
		if err != nil {
			t.Fatal(err)
		}
		w := csv.NewWriter(f)
		_ = w.Write([]string{"ballots", "record_depth", "proof_fields", "constraints", "proof_attempt", "proof_time_seconds", "setup_seconds", "compile_seconds", "goarch", "num_cpu"})
		for _, r := range rows {
			_ = w.Write([]string{strconv.Itoa(r.n), strconv.Itoa(depth), "12", strconv.Itoa(r.constraints), strconv.Itoa(r.attempt),
				fmt.Sprintf("%.6f", r.seconds), fmt.Sprintf("%.3f", r.setupSec), fmt.Sprintf("%.3f", r.compileSec), runtime.GOARCH, strconv.Itoa(runtime.NumCPU())})
		}
		w.Flush()
		f.Close()
	}
	for _, n := range counts {
		start := time.Now()
		ccs, err := frontend.Compile(field, r1cs.NewBuilder, NewCircuit(cfg, n))
		if err != nil {
			t.Fatal(err)
		}
		compileSec := time.Since(start).Seconds()
		start = time.Now()
		pk, vk, err := groth16.Setup(ccs)
		if err != nil {
			t.Fatal(err)
		}
		setupSec := time.Since(start).Seconds()
		fx := RandomFixture(cfg, n, 1<<depth)
		w, err := frontend.NewWitness(fx.Assignment(), field)
		if err != nil {
			t.Fatal(err)
		}
		pub, _ := w.Public()
		var times []float64
		var proof groth16.Proof
		for i := 0; i < repeats; i++ {
			start = time.Now()
			proof, err = groth16.Prove(ccs, pk, w)
			if err != nil {
				t.Fatal(err)
			}
			d := time.Since(start).Seconds()
			times = append(times, d)
			rows = append(rows, row{n: n, attempt: i + 1, constraints: ccs.GetNbConstraints(), seconds: d, setupSec: setupSec, compileSec: compileSec})
		}
		if err := groth16.Verify(proof, vk, pub); err != nil {
			t.Fatal(err)
		}
		t.Logf("ballots=%d constraints=%d compile=%.1fs setup=%.1fs proof times=%v", n, ccs.GetNbConstraints(), compileSec, setupSec, times)
		write()
		pk, vk, ccs = nil, nil, nil
		runtime.GC()
	}
}
