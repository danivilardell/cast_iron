package auditcircuit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func compileCount(t *testing.T, cfg Config, n int) int {
	t.Helper()
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, NewCircuit(cfg, n))
	if err != nil {
		t.Fatal(err)
	}
	return ccs.GetNbConstraints()
}

// TestConstraintBreakdown compiles n = 1 and n = 2 of several variants and
// writes the exact affine model constraints(n) = A + B·n per variant (the
// circuit is affine in n), from which the per-ballot breakdown (decryption /
// hashing / record check / mock verification) is derived, to
// results/breakdown.md and .json.
func TestConstraintBreakdown(t *testing.T) {
	type variant struct {
		name string
		cfg  Config
	}
	variants := []variant{}
	for _, depth := range []int{10, 33} {
		variants = append(variants,
			variant{fmt.Sprintf("depth%d mock12", depth), Config{ProofFields: 12, RecordDepth: depth, Verifier: MockVerifier{Fields: 12}}},
			variant{fmt.Sprintf("depth%d const12 (no verification)", depth), Config{ProofFields: 12, RecordDepth: depth, Verifier: ConstVerifier{Fields: 12, Bit: 1}}},
			variant{fmt.Sprintf("depth%d const0 (no proof decryption)", depth), Config{ProofFields: 0, RecordDepth: depth, Verifier: ConstVerifier{Fields: 0, Bit: 1}}},
			variant{fmt.Sprintf("depth%d mock24", depth), Config{ProofFields: 24, RecordDepth: depth, Verifier: MockVerifier{Fields: 24}}},
		)
	}
	type rec struct {
		Name      string `json:"name"`
		Depth     int    `json:"depth"`
		Fields    int    `json:"proof_fields"`
		C1        int    `json:"c1"`
		C2        int    `json:"c2"`
		PerBallot int    `json:"per_ballot"`
		Fixed     int    `json:"fixed"`
	}
	var recs []rec
	var sb strings.Builder
	sb.WriteString("| variant | constraints(1) | constraints(2) | per ballot B | fixed A |\n|---|---:|---:|---:|---:|\n")
	for _, v := range variants {
		c1, c2 := compileCount(t, v.cfg, 1), compileCount(t, v.cfg, 2)
		B := c2 - c1
		A := c1 - B
		recs = append(recs, rec{Name: v.name, Depth: v.cfg.RecordDepth, Fields: v.cfg.ProofFields, C1: c1, C2: c2, PerBallot: B, Fixed: A})
		line := fmt.Sprintf("| %s | %d | %d | %d | %d |", v.name, c1, c2, B, A)
		t.Log(line)
		sb.WriteString(line + "\n")
	}
	if err := os.MkdirAll("results", 0o755); err != nil {
		t.Fatal(err)
	}
	b, _ := json.MarshalIndent(recs, "", "  ")
	if err := os.WriteFile(filepath.Join("results", "breakdown.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("results", "breakdown.md"), []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

/* --------------------------- Groth16 benchmark --------------------------- */

type memSampler struct {
	stop               chan struct{}
	wg                 sync.WaitGroup
	peakInuse, peakSys uint64
}

func startMemSampler(interval time.Duration) *memSampler {
	s := &memSampler{stop: make(chan struct{})}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		var m runtime.MemStats
		tick := time.NewTicker(interval)
		defer tick.Stop()
		for {
			runtime.ReadMemStats(&m)
			if m.HeapInuse > s.peakInuse {
				s.peakInuse = m.HeapInuse
			}
			if m.Sys > s.peakSys {
				s.peakSys = m.Sys
			}
			select {
			case <-s.stop:
				return
			case <-tick.C:
			}
		}
	}()
	return s
}

func (s *memSampler) Stop() { close(s.stop); s.wg.Wait() }

type benchResult struct {
	N               int       `json:"n"`
	Depth           int       `json:"record_depth"`
	ProofFields     int       `json:"proof_fields"`
	Constraints     int       `json:"constraints"`
	Wires           int       `json:"wires"`
	CompileSec      float64   `json:"compile_sec"`
	CompilePeakMB   float64   `json:"compile_peak_heap_mb"`
	SetupSec        float64   `json:"setup_sec"`
	WitnessSec      float64   `json:"witness_sec"`
	ProveSecAll     []float64 `json:"prove_sec_all"`
	ProveSecMin     float64   `json:"prove_sec_min"`
	ProveSecMed     float64   `json:"prove_sec_median"`
	ProvePeakHeapMB float64   `json:"prove_peak_heap_mb"`
	ProvePeakSysMB  float64   `json:"prove_peak_sys_mb"`
	VerifySec       float64   `json:"verify_sec"`
	ProofBytes      int       `json:"proof_bytes"`
	PKBytes         int       `json:"pk_bytes"`
	PublicInputs    int       `json:"nb_public_inputs"`
	GoArch          string    `json:"goarch"`
	NumCPU          int       `json:"num_cpu"`
}

func envInt(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			panic(err)
		}
		return n
	}
	return def
}

// TestBenchGroth16 compiles, sets up, proves and verifies the audit circuit
// (mock verifier, 12 proof fields) for AC_N ballots and AC_DEPTH record
// depth; AC_BENCH=1 enables it, AC_OUT writes a JSON record.
func TestBenchGroth16(t *testing.T) {
	if os.Getenv("AC_BENCH") == "" {
		t.Skip("set AC_BENCH=1")
	}
	n := envInt("AC_N", 8)
	depth := envInt("AC_DEPTH", 33)
	runs := envInt("AC_RUNS", 3)
	cfg := Config{ProofFields: 12, RecordDepth: depth, Verifier: MockVerifier{Fields: 12}}
	res := benchResult{N: n, Depth: depth, ProofFields: 12, GoArch: runtime.GOARCH, NumCPU: runtime.NumCPU()}

	sampler := startMemSampler(20 * time.Millisecond)
	start := time.Now()
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, NewCircuit(cfg, n))
	if err != nil {
		t.Fatal(err)
	}
	res.CompileSec = time.Since(start).Seconds()
	sampler.Stop()
	res.CompilePeakMB = float64(sampler.peakInuse) / (1 << 20)
	res.Constraints = ccs.GetNbConstraints()
	res.Wires = ccs.GetNbPublicVariables() + ccs.GetNbSecretVariables() + ccs.GetNbInternalVariables()
	res.PublicInputs = ccs.GetNbPublicVariables() - 1

	start = time.Now()
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	res.SetupSec = time.Since(start).Seconds()

	start = time.Now()
	f := RandomFixture(cfg, n, 1<<depth)
	w, err := frontend.NewWitness(f.Assignment(), field)
	if err != nil {
		t.Fatal(err)
	}
	res.WitnessSec = time.Since(start).Seconds()
	pub, _ := w.Public()

	runtime.GC()
	sampler = startMemSampler(10 * time.Millisecond)
	var proof groth16.Proof
	for i := 0; i < runs; i++ {
		start = time.Now()
		proof, err = groth16.Prove(ccs, pk, w)
		if err != nil {
			t.Fatal(err)
		}
		res.ProveSecAll = append(res.ProveSecAll, time.Since(start).Seconds())
		runtime.GC()
	}
	sampler.Stop()
	res.ProvePeakHeapMB = float64(sampler.peakInuse) / (1 << 20)
	res.ProvePeakSysMB = float64(sampler.peakSys) / (1 << 20)
	sorted := append([]float64{}, res.ProveSecAll...)
	sort.Float64s(sorted)
	res.ProveSecMin, res.ProveSecMed = sorted[0], sorted[len(sorted)/2]

	start = time.Now()
	if err := groth16.Verify(proof, vk, pub); err != nil {
		t.Fatal(err)
	}
	res.VerifySec = time.Since(start).Seconds()
	size := func(w interface {
		WriteTo(io.Writer) (int64, error)
	}) int {
		var buf bytes.Buffer
		_, _ = w.WriteTo(&buf)
		return buf.Len()
	}
	res.ProofBytes, res.PKBytes = size(proof), size(pk)

	t.Logf("n=%d depth=%d: %d constraints (%d/ballot), compile %.1fs (peak %.0f MB), setup %.1fs, prove min %.2fs med %.2fs, peak heap %.0f MB, verify %.3fs, proof %dB, %d public inputs",
		n, depth, res.Constraints, res.Constraints/n, res.CompileSec, res.CompilePeakMB, res.SetupSec, res.ProveSecMin, res.ProveSecMed, res.ProvePeakHeapMB, res.VerifySec, res.ProofBytes, res.PublicInputs)
	if out := os.Getenv("AC_OUT"); out != "" {
		_ = os.MkdirAll(filepath.Dir(out), 0o755)
		b, _ := json.MarshalIndent(res, "", "  ")
		if err := os.WriteFile(out, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
