package voteropening

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
	"sync"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth16bls12377 "github.com/consensys/gnark/backend/groth16/bls12-377"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// Groth16 benchmark harness.  Enabled with VO_BENCH=1; knobs:
//
//	VO_HASH=wide|narrow   VO_MUL=windowed|glv|dadd   VO_WINDOW=8   VO_RUNS=5
//	VO_PHASE=all|setup|prove   VO_DIR=<dir for serialized ccs/pk/vk>   VO_OUT=<json file>
//
// VO_PHASE=setup compiles + runs setup and serializes the artifacts; VO_PHASE=prove
// loads them and only proves/verifies, so that an external `/usr/bin/time -l`
// measures the proving process alone.

type benchResult struct {
	Config             string    `json:"config"`
	GoArch             string    `json:"goarch"`
	GoVersion          string    `json:"goversion"`
	NumCPU             int       `json:"num_cpu"`
	Constraints        int       `json:"constraints"`
	PublicVars         int       `json:"public_vars"`
	SecretVars         int       `json:"secret_vars"`
	InternalVars       int       `json:"internal_vars"`
	Coefficients       int       `json:"coefficients"`
	CompileSec         float64   `json:"compile_sec"`
	SetupSec           float64   `json:"setup_sec"`
	WitnessSec         float64   `json:"witness_sec"`
	ProveSecAll        []float64 `json:"prove_sec_all"`
	ProveSecMin        float64   `json:"prove_sec_min"`
	ProveSecMed        float64   `json:"prove_sec_median"`
	VerifySec          float64   `json:"verify_sec"`
	ProofBytes         int       `json:"proof_bytes_compressed"`
	ProofRawBytes      int       `json:"proof_bytes_raw"`
	NbCommitments      int       `json:"proof_nb_commitments"`
	PublicWitnessBytes int       `json:"public_witness_bytes"`
	NbPublicInputs     int       `json:"nb_public_inputs"`
	VKBytes            int       `json:"vk_bytes"`
	PKBytes            int       `json:"pk_bytes"`
	CCSBytes           int       `json:"ccs_bytes"`
	HeapBeforeProveMB  float64   `json:"heap_inuse_before_prove_mb"`
	PeakHeapInuseMB    float64   `json:"peak_heap_inuse_mb"`
	PeakHeapAllocMB    float64   `json:"peak_heap_alloc_mb"`
	PeakSysMB          float64   `json:"peak_sys_mb"`
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func configFromEnv(t *testing.T) Config {
	cfg := DefaultConfig()
	switch envOr("VO_CURVE", "bn254") {
	case "bn254":
		cfg.Curve = ecc.BN254
	case "bls12377":
		cfg.Curve = ecc.BLS12_377
	default:
		t.Fatalf("bad VO_CURVE")
	}
	switch envOr("VO_HASH", "wide") {
	case "wide":
		cfg.Hash = HashWide
	case "narrow":
		cfg.Hash = HashNarrow
	default:
		t.Fatalf("bad VO_HASH")
	}
	switch envOr("VO_MUL", "windowed") {
	case "windowed":
		cfg.Mul = MulWindowed
	case "glv":
		cfg.Mul = MulGnarkGLV
	case "dadd":
		cfg.Mul = MulGnarkDoubleAdd
	default:
		t.Fatalf("bad VO_MUL")
	}
	w, err := strconv.Atoi(envOr("VO_WINDOW", "8"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Window = w
	switch envOr("VO_LOOKUP", "tensor") {
	case "tensor":
		cfg.Lookup = LookupTensor
	case "decoder":
		cfg.Lookup = LookupDecoder
	default:
		t.Fatalf("bad VO_LOOKUP")
	}
	cfg.CheckTableLimbs = os.Getenv("VO_TABLECHECK") != ""
	return cfg
}

// memSampler tracks peak Go heap usage while running.
type memSampler struct {
	stop                          chan struct{}
	wg                            sync.WaitGroup
	peakInuse, peakAlloc, peakSys uint64
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
			if m.HeapAlloc > s.peakAlloc {
				s.peakAlloc = m.HeapAlloc
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

func mb(b uint64) float64 { return float64(b) / (1 << 20) }

func TestBenchGroth16(t *testing.T) {
	if os.Getenv("VO_BENCH") == "" {
		t.Skip("set VO_BENCH=1 to run the Groth16 benchmark")
	}
	cfg := configFromEnv(t)
	phase := envOr("VO_PHASE", "all")
	dir := envOr("VO_DIR", filepath.Join(os.TempDir(), "voteropening_keys"))
	runs, _ := strconv.Atoi(envOr("VO_RUNS", "5"))
	res := benchResult{Config: cfg.String(), GoArch: runtime.GOARCH, GoVersion: runtime.Version(), NumCPU: runtime.NumCPU()}

	var ccs constraint.ConstraintSystem
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey
	artifact := func(name string) string {
		return filepath.Join(dir, fmt.Sprintf("%s_%s_%s_%s_w%d_%s.bin", name, cfg.CurveID(), cfg.Hash, cfg.Mul, cfg.Window, cfg.Lookup))
	}

	if phase == "all" || phase == "setup" {
		start := time.Now()
		var err error
		ccs, err = frontend.Compile(cfg.Field(), r1cs.NewBuilder, NewCircuit(cfg))
		if err != nil {
			t.Fatal(err)
		}
		res.CompileSec = time.Since(start).Seconds()
		start = time.Now()
		pk, vk, err = groth16.Setup(ccs)
		if err != nil {
			t.Fatal(err)
		}
		res.SetupSec = time.Since(start).Seconds()
		if phase == "setup" {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			for name, w := range map[string]interface {
				WriteTo(io.Writer) (int64, error)
			}{"ccs": ccs, "pk": pk, "vk": vk} {
				f, err := os.Create(artifact(name))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := w.WriteTo(f); err != nil {
					t.Fatal(err)
				}
				f.Close()
			}
			t.Logf("setup done: %d constraints, compile %.2fs, setup %.2fs, artifacts in %s", ccs.GetNbConstraints(), res.CompileSec, res.SetupSec, dir)
			return
		}
	} else {
		load := func(name string, r interface {
			ReadFrom(io.Reader) (int64, error)
		}) {
			f, err := os.Open(artifact(name))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if _, err := r.ReadFrom(f); err != nil {
				t.Fatal(err)
			}
		}
		start := time.Now()
		ccs = groth16.NewCS(cfg.CurveID())
		pk = groth16.NewProvingKey(cfg.CurveID())
		vk = groth16.NewVerifyingKey(cfg.CurveID())
		load("ccs", ccs)
		load("pk", pk)
		load("vk", vk)
		t.Logf("loaded artifacts in %.2fs", time.Since(start).Seconds())
	}

	res.Constraints = ccs.GetNbConstraints()
	res.PublicVars = ccs.GetNbPublicVariables()
	res.SecretVars = ccs.GetNbSecretVariables()
	res.InternalVars = ccs.GetNbInternalVariables()
	res.Coefficients = ccs.GetNbCoefficients()

	// witness
	start := time.Now()
	o := RandomOpening(cfg)
	w, err := frontend.NewWitness(o.Assignment(), cfg.Field())
	if err != nil {
		t.Fatal(err)
	}
	res.WitnessSec = time.Since(start).Seconds()
	pub, err := w.Public()
	if err != nil {
		t.Fatal(err)
	}

	// proving
	var proof groth16.Proof
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	res.HeapBeforeProveMB = mb(m.HeapInuse)
	sampler := startMemSampler(5 * time.Millisecond)
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
	res.PeakHeapInuseMB = mb(sampler.peakInuse)
	res.PeakHeapAllocMB = mb(sampler.peakAlloc)
	res.PeakSysMB = mb(sampler.peakSys)
	sorted := append([]float64{}, res.ProveSecAll...)
	sort.Float64s(sorted)
	res.ProveSecMin = sorted[0]
	res.ProveSecMed = sorted[len(sorted)/2]

	// verification
	start = time.Now()
	if err := groth16.Verify(proof, vk, pub); err != nil {
		t.Fatal(err)
	}
	res.VerifySec = time.Since(start).Seconds()

	// sizes
	size := func(w interface {
		WriteTo(io.Writer) (int64, error)
	}) int {
		var buf bytes.Buffer
		if _, err := w.WriteTo(&buf); err != nil {
			t.Fatal(err)
		}
		return buf.Len()
	}
	res.ProofBytes = size(proof)
	{
		var buf bytes.Buffer
		if _, err := proof.WriteRawTo(&buf); err != nil {
			t.Fatal(err)
		}
		res.ProofRawBytes = buf.Len()
	}
	switch p := proof.(type) {
	case *groth16bn254.Proof:
		res.NbCommitments = len(p.Commitments)
	case *groth16bls12377.Proof:
		res.NbCommitments = len(p.Commitments)
	}
	res.VKBytes = size(vk)
	res.PKBytes = size(pk)
	res.CCSBytes = size(ccs)
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	res.PublicWitnessBytes = len(pubBytes)
	res.NbPublicInputs = ccs.GetNbPublicVariables() - 1 // minus the constant wire

	t.Logf("%s: %d constraints | prove min %.3fs median %.3fs (runs %v) | verify %.4fs | proof %dB (raw %dB, %d commitments) | pk %.1fMB vk %dB | heap before %.0fMB peak inuse %.0fMB peak sys %.0fMB",
		cfg, res.Constraints, res.ProveSecMin, res.ProveSecMed, res.ProveSecAll, res.VerifySec, res.ProofBytes, res.ProofRawBytes, res.NbCommitments,
		float64(res.PKBytes)/(1<<20), res.VKBytes, res.HeapBeforeProveMB, res.PeakHeapInuseMB, res.PeakSysMB)

	if out := os.Getenv("VO_OUT"); out != "" {
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			t.Fatal(err)
		}
		b, _ := json.MarshalIndent(res, "", "  ")
		if err := os.WriteFile(out, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
