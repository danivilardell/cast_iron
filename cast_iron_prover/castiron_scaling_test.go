package castiron

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"cast_iron/shared"
)

// proverTimeCSV is where TestProverTimePlot writes its results, one row per
// proof.  plots/make_total_plot.py merges them with the MACI measurements
// (plots/maci_time_raw.csv) and renders Figure 4.
const proverTimeCSV = "plots/prover_time_raw.csv"

// numProveRepeats is the number of proofs per (ballots, record size).
const numProveRepeats = 5

// intListEnv parses a comma/space separated list of ints from an environment
// variable; it returns def when the variable is unset.
func intListEnv(name string, def []int) []int {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	var out []int
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' }) {
		n, err := strconv.Atoi(f)
		if err != nil {
			panic(fmt.Sprintf("%s: bad value %q", name, f))
		}
		out = append(out, n)
	}
	return out
}

// TestProverTimePlot is the Figure 4 sweep: Groth16 proving time of the
// tallying circuit for n ballots (n voters, one registration and one ballot
// each) over record trees of 2^10, 2^20 and 2^30 entries.  It runs only with
// CASTIRON_SWEEP=1 (hours, and needs a large machine: about 100 MB per ballot
// to compile).
//
//	CASTIRON_COUNTS   ballot counts            (default 1,2,4,...,512)
//	CASTIRON_LEAVES   record sizes             (default 2^10, 2^20, 2^30)
//	CASTIRON_REPEATS  proofs per configuration (default 5)
//	CASTIRON_CSV      output file              (default plots/prover_time_raw.csv, overwritten)
//	CASTIRON_CURVE    bn254 (default) | bls12381 (needed above ~2^28 constraints)
//	CASTIRON_KEYS     directory to cache proving keys in (default: no caching)
func TestProverTimePlot(t *testing.T) {
	if os.Getenv("CASTIRON_SWEEP") == "" {
		t.Skip("set CASTIRON_SWEEP=1 to run the Figure 4 sweep")
	}
	counts := intListEnv("CASTIRON_COUNTS", []int{1, 2, 4, 8, 16, 32, 64, 128, 256, 512})
	leavesList := intListEnv("CASTIRON_LEAVES", []int{1 << 10, 1 << 20, 1 << 30})
	repeats := numProveRepeats
	if v := intListEnv("CASTIRON_REPEATS", nil); len(v) == 1 && v[0] > 0 {
		repeats = v[0]
	}
	csvPath := proverTimeCSV
	if v := os.Getenv("CASTIRON_CSV"); v != "" {
		csvPath = v
	}

	rows := [][]string{{"ballots", "simulated_blockchain_leaves", "proof_attempt", "proof_time_seconds", "proof_system",
		"constraints", "compile_seconds", "setup_seconds"}}
	for _, leaves := range leavesList {
		for _, n := range counts {
			if leaves < n {
				continue // one registration per ballot must fit in the record
			}
			res := proveGroth16(t, syntheticElection(t, n, leaves), repeats)
			for i, d := range res.proofs {
				rows = append(rows, []string{
					strconv.Itoa(n), strconv.Itoa(leaves), strconv.Itoa(i + 1), fmt.Sprintf("%.6f", d.Seconds()), "groth16",
					strconv.Itoa(res.constraints), fmt.Sprintf("%.1f", res.compile.Seconds()), fmt.Sprintf("%.1f", res.setup.Seconds()),
				})
				t.Logf("[groth16/%s] ballots=%d leaves=%d attempt=%d/%d => %s proof time", shared.Curve.Name, n, leaves, i+1, repeats, d)
			}
			// rewrite the file after every configuration so that an interrupted run keeps its results
			if err := writeCSV(csvPath, rows); err != nil {
				t.Fatalf("writing %s: %v", csvPath, err)
			}
		}
	}
}

func writeCSV(path string, rows [][]string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	w := csv.NewWriter(f)
	if err := w.WriteAll(rows); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
