package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

func generateSyntheticScenario(numBallots int) JSONScenario {
	voters := make([]JSONVoter, numBallots)
	for i := 0; i < numBallots; i++ {
		ballot := JSONBallot{
			ChoiceIndex:     i % 2,
			GoodAnchorSig:   true,
			GoodVoteSig:     true,
			GoodVoterMerkle: true,
			GoodRegMerkle:   true,
		}
		reg := JSONRegistration{
			NumBallots: 1,
			Ballots:    []JSONBallot{ballot},
		}
		voters[i] = JSONVoter{
			Weight:           1,
			NumRegistrations: 1,
			Registrations:    []JSONRegistration{reg},
		}
	}
	return JSONScenario{
		ElectionID: 1000 + numBallots,
		NumChoices: 2,
		Voters:     voters,
	}
}

const numProveRepeats = 5 // Number of proof runs per (ballots, leaves) after setup.

// proverTimeCSV is where TestProverTimePlot writes its raw results (one row
// per proof).  plots/make_total_plot.py merges them with the MACI reference
// rows of plots/prover_time.csv into plots/prover_time_total.csv and renders
// Figure 4.  The paper's pre-revision measurements stay in plots/prover_time.csv.
const proverTimeCSV = "plots/prover_time_raw.csv"

// intListEnv parses a comma/space separated list of ints from an environment
// variable (e.g. CASTIRON_COUNTS="512" to run a subset of the sweep); returns
// def when unset.
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

func TestProverTimePlot(t *testing.T) {
	fmt.Println("TestProverTimePlot")

	// Voter/ballot counts and registration-tree sizes to sweep.  Override with
	// CASTIRON_COUNTS / CASTIRON_LEAVES (comma separated) to run a subset, and
	// CASTIRON_CSV to write elsewhere (n = 512 needs ≈65 GB to compile: cloud only).
	counts := intListEnv("CASTIRON_COUNTS", []int{1, 2, 4, 8, 16, 32, 64, 128, 256})
	blockchainLeavesValues := intListEnv("CASTIRON_LEAVES", []int{1 << 10, 1 << 20, 1 << 30})
	csvPath := proverTimeCSV
	if v := os.Getenv("CASTIRON_CSV"); v != "" {
		csvPath = v
	}
	// CASTIRON_REPEATS overrides the number of proofs per configuration (e.g. 4
	// proofs of a 2048-ballot circuit = one pass over 8192 ballots).
	repeats := numProveRepeats
	if v := intListEnv("CASTIRON_REPEATS", nil); len(v) == 1 && v[0] > 0 {
		repeats = v[0]
	}
	//proofSystems := []ProofSystem{Groth16, Plonk}
	proofSystems := []ProofSystem{Groth16}

	var ballotsCol, leavesCol, attemptCol []int
	var secondsCol []float64
	var proofSystemCol []string

	for _, ps := range proofSystems {
		for _, leaves := range blockchainLeavesValues {
			for _, c := range counts {
				if leaves < c {
					// Need leaves >= number of registrations (one per ballot in our scenario).
					continue
				}
				scen := generateSyntheticScenario(c)
				proofTimes, _, _, _ := runScenarioWithBlockchainLeavesProveRepeats(t, scen, leaves, repeats, ps)
				for i, d := range proofTimes {
					ballotsCol = append(ballotsCol, c)
					leavesCol = append(leavesCol, leaves)
					attemptCol = append(attemptCol, i+1)
					secondsCol = append(secondsCol, d.Seconds())
					proofSystemCol = append(proofSystemCol, ps.String())
					t.Logf("[%s] ballots=%d simulatedBlockchainLeaves=%d attempt=%d/%d => %s proof time", ps, c, leaves, i+1, repeats, d)
				}
				t.Logf("[%s] ballots=%d simulatedBlockchainLeaves=%d => all times: %v", ps, c, leaves, proofTimes)
				if err := os.MkdirAll("plots", 0o755); err != nil {
					t.Fatalf("creating plots folder: %v", err)
				}
				if err := writeProverTimeCSV(ballotsCol, leavesCol, attemptCol, secondsCol, proofSystemCol, csvPath); err != nil {
					t.Fatalf("writing csv: %v", err)
				}
			}
		}
	}

	if err := os.MkdirAll("plots", 0o755); err != nil {
		t.Fatalf("creating plots folder: %v", err)
	}
	if err := writeProverTimeCSV(ballotsCol, leavesCol, attemptCol, secondsCol, proofSystemCol, csvPath); err != nil {
		t.Fatalf("writing csv: %v", err)
	}
}

// writeProverTimeCSV writes rows (ballots, simulated_blockchain_leaves, proof_attempt, proof_time_seconds, proof_system) to path.
func writeProverTimeCSV(ballots, simulatedBlockchainLeaves, proofAttempt []int, proofTimeSeconds []float64, proofSystems []string, path string) error {
	if len(ballots) == 0 {
		return nil
	}
	if len(ballots) != len(simulatedBlockchainLeaves) || len(ballots) != len(proofAttempt) || len(ballots) != len(proofTimeSeconds) || len(ballots) != len(proofSystems) {
		return fmt.Errorf("column length mismatch")
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	if err := writer.Write([]string{"ballots", "simulated_blockchain_leaves", "proof_attempt", "proof_time_seconds", "proof_system"}); err != nil {
		return err
	}
	for i := range ballots {
		row := []string{
			fmt.Sprintf("%d", ballots[i]),
			fmt.Sprintf("%d", simulatedBlockchainLeaves[i]),
			fmt.Sprintf("%d", proofAttempt[i]),
			fmt.Sprintf("%.6f", proofTimeSeconds[i]),
			proofSystems[i],
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}
	writer.Flush()
	return writer.Error()
}
