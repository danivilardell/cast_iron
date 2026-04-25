package main

import (
	"encoding/csv"
	"fmt"
	"os"
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

const numProveRepeats = 1 // Number of proof runs per (ballots, leaves) after setup.

func TestProverTimePlot(t *testing.T) {
	fmt.Println("TestProverTimePlot")

	// Voter/ballot counts to sweep.
	counts := []int{512}
	//blockchainLeavesValues := []int{1 << 10, 1 << 15, 1 << 20, 1 << 25, 1 << 30}
	blockchainLeavesValues := []int{1 << 30}
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
				proofTimes, _, _, _ := runScenarioWithBlockchainLeavesProveRepeats(t, scen, leaves, numProveRepeats, ps)
				for i, d := range proofTimes {
					ballotsCol = append(ballotsCol, c)
					leavesCol = append(leavesCol, leaves)
					attemptCol = append(attemptCol, i+1)
					secondsCol = append(secondsCol, d.Seconds())
					proofSystemCol = append(proofSystemCol, ps.String())
					t.Logf("[%s] ballots=%d simulatedBlockchainLeaves=%d attempt=%d/%d => %s proof time", ps, c, leaves, i+1, numProveRepeats, d)
				}
				t.Logf("[%s] ballots=%d simulatedBlockchainLeaves=%d => all times: %v", ps, c, leaves, proofTimes)
			}
		}
	}

	if err := os.MkdirAll("plots", 0o755); err != nil {
		t.Fatalf("creating plots folder: %v", err)
	}
	if err := writeProverTimeCSV(ballotsCol, leavesCol, attemptCol, secondsCol, proofSystemCol, "plots/prover_time.csv"); err != nil {
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
