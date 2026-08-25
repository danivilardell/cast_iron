package voteropening

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// TestWindowSweep prints the constraint count of the windowed gadget for a
// range of window widths (compile only).
func TestWindowSweep(t *testing.T) {
	for _, hm := range []HashMode{HashWide, HashNarrow} {
		for w := 4; w <= 9; w++ {
			cfg := Config{Hash: hm, Mul: MulWindowed, Window: w, Lookup: LookupTensor}
			if _, err := ExceptionalScalars(w, cfg.ScalarBits()); err != nil {
				t.Logf("%-40s unsupported: %v", cfg, err)
				continue
			}
			ccs, err := frontend.Compile(cfg.Field(), r1cs.NewBuilder, NewCircuit(cfg))
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("%-40s %8d constraints %8d internal vars", cfg, ccs.GetNbConstraints(), ccs.GetNbInternalVariables())
		}
	}
}
