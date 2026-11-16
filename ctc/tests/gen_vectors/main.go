package main

import (
	"encoding/json"
	"fmt"
	"math/big"

	"cast_iron/shared"
	"cast_iron/voteropening"
)

func s(x *big.Int) string { return x.String() }

func main() {
	out := map[string]any{}
	var pm []map[string]any
	for n := 0; n <= 6; n++ {
		in := []string{}
		bi := []*big.Int{}
		for i := 0; i < n; i++ {
			v := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 200), big.NewInt(int64(i*7919+3)))
			bi = append(bi, v)
			in = append(in, s(v))
		}
		pm = append(pm, map[string]any{"in": in, "out": s(shared.PoseidonMD(bi...))})
	}
	out["poseidon_md"] = pm
	var ops []map[string]any
	for i := 0; i < 5; i++ {
		var o *voteropening.Opening
		for {
			var err error
			o, err = voteropening.ComputeOpening(shared.RandomScalar(), shared.RandomScalar(), shared.RandomScalar(), shared.RandomScalar())
			if err == nil {
				break
			}
		}
		pos := big.NewInt(int64(1000 + i))
		ops = append(ops, map[string]any{
			"rx": s(o.SigRx), "ry": s(o.SigRy), "s": s(o.SigS), "r": s(o.R),
			"h1": s(o.H1), "h2": s(o.H2), "c": s(o.C), "rsig": s(o.Rsig),
			"rsig_hi": s(o.RsigHi), "rsig_lo": s(o.RsigLo),
			"pos": s(pos), "leaf": s(shared.EntryCommitmentNative(pos, o.RsigHi, o.RsigLo)),
		})
	}
	out["openings"] = ops
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(b))
}
