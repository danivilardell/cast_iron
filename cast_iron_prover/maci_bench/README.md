# MACI reference measurements (Figure 4)

Scripts used to measure MACI's coordinator proving time on the same machine as
the Cast Iron tallying circuit. They run against a checkout of
[privacy-ethereum/maci](https://github.com/privacy-ethereum/maci) at tag
`v3.0.0` (commit 4d0e3a3) with its published test artifacts (`10-20-2`
message processor: batches of 20 messages; `10-1-2` vote tally: batches of
2 ballots) and snarkjs 0.7.5 (`groth16.fullProve`, i.e. witness generation +
proving, exactly what MACI's own `generateProofSnarkjs` does).

Setup (Node 20, pnpm 9):

```
git clone --depth 1 --branch v3.0.0 https://github.com/privacy-ethereum/maci.git && cd maci
pnpm install --frozen-lockfile
pnpm exec lerna run build --scope @maci-protocol/core --include-dependencies
pnpm exec ts-node ./.github/scripts/downloadZkeys.ts test ./zkeys_test
mkdir bench && cp <this directory>/*.js <this directory>/run_sweep.sh bench/
bash bench/run_sweep.sh          # COUNTS="1 2 4 8 16 32 64 128" REPEATS=5 by default; Figure 4 uses COUNTS up to 512
```

* `gen_inputs.js` builds a poll with `n` voters (one valid vote message each)
  with `@maci-protocol/core` and writes the circuit inputs of every
  message-processing and tally batch.
* `prove.js` times every batch proof (`label,repeat,batch,witness_s,prove_s,full_s,nproc`).
* `run_sweep.sh` runs both for the QV and non-QV circuits; `bench/results/maci_QV.csv`
  is copied to `plots/maci_batches_raw.csv` and summed per ballot count by
  `plots/maci_totals.py`.
