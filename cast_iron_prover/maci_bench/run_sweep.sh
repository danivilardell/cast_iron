#!/bin/bash
# MACI v3.0.0 prover-time sweep (snarkjs, test parameter set 10-20-2 / 10-1-2).
cd ~/maci || exit 1
export NVM_DIR=$HOME/.nvm; . $NVM_DIR/nvm.sh >/dev/null
Z=zkeys_test
sweep() {  # MODE REPEATS COUNTS PROVE_MODE LABELPREFIX
  local MODE=$1 REPEATS=$2 COUNTS=$3 PM=$4 PREFIX=$5 P T
  case $MODE in
    QV) P=MessageProcessorQv_10-20-2_test; T=VoteTallyQv_10-1-2_test;;
    NON_QV) P=MessageProcessorNonQv_10-20-2_test; T=VoteTallyNonQv_10-1-2_test;;
    *) echo "bad mode"; return 1;;
  esac
  local OUT=bench/results/maci_${PREFIX}${MODE}.csv
  for n in $COUNTS; do
    local d=bench/inputs/${MODE}_$n
    if [ ! -f $d/process_000.json ]; then
      NODE_PATH=packages/circuits/node_modules node bench/gen_inputs.js $n $MODE $d | tee -a bench/results/gen_${MODE}.log
    fi
    echo "=== $(date -u +%FT%TZ) $PREFIX$MODE n=$n repeats=$REPEATS prove_mode=$PM ==="
    PROVE_MODE=$PM NODE_PATH=packages/contracts/node_modules node bench/prove.js $d \
      $Z/$P/$P.0.zkey $Z/$P/${P}_js/$P.wasm $Z/$T/$T.0.zkey $Z/$T/${T}_js/$T.wasm $REPEATS ${MODE}_n$n $OUT || return 1
  done
}
COUNTS=${COUNTS:-"1 2 4 8 16 32 64 128"}
sweep QV ${REPEATS:-5} "$COUNTS" full "" || exit 1
sweep NON_QV ${REPEATS_NONQV:-2} "$COUNTS" full "" || exit 1
# per-proof breakdown (witness vs prove), single batch of each circuit
sweep QV 5 "1" split "split_" || exit 1
sweep NON_QV 5 "1" split "split_" || exit 1
echo SWEEP_DONE
