#!/bin/zsh
# Full measurement run for the voter opening circuit (native arm64 Go).
set -u
GO=/tmp/goarm/go/bin/go
cd "$(dirname "$0")/.."
OUT=results
export VO_BENCH=1 VO_RUNS=5
echo "== constraint breakdown"
$GO test -count=1 -run 'TestConstraintBreakdown' -v . > $OUT/breakdown_run.log 2>&1 || echo BREAKDOWN-FAILED
echo "== groth16 benchmarks (in-process)"
run() { # name hash mul window lookup
  echo "-- $1"
  VO_HASH=$2 VO_MUL=$3 VO_WINDOW=$4 VO_LOOKUP=$5 VO_PHASE=all VO_OUT=$OUT/bench_$1.json \
    $GO test -count=1 -run TestBenchGroth16 -v . 2>&1 | grep -E "bench_test.go" | sed 's/^.*bench_test.go:[0-9]*: //'
}
run wide_w7_tensor   wide   windowed 7 tensor
run narrow_w7_tensor narrow windowed 7 tensor
run wide_w6_tensor   wide   windowed 6 tensor
run wide_w8_tensor   wide   windowed 8 tensor
run wide_glv         wide   glv      7 tensor
run wide_dadd        wide   dadd     7 tensor
echo "== peak RSS of a prove-only process (default config)"
rm -rf /tmp/vo_keys && mkdir -p /tmp/vo_keys
VO_HASH=wide VO_MUL=windowed VO_WINDOW=7 VO_LOOKUP=tensor VO_PHASE=setup VO_DIR=/tmp/vo_keys \
  $GO test -count=1 -run TestBenchGroth16 -v . 2>&1 | grep -E "bench_test.go" | sed 's/^.*bench_test.go:[0-9]*: //'
$GO test -c -o /tmp/vo.test . || echo COMPILE-FAILED
( cd $OUT && VO_HASH=wide VO_MUL=windowed VO_WINDOW=7 VO_LOOKUP=tensor VO_PHASE=prove VO_DIR=/tmp/vo_keys VO_RUNS=3 VO_OUT=$PWD/bench_wide_w7_tensor_proveonly.json \
  /usr/bin/time -l /tmp/vo.test -test.run TestBenchGroth16 -test.v > rss_prove.txt 2>&1 )
grep -E "maximum resident|bench_test.go|real|user|sys" $OUT/rss_prove.txt | sed 's/^.*bench_test.go:[0-9]*: //'
echo "== same default config under Rosetta (system x86_64 Go) for reference"
VO_HASH=wide VO_MUL=windowed VO_WINDOW=7 VO_LOOKUP=tensor VO_PHASE=all VO_OUT=$OUT/bench_wide_w7_tensor_rosetta_amd64.json \
  GOTOOLCHAIN=auto go test -count=1 -run TestBenchGroth16 -v . 2>&1 | grep -E "bench_test.go" | sed 's/^.*bench_test.go:[0-9]*: //'
echo "== done"
