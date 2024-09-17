#!/usr/bin/env bash

set -uxo pipefail

#export CARGO_LOG=cargo::core::compiler::fingerprint=debug
export RPC=
if [ -z $RPC ]; then
  # You must set an RPC endpoint
  exit 1
fi
mkdir -p witnesses

export RAYON_NUM_THREADS=4
export TOKIO_WORKER_THREADS=4
export RUST_BACKTRACE=full
export RUST_LOG=info
export 'RUSTFLAGS=-C target-cpu=native -Zlinker-features=-lld'
export RUST_MIN_STACK=67108864

GITHASH=`git rev-parse --short HEAD`
echo "Testing against jergion, current revision: $GITHASH."

TESTNETBLOCKS="
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
"


KNOWNFAILED="
2
15
28
35
37
43
65

28
444

43
460
461
462
463
464
465
467
468
474
475
476
566
662
664
665
667
670
72
77
"


# 470..663 from Robin
for i in {470..663}
do
  ROBIN+=" $i"
done

# Pick random blocks
for i in {1..10}
do
  RANDOMBLOCKS+=" $((1 + $RANDOM % 688))"
done

# TESTNETBLOCKS="$KNOWNFAILED $ROBIN $RANDOMBLOCKS $TESTNETBLOCKS"
# BLOCKS="$ROBIN $RANDOMBLOCKS $TESTNETBLOCKS"
#BLOCKS=`echo $TESTNETBLOCKS | sed 's/\s/\n/g'`

SHUF=`shuf -e $TESTNETBLOCKS` 
echo $SHUF


#echo "Testing:  $BLOCKS"
printf "githash       block verdict\n" | tee -a witnesses/jerigon_results.txt
printf "---------------------------\n" | tee -a witnesses/jerigon_results.txt

for BLOCK in $KNOWNFAILED; do
  GITHASH=`git rev-parse --short HEAD`
  WITNESS="witnesses/$BLOCK.jerigon.$GITHASH.witness.json"
  echo "Fetching block $BLOCK"
  timeout 2m cargo run --release --bin rpc -- --backoff 3000 --max-retries 100 --rpc-url $RPC --rpc-type jerigon fetch --start-block $BLOCK --end-block $BLOCK 1> $WITNESS
  echo "Checking block $BLOCK"
  zero_bin/tools/prove_stdio.sh $WITNESS test_only
  EXITCODE=$?
  if [ $EXITCODE -eq 0 ]
  then
    RESULT="success"
  else
    RESULT="failure"
  fi
  printf "%s %10i %s\n" $GITHASH $BLOCK $RESULT | tee -a witnesses/jerigon_results.txt
done

exit 0
