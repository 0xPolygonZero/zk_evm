#!/usr/bin/env bash

set -uxo pipefail

if [ -z $RPC ]; then
  # You must set an RPC endpoint
  exit 1
fi
mkdir -p witnesses

# Must match the values in prove_stdio.sh or build is dirty.
#export RAYON_NUM_THREADS=1
#export TOKIO_WORKER_THREADS=1
export RUST_BACKTRACE=full
#export RUST_LOG=info
#export RUSTFLAGS='-C target-cpu=native -Zlinker-features=-lld'
#export RUST_MIN_STACK=33554432



CANCUNBLOCKS="
20548415
20240058
19665756
20634472
19807080
20634403
"

PRECANCUN="
19096840
19240700
"


#It's visible with block 20727641 
ROUND1=`echo {20727640..20727650}`

ROUND2="
20727641
20727643
20727644
20727645
20727646
20727647
20727648
20727649
20727650
"

ROUND3="
20727643
20727644
20727648
20727649
20727650
"

ROUND4="
19457111
19477724
19501672
19508907
19511272
19548904
19550401
19553425
19563122
19585193
19600168
19603017
19607029
19649976
19654474
19657021
19670735
19688239
19737540
19767306
19792995
19812505
19829370
19835094
19862390
19871215
19877263
19877279
19893964
19922838
19938970
19971875
20011069
20071977
20131326
20173673
20182890
20218660
20225259
20229861
20259823
20274215
20288828
20291090
20301243
20346949
20410573
20462322
20518465
20521004
20542632
20543651
20555951
20634148
20691605
20714397
20715309
20715461
20719386
20720179
20720275
20741147
20775888
20804319
20835783
20859523
20727643
20727644
20727648
20727649
20727650
"

ROUND5="
19650385
19542391
19578175
19511272
"


CANCUN=19426587
TIP=`cast block-number --rpc-url $RPC`
STATICTIP=20721266
NUMRANDOMBLOCKS=100
RANDOMBLOCKS=`shuf --input-range=$CANCUN-$TIP -n $NUMRANDOMBLOCKS | sort`

GITHASH=`git rev-parse --short HEAD`
echo "Testing against mainnet, current revision: $GITHASH."

#BLOCKS="$CANCUNBLOCKS $RANDOMBLOCKS $ROUND3"
#BLOCKS="19511272"
BLOCKS=$ROUND5
BLOCKS=`echo $BLOCKS | tr ' ' '\n' | sort -nu | tr '\n' ' '`
echo "Testing blocks: $BLOCKS"

echo "Testing:  $BLOCKS"
printf "\n\ngithash       block verdict   r duration\n" | tee -a witnesses/native_results.txt
echo       "----------------------------------------"   | tee -a witnesses/native_results.txt

for BLOCK in $BLOCKS; do
  GITHASH=`git rev-parse --short HEAD`
  WITNESS="witnesses/$BLOCK.native.$GITHASH.witness.json"
  echo "Fetching block $BLOCK"
  export RUST_LOG=rpc=trace
  nice -19 cargo run --quiet --release --bin rpc -- --backoff 3000 --max-retries 100 --rpc-url $RPC --rpc-type native --jumpdest-src client-fetched-structlogs fetch --start-block $BLOCK --end-block $BLOCK 1> $WITNESS
  rg "jump" $WITNESS
  echo "Testing blocks: $BLOCKS."
  echo "Now testing block $BLOCK .."
  export RUST_LOG=info
  SECONDS=0
  timeout 10m nice -19 ./prove_stdio.sh $WITNESS test_only $BLOCK
  EXITCODE=$?
  DURATION=`date -u -d @"$SECONDS" +'%-Hh%-Mm%-Ss'`
  echo $DURATION
  if [ $EXITCODE -eq 0 ]
  then
    VERDICT="success"
  else
    VERDICT="failure"
  fi
  printf "%s %10i %s %3i %s\n" $GITHASH $BLOCK $VERDICT $EXITCODE $DURATION | tee -a witnesses/native_results.txt
done
