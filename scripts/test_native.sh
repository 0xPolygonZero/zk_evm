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

ROUND6="
19426872
19427018
19427388
19427472
19429634
19430273
19430687
19430855
19431223
19431344
19432360
19432641
19435607
19435804
19436307
19439155
19439754
19440665
19441789
19443628
19443673
19444327
19444582
19445175
19445286
19445799
19446774
19446911
19447598
19447814
19448687
19449229
19449755
19450491
19451118
19451955
19452325
19452532
19452795
19452869
19454136
19455621
19456052
19456615
19460281
19460945
19462377
19463186
19464727
19466034
19466036
19466108
19466509
"

ROUND7="
19430273
19431344
19451118
19452869
19460945
19464727
19466034
"

ROUND8="
19657436
19508991
19500774
19794433
"

CANCUN=19426587
TIP=`cast block-number --rpc-url $RPC`
STATICTIP=20978815
NUMRANDOMBLOCKS=1000
RANDOMBLOCKS=`shuf --input-range=$CANCUN-$TIP -n $NUMRANDOMBLOCKS | sort`

REPO_ROOT=$(git rev-parse --show-toplevel)

GITHASH=`git rev-parse --short HEAD`
echo "Testing against mainnet, current revision: $GITHASH."

#BLOCKS="$CANCUNBLOCKS $RANDOMBLOCKS $ROUND3"
#BLOCKS="$RANDOMBLOCKS"
BLOCKS="$ROUND8"
BLOCKS=`echo $BLOCKS | tr ' ' '\n' | sort -nu | tr '\n' ' '`
echo "Testing blocks: $BLOCKS"

echo "Testing:  $BLOCKS"

printf "\n\nr\n" | tee -a witnesses/native_results.txt
echo "0 is success" | tee -a witnesses/native_results.txt
echo "5 [defect] is non-matching jumpdest tables" | tee -a witnesses/native_results.txt
echo "1 [unexpected] is other errors" | tee -a witnesses/native_results.txt
echo "4 [expected] is Attempted to collapse an extension node" | tee -a witnesses/native_results.txt
echo "6 [expected] is empty witness. Usually due to Error: Failed to get proof for account" | tee -a witnesses/native_results.txt
echo "Report started: $(date)" | tee -a witnesses/native_results.txt
printf "\ngithash       block verdict   r  rpc-time  test-time total-time  tx-ok tx-none tx-total \n" | tee -a witnesses/native_results.txt
echo   "---------------------------------------------------------------------------------------"    | tee -a witnesses/native_results.txt

for BLOCK in $BLOCKS; do
  TOTALTIME=0
  GITHASH=`git rev-parse --short HEAD`
  WITNESS="witnesses/$BLOCK.native.$GITHASH.witness.json"
  echo "Fetching block $BLOCK"
  export RUST_LOG=rpc=trace
  SECONDS=0
  nice -19 cargo run --quiet --release --bin rpc -- --backoff 3000 --max-retries 100 --rpc-url $RPC --rpc-type native --jumpdest-src client-fetched-structlogs --timeout 600 fetch --start-block $BLOCK --end-block $BLOCK 1> $WITNESS
  TOTALTIME=`echo -n $(($TOTALTIME + $SECONDS))`
  DURATION_RPC=`date -u -d @"$SECONDS" +'%-Hh%-Mm%-Ss'`
  TXALL=`grep '"jumpdest_table":' $WITNESS | wc -l`
  TXNONE=`grep '"jumpdest_table": null' $WITNESS | wc -l`
  TXOK=`echo -n $(($TXALL - $TXNONE))`
  TEST_OUT_PATH="${REPO_ROOT}/$BLOCK.test.out"
  #rm $TEST_OUT_PATH
  echo "Now testing block $BLOCK .."
  export RUST_LOG=info
  SECONDS=0
  timeout 10m nice -19 ./prove_stdio.sh $WITNESS test_only $BLOCK
  EXITCODE=$?
  TOTALTIME=`echo -n $(($TOTALTIME + $SECONDS))`
  DURATION_PRV=`date -u -d @"$SECONDS" +'%-Hh%-Mm%-Ss'`
  TOTALTIME=`date -u -d @"$TOTALTIME" +'%-Hh%-Mm%-Ss'`
  if [ $EXITCODE -eq 0 ]
  then
    VERDICT="success"
  else
    VERDICT="failure"
  fi
  printf "%s %10i %s %3i  %8s   %8s   %8s    %3i     %3i      %3i \n" $GITHASH $BLOCK $VERDICT $EXITCODE $DURATION_RPC $DURATION_PRV $TOTALTIME $TXOK $TXNONE $TXALL | tee -a witnesses/native_results.txt
done
