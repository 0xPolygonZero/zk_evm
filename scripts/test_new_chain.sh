#!/usr/bin/env bash

set -uo pipefail

RPC=${RPC_JERIGON_TESTCHAIN2}
if [ -z $RPC ]; then
  # You must set an RPC endpoint
  exit 1
fi

git diff --quiet --exit-code HEAD
if [ $? -ne 0  ]; then
  exit 1
fi

REPO_ROOT=$(git rev-parse --show-toplevel)

mkdir -p witnesses

RESULTS="witnesses/jerigon_new_chain.txt"
RESULT_LEN=$(cat $RESULTS | wc -l)
BLOCKS_TESTED=0


function statistics()
{
  PREFIX_LEN=$BLOCKS_TESTED
  wc -l $RESULTS
  cat $RESULTS | tail -n $PREFIX_LEN
  
  SUMOK=$(cat $RESULTS | tail -n $PREFIX_LEN | tr -s ' ' | cut -d' ' -f8  |  paste -s -d+ - | bc)
  SUMFAIL=$(cat $RESULTS | tail -n $PREFIX_LEN | tr -s ' ' | cut -d' ' -f9  |  paste -s -d+ - | bc)
  SUMTOTAL=$(cat $RESULTS | tail -n $PREFIX_LEN | tr -s ' ' | cut -d' ' -f10 |  paste -s -d+ - | bc)
  echo "Total transactions: " $SUMTOTAL
  echo "Transactions without prefetched JUMPDEST table: "$SUMFAIL
  echo "Failure rate: " $([[ $SUMTOTAL -eq 0 ]] && echo "0" || echo "$(($SUMFAIL * 100 / $SUMTOTAL))%")
  echo "Success rate: " $([[ $SUMTOTAL -eq 0 ]] && echo "0" || echo "$(($SUMOK * 100 / $SUMTOTAL))%")

  ZEROES=$(cat $RESULTS | tail -n $PREFIX_LEN | tr -s ' ' | cut -d' ' -f4 | grep --count "0")
  ONES=$(  cat $RESULTS | tail -n $PREFIX_LEN | tr -s ' ' | cut -d' ' -f4 | grep --count "1")
  TWOS=$(  cat $RESULTS | tail -n $PREFIX_LEN | tr -s ' ' | cut -d' ' -f4 | grep --count "2")
  THREES=$(cat $RESULTS | tail -n $PREFIX_LEN | tr -s ' ' | cut -d' ' -f4 | grep --count "3")
  FOURS=$(cat $RESULTS | tail -n $PREFIX_LEN | tr -s ' ' | cut -d' ' -f4 | grep --count "4")
  FIVES=$(cat $RESULTS | tail -n $PREFIX_LEN | tr -s ' ' | cut -d' ' -f4 | grep --count "5")
  SIXES=$(cat $RESULTS | tail -n $PREFIX_LEN | tr -s ' ' | cut -d' ' -f4 | grep --count "6")
  echo "Zeroes: " $ZEROES
  echo "Ones: " $ONES
  echo "Twos: " $TWOS
  echo "Threes: " $THREES
  echo "Fours: " $FOURS
  echo "Fives: " $FIVES
  echo "Sixes: " $SIXES
  echo "good bye"
  exit 0
}
trap statistics INT EXIT QUIT HUP TERM

#statistics
#exit 0

# Must match the values in prove_stdio.sh or build is dirty.
#export RAYON_NUM_THREADS=1
#export TOKIO_WORKER_THREADS=1
export RUST_BACKTRACE=full
#export RUST_LOG=info
#export RUSTFLAGS='-C target-cpu=native -Zlinker-features=-lld'
#export RUST_MIN_STACK=33554432

TIP=`cast block-number --rpc-url $RPC`
STATICTIP=6555

REPO_ROOT=$(git rev-parse --show-toplevel)

GITHASH=`git rev-parse --short HEAD`


nice -19 cargo build --release --bin rpc
nice -19 cargo build --release --bin leader


echo "Testing against jerigon testnet 2, current revision: $GITHASH."

#BLOCKS="$(seq $STATICTIP)"
BLOCKS="$(seq 6555)"
#BLOCKS=`echo $BLOCKS | tr ' ' '\n' | sort -nu | tr '\n' ' '`

echo "Testing:  $BLOCKS"



printf "\n\nr\n" | tee -a $RESULTS
echo "0 is success" | tee -a $RESULTS
echo "5 [defect] is non-matching jumpdest tables" | tee -a $RESULTS
echo "1 [unexpected] is other errors" | tee -a $RESULTS
echo "4 [expected] is Attempted to collapse an extension node" | tee -a $RESULTS
echo "6 [expected] is empty witness. Usually due to Error: Failed to get proof for account" | tee -a $RESULTS
echo "Report started: $(date)" | tee -a $RESULTS
printf "\ngithash       block verdict   r  rpc-time  test-time total-time  tx-ok tx-none tx-total \n" | tee -a $RESULTS
echo   "---------------------------------------------------------------------------------------"    | tee -a $RESULTS


for BLOCK in $BLOCKS; do
  TOTALTIME=0
  GITHASH=`git rev-parse --short HEAD`
  WITNESS="witnesses/$BLOCK.jerigon2.$GITHASH.witness.json"
  echo "Fetching block $BLOCK"
  export RUST_LOG=rpc=trace
  SECONDS=0
  nice -19 -- "${REPO_ROOT}/target/release/rpc" --backoff 3000 --max-retries 100 --rpc-url $RPC --rpc-type jerigon --jumpdest-src client-fetched-structlogs --timeout 120 fetch --start-block $BLOCK --end-block $BLOCK 1> $WITNESS
  TOTALTIME=`echo -n $(($TOTALTIME + $SECONDS))`
  DURATION_RPC=`date -u -d @"$SECONDS" +'%-Hh%-Mm%-Ss'`
  TXALL=`grep '"jumpdest_table":' $WITNESS | wc -l`
  TXNONE=`grep '"jumpdest_table": null' $WITNESS | wc -l`
  TXOK=`echo -n $(($TXALL - $TXNONE))`
  echo "Now testing block $BLOCK .."
  export RUST_LOG=info
  SECONDS=0
  timeout 2m nice -19 -- ./prove_stdio.sh $WITNESS test_only $BLOCK
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
  printf "%s %10i %s %3i  %8s   %8s   %8s    %3i     %3i      %3i \n" $GITHASH $BLOCK $VERDICT $EXITCODE $DURATION_RPC $DURATION_PRV $TOTALTIME $TXOK $TXNONE $TXALL | tee -a $RESULTS
  ((BLOCKS_TESTED+=1))


  ### Clean up
  TEST_OUT_PATH="${REPO_ROOT}/$BLOCK.test.out"
  rm $TEST_OUT_PATH
  rm $WITNESS

done

