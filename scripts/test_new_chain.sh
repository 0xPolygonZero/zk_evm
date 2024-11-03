#!/usr/bin/env bash

set -uo pipefail

if [ -z $RPC ]; then
  echo You must set an RPC endpoint
  exit 1
fi

git diff --quiet --exit-code HEAD
if [ $? -ne 0  ]; then
  echo Uncommited changes, please commit to make githash consistent
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

  ZEROES=$(cat $RESULTS | tail -n $PREFIX_LEN | tr -s ' ' | cut -d' ' -f4 | grep --count "0")
  ONES=$(cat $RESULTS | tail -n $PREFIX_LEN | tr -s ' ' | cut -d' ' -f4 | grep --count "1")
  TWOS=$(cat $RESULTS | tail -n $PREFIX_LEN | tr -s ' ' | cut -d' ' -f4 | grep --count "2")
  THREES=$(cat $RESULTS | tail -n $PREFIX_LEN | tr -s ' ' | cut -d' ' -f4 | grep --count "3")
  FOURS=$(cat $RESULTS | tail -n $PREFIX_LEN | tr -s ' ' | cut -d' ' -f4 | grep --count "4")
  FIVES=$(cat $RESULTS | tail -n $PREFIX_LEN | tr -s ' ' | cut -d' ' -f4 | grep --count "5")
  SIXES=$(cat $RESULTS | tail -n $PREFIX_LEN | tr -s ' ' | cut -d' ' -f4 | grep --count "6")
  SEVENS=$(cat $RESULTS | tail -n $PREFIX_LEN | tr -s ' ' | cut -d' ' -f4 | grep --count "7")
  EIGHTS=$(cat $RESULTS | tail -n $PREFIX_LEN | tr -s ' ' | cut -d' ' -f4 | grep --count "8")
  NINES=$(cat $RESULTS | tail -n $PREFIX_LEN | tr -s ' ' | cut -d' ' -f4 | grep --count "9")
  TIMEOUTS=$(cat $RESULTS | tail -n $PREFIX_LEN | tr -s ' ' | cut -d' ' -f4 | grep --count "134")

  printf "\n\nStatistics\n" | tee -a $RESULTS
  echo   "---------------------------------------------------------------------------------------"    | tee -a $RESULTS
  echo "Total blocks: " $BLOCKS_TESTED | tee -a $RESULTS
  echo "Total transactions: " $SUMTOTAL | tee -a $RESULTS
  echo "Transactions without prefetched JUMPDEST table: "$SUMFAIL | tee -a $RESULTS
  echo "Failure rate: " $([[ $SUMTOTAL -eq 0 ]] && echo "0" || echo "$(($SUMFAIL * 100 / $SUMTOTAL))%") | tee -a $RESULTS
  echo "Success rate: " $([[ $SUMTOTAL -eq 0 ]] && echo "0" || echo "$(($SUMOK * 100 / $SUMTOTAL))%") | tee -a $RESULTS
  echo "Zeroes: " $ZEROES | tee -a $RESULTS
  echo "Ones: " $ONES | tee -a $RESULTS
  echo "Twos: " $TWOS | tee -a $RESULTS
  echo "Threes: " $THREES | tee -a $RESULTS
  echo "Fours: " $FOURS | tee -a $RESULTS
  echo "Fives: " $FIVES | tee -a $RESULTS
  echo "Sixes: " $SIXES | tee -a $RESULTS
  echo "Sevens: " $SEVENS | tee -a $RESULTS
  echo "Eights: " $EIGHTS | tee -a $RESULTS
  echo "Nines: " $NINES | tee -a $RESULTS
  echo "Timeouts: " $TIMEOUTS | tee -a $RESULTS
  echo "End of statistics" | tee -a $RESULTS
  exit 0
}
trap statistics INT EXIT # QUIT # HUP TERM

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

FAILING_BLOCKS1="
678
679
680
681
690
692
697
737
1178
1913
3010
3114
3115
3205
3206
3215
3265
3915
4076
4284
4285
4286
5282
5661
6086
6237
6321
6494
6495
"

FAILING_BLOCKS2="
678
679
680
681
690
692
697
737
3010
"


#BLOCKS="$(seq $STATICTIP)"
BLOCKS="$(seq 18 6555)"
#BLOCKS=$FAILING_BLOCKS1
#BLOCKS=`echo $BLOCKS | tr ' ' '\n' | sort -nu | tr '\n' ' '`

echo "Testing:  $BLOCKS"



printf "\n\nReport started: $(date)" | tee -a $RESULTS
printf "\n\nTable of exit codes\n" | tee -a $RESULTS
echo   "---------------------------------------------------------------------------------------"    | tee -a $RESULTS
echo "0 is success" | tee -a $RESULTS
echo "1 [unexpected] is other errors" | tee -a $RESULTS
echo "2 [unexpected] is undecided" | tee -a $RESULTS
echo "4 [expected] is Attempted to collapse an extension node" | tee -a $RESULTS
echo "5 [unexpected] is non-matching jumpdest tables" | tee -a $RESULTS
echo "6 [expected] is empty witness. Possibly due to Error: Failed to get proof for account" | tee -a $RESULTS
echo "7 [expected] is Found a Hash node during an insert in a PartialTrie" | tee -a $RESULTS
echo "8 [expected] is Attempted to delete a value that ended up inside a hash node" | tee -a $RESULTS
echo "9 [expected] is Memory allocation failed.  Increase RAM" | tee -a $RESULTS
echo "134 [undecided] is timeout.  Try increasing the proving timeout." | tee -a $RESULTS

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
  #timeout 600s
  nice -19 -- ./prove_stdio.sh $WITNESS test_only $BLOCK
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

  ### Clean up except when unknown error or undecided
  TEST_OUT_PATH="${REPO_ROOT}/$BLOCK.test.out"
  if [ $EXITCODE -ne 1 ] && [ $EXITCODE -ne 2 ]; then
    #rm $TEST_OUT_PATH
    #rm $WITNESS
    echo
  fi

done

