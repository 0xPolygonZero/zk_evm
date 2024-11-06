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
trap statistics EXIT # INT QUIT # HUP TERM

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


nice -19 cargo build --release --quiet --bin rpc
nice -19 cargo build --release --quiet --bin leader


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

FAILING_BLOCKS3="
678
679
680
681
697
737
1178
1913
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
5571
5572
5588
5592
5595
5604
5608
5617
5619
5632
5634
5636
5639
5644
5645
5648
5651
5660
5661
5662
5666
5675
5678
6082
6086
6088
6097
6098
6099
6100
6101
6107
6108
6110
6111
6113
6114
6115
6117
6118
6120
6162
6164
6169
6170
6174
6175
6176
6177
6178
6181
6183
6184
6186
6187
6188
6189
6222
6224
6225
6226
6227
6231
6232
6236
6240
6241
6243
6244
6256
6258
6259
6260
6262
6263
6265
6266
6267
6268
6271
6274
6277
6280
6284
6288
6289
6290
6291
6293
6294
6295
6296
6297
6298
6299
6300
6301
6302
6303
6304
6305
6306
6307
6309
6311
6312
6313
6314
6315
6316
6317
6318
6319
6320
6322
6325
6326
6327
6329
6331
6332
6333
6334
6335
6336
6337
6338
6339
6340
6342
6344
6345
6348
6349
6350
6351
6352
6353
6355
6356
6359
6360
6362
6363
6364
6365
6367
6368
6369
6370
6371
6377
6378
6386
6387
6388
6391
6393
6394
6395
6396
6397
6398
6402
6403
6406
6407
6415
6416
6417
6418
6422
6423
6424
6425
6426
6428
6429
6430
6431
6433
6434
6435
6436
6437
6439
6442
6444
6445
6447
6450
6451
6452
6454
6455
6456
6457
6458
6459
6461
6462
6463
6472
6474
6476
6477
6478
6481
6483
6484
6485
6486
6487
6488
6490
6491
6493
6494
6495
6498
6499
6501
6503
6504
6505
6508
6513
6514
6515
"

#BLOCKS="$(seq $STATICTIP)"
#BLOCKS="$(seq 6555)"
BLOCKS=$FAILING_BLOCKS3
BLOCKS=`echo $BLOCKS | tr ' ' '\n' | sort -nu | tr '\n' ' '`

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
  nice -19 -- "${REPO_ROOT}/target/release/rpc" --backoff 3000 --max-retries 100 --rpc-url $RPC --rpc-type jerigon --jumpdest-src client-fetched-structlogs --timeout 600 fetch --start-block $BLOCK --end-block $BLOCK 1> $WITNESS
  TOTALTIME=`echo -n $(($TOTALTIME + $SECONDS))`
  DURATION_RPC=`date -u -d @"$SECONDS" +'%-Hh%-Mm%-Ss'`
  TXALL=`grep '"jumpdest_table":' $WITNESS | wc -l`
  TXNONE=`grep '"jumpdest_table": null' $WITNESS | wc -l`
  TXOK=`echo -n $(($TXALL - $TXNONE))`
  echo "Now testing block $BLOCK .."
  export RUST_LOG=info
  SECONDS=0
  timeout 5h nice -19 -- ./prove_stdio.sh $WITNESS test_only $BLOCK
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

