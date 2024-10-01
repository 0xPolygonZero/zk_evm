#!/usr/bin/env bash

set -uo pipefail

RPC=${RPC_JERIGON}
if [ -z $RPC ]; then
  # You must set an RPC endpoint
  exit 1
fi
mkdir -p witnesses

# Must match the values in prove_stdio.sh or build is dirty.
export RAYON_NUM_THREADS=1
export TOKIO_WORKER_THREADS=1
export RUST_BACKTRACE=full
#export RUST_LOG=info
#export RUSTFLAGS='-C target-cpu=native -Zlinker-features=-lld'
#export RUST_MIN_STACK=67108864

GITHASH=`git rev-parse --short HEAD`
echo "Testing against jergion, current revision: $GITHASH."

CIBLOCKS="
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


STILLFAIL="
37
75
15
35
43
72
77
184
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
477
478
444
"

JUMPI="
662
664
665
667
670
"

CONTAINSKEY="
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
72
"

CREATE2="
43
566
77
"

DECODING="
477
478
"

USEDTOFAIL="
2
15
28
35
37
43
65

28

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

ROUND2="
664
667
670
665
"

NOWSUCCESS="
444
4
5
28
65
566
15
35
"

ROUND3="
125
127
131
132
136
141
142
143
145
149
150
151
153
154
186
187
188
190
193
195
197
199
201
214
220
221
222
223
226
228
229
230
231
232
234
242
256
257
258
262
264
267
268
282
284
285
287
292
294
295
301
303
304
321
325
333
460
461
462
463
464
465
466
467
468
473
474
528
529
530
531
532
533
534
566
570
664
77
548
"

ROUND4="
136
186
268
282
301
304
321
333
460
461
462
463
464
465
466
467
468
473
474
528
529
530
531
532
533
534
570
664
"

ROUND5="
460
461
462
463
464
465
466
467
468
473
474
664
"

ROUND6="
664
"

# 470..663 from Robin
for i in {470..663}
do
  ROBIN+=" $i"
done

TIP=688
NUMRANDOMBLOCKS=10
RANDOMBLOCKS=`shuf --input-range=0-$TIP -n $NUMRANDOMBLOCKS | sort`

#$CREATE2 $DECODING $CONTAINSKEY $USEDTOFAIL $STILLFAIL $CIBLOCKS $JUMPI $ROUND2 $RANDOMBLOCKS $ROUND3" 
BLOCKS="$ROUND6"
BLOCKS=`echo $BLOCKS | tr ' ' '\n' | sort -nu | tr '\n' ' '`

echo "Testing:  $BLOCKS"
printf "\ngithash       block verdict duration\n" | tee -a witnesses/jerigon_results.txt
echo   "------------------------------------"   | tee -a witnesses/jerigon_results.txt

for BLOCK in $BLOCKS; do
  GITHASH=`git rev-parse --short HEAD`
  WITNESS="witnesses/$BLOCK.jerigon.$GITHASH.witness.json"
  echo "Fetching block $BLOCK"
  export RUST_LOG=rpc=trace
  SECONDS=0
  cargo run --quiet --release --bin rpc -- --backoff 3000 --max-retries 100 --rpc-url $RPC --rpc-type jerigon --jumpdest-src client-fetched-structlogs fetch  --start-block $BLOCK --end-block $BLOCK 1> $WITNESS
  echo "Testing blocks: $BLOCKS."
  echo "Now testing block $BLOCK .."
  export RUST_LOG=info
  timeout 10m ./prove_stdio.sh $WITNESS test_only $BLOCK
  EXITCODE=$?
  DURATION=`date -u -d @"$SECONDS" +'%-Hh%-Mm%-Ss'`
  echo $DURATION
  if [ $EXITCODE -eq 0 ]
  then
    VERDICT="success"
  else
    VERDICT="failure"
  fi
  printf "%s %10i %s %s\n" $GITHASH $BLOCK $VERDICT $DURATION | tee -a witnesses/jerigon_results.txt
done
