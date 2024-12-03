#!/usr/bin/env bash

set -exo

test_batch_size() {
  cargo --quiet run --release --bin leader -- --runtime in-memory -b $2 -n 1  --test-only --save-inputs-on-error stdio < $1.witness.json
}

main() {
  local NUM_TX=$(expr $(cast block $1 | wc -l) - 10)
  for BATCH_SIZE in $(seq $NUM_TX)
  do
    test_batch_size $1 $BATCH_SIZE
  done
}

main 748
