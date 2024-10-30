#!/bin/bash

export LEADER_INPUT_JSON_FILE=$1

export  LEADER_BLOCK_BATCH_SIZE="${BLOCK_BATCH_SIZE:-8}"

REPO_ROOT=$(git rev-parse --show-toplevel)

export PROOF_OUTPUT_DIR="${REPO_ROOT}/proofs"
mkdir -p "$PROOF_OUTPUT_DIR"
chmod 777 "$PROOF_OUTPUT_DIR"

export DOCKER_CIRCUITS_CACHE_DIR="./docker_circuit_cache"
mkdir -p --mode=777 "$DOCKER_CIRCUITS_CACHE_DIR"
mkdir -p --mode=777 "$DOCKER_CIRCUITS_CACHE_DIR/worker1"
mkdir -p --mode=777 "$DOCKER_CIRCUITS_CACHE_DIR/worker2"

docker compose up