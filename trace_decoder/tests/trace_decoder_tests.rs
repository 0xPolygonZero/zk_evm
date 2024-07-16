//! These tests rely on the jerigon and cdk erigon witness files as input
//! To add a new block or range of blocks as test input, do the following:
//! 1. Run rpc tool to fetch block witness:
//!```
//!     cargo run --bin rpc fetch --rpc-url <node_rpc_endpoint> --start-block <start> --end-block <end> ./b<number>_<network>.json
//! ```
//! 2. Download the header file for the block or range of blocks:
//!```
//!     file_name = b<number>_<network>_header.json
//!     echo "[" > $file_name && cast rpc eth_getBlockByNumber "0x<block_number>" 'false' --rpc-url <node_rpc_endpoint>  >> $file_name && echo "]" >> $file_name
//! ```

use std::time::Duration;
use std::{
    fs,
    path::{Path, PathBuf},
};

use alloy_rpc_types_eth::Header;
use anyhow::Context as _;
use evm_arithmetization::prover::testing::simulate_execution;
use evm_arithmetization::GenerationInputs;
use itertools::Itertools;
use log::{info, warn};
use mpt_trie::partial_trie::PartialTrie;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::util::timing::TimingTree;
use plonky2_maybe_rayon::*;
use pretty_env_logger::env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
use prover::BlockProverInput;
use rstest::rstest;
use trace_decoder::OtherBlockData;

type F = GoldilocksField;

const JERIGON_WITNESS_DIR: &str = "tests/data/witnesses/zero_jerigon";
const CDK_ERIGON_WITNESS_DIR: &str = "tests/data/witnesses/hermez_cdk_erigon";

enum JsonFileType {
    Witness,
}

fn init_logger() {
    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "info"));
}

fn find_json_data_files(dir: &str, file_type: JsonFileType) -> anyhow::Result<Vec<PathBuf>> {
    let read_dir = fs::read_dir(dir)?;
    read_dir
        .into_iter()
        .map(|dir_entry| dir_entry.map(|it| it.path()))
        .filter_ok(|path| match file_type {
            JsonFileType::Witness => !path
                .to_str()
                .expect("valid str file path")
                .contains("header"),
        })
        .collect::<Result<Vec<_>, _>>()
        .context(format!("Failed to find witness files in dir {dir}"))
}

fn read_witness_file(file_path: &Path) -> anyhow::Result<Vec<BlockProverInput>> {
    let witness = fs::File::open(file_path).context("Unable to read file")?;
    let mut reader = std::io::BufReader::new(witness);
    let jd = &mut serde_json::Deserializer::from_reader(&mut reader);
    serde_path_to_error::deserialize(jd).context(format!(
        "Failed to deserialize json file {}",
        file_path.display()
    ))
}

fn decode_generation_inputs(
    block_prover_input: BlockProverInput,
) -> anyhow::Result<Vec<GenerationInputs>> {
    let block_num = block_prover_input.other_data.b_data.b_meta.block_number;
    let trace_decoder_output = trace_decoder::entrypoint(
        block_prover_input.block_trace,
        block_prover_input.other_data.clone(),
        |_| unimplemented!(),
    )
    .context(format!(
        "Failed to execute trace decoder on block {}",
        block_num
    ))?
    .into_iter()
    .collect::<Vec<GenerationInputs>>();
    Ok(trace_decoder_output)
}

fn verify_generation_inputs(
    header: &Header,
    other: &OtherBlockData,
    generation_inputs: Vec<GenerationInputs>,
) -> anyhow::Result<()> {
    if generation_inputs.is_empty() {
        warn!("Empty generation inputs list");
        return Ok(());
    }
    assert_eq!(
        other.checkpoint_state_trie_root,
        generation_inputs
            .first()
            .expect("generation inputs should have first element")
            .tries
            .state_trie
            .hash()
    );
    assert!(generation_inputs
        .windows(2)
        .map(|inputs| {
            inputs[0].trie_roots_after.state_root == inputs[1].tries.state_trie.hash()
                && inputs[0].trie_roots_after.receipts_root == inputs[1].tries.receipts_trie.hash()
                && inputs[0].trie_roots_after.transactions_root
                    == inputs[1].tries.transactions_trie.hash()
        })
        .all(|it| it));
    let last_generation_input = generation_inputs
        .last()
        .expect("generation inputs should have last element");
    assert_eq!(
        last_generation_input.trie_roots_after.state_root.0,
        header.state_root.0
    );
    // Some block metadata sanity checks
    assert_eq!(
        last_generation_input
            .block_metadata
            .block_timestamp
            .as_u64(),
        header.timestamp
    );
    // Block hash check
    assert_eq!(
        last_generation_input.block_hashes.cur_hash.as_bytes(),
        &header.hash.unwrap().to_vec()
    );
    // Previous block hash check
    assert_eq!(
        last_generation_input
            .block_hashes
            .prev_hashes
            .last()
            .expect("Valid last hash")
            .as_bytes(),
        &header.parent_hash.to_vec()
    );
    info!(
        "Block {} GenerationInputs valid",
        other.b_data.b_meta.block_number
    );
    Ok(())
}

/// This test aims at ensuring that the decoder can properly parse a block trace
/// received from Jerigon and CDK Erigon into zkEVM `GenerationInputs`, which
/// the prover can then pick to prove each transaction in the block
/// independently.
///
/// This test only `simulates` the zkEVM CPU, i.e. does not generate STARK
/// traces nor generates proofs, as its purpose is to be runnable easily in the
/// CI even in `debug` mode.
#[rstest]
#[case(JERIGON_WITNESS_DIR)]
#[case(CDK_ERIGON_WITNESS_DIR)]
fn test_parsing_decoding_proving(#[case] test_witness_directory: &str) {
    init_logger();

    let results = find_json_data_files(test_witness_directory, JsonFileType::Witness)
        .expect("valid json data files found")
        .into_iter()
        .map(|file_path| {
            {
                // Read one json witness file for this block and get list of BlockProverInputs
                read_witness_file(&file_path)
            }
        })
        .map_ok(|block_prover_inputs| {
            block_prover_inputs.into_iter().map(|block_prover_input| {
                // Run trace decoder, create list of generation inputs
                let block_generation_inputs = decode_generation_inputs(block_prover_input)?;
                block_generation_inputs
                    .into_par_iter()
                    .map(|generation_inputs| {
                        // For every generation input, simulate execution.
                        // Execution will be simulated in parallel
                        let timing = TimingTree::new(
                            &format!(
                                "Simulating zkEVM CPU for block {} txn {:?}",
                                generation_inputs.block_metadata.block_number,
                                generation_inputs.txn_number_before
                            ),
                            log::Level::Info,
                        );
                        simulate_execution::<F>(generation_inputs)?;
                        timing.filter(Duration::from_millis(100)).print();
                        Ok::<(), anyhow::Error>(())
                    })
                    .collect::<Result<Vec<_>, anyhow::Error>>()
            })
        })
        .flatten_ok()
        .map(|it| it?)
        .collect::<Vec<Result<_, anyhow::Error>>>();

    results.iter().for_each(|it| {
        if let Err(e) = it {
            panic!("Failed to run parsing decoding proving test: {e:?}");
        }
    });
}

/// This test checks for the parsing and decoding of the block witness
/// received from Jerigon and CDK Erigon into zkEVM `GenerationInputs`, and
/// checks if trace decoder output generation inputs are valid and consistent
#[rstest]
#[case(JERIGON_WITNESS_DIR)]
#[case(CDK_ERIGON_WITNESS_DIR)]
fn test_generation_inputs_consistency(#[case] test_witness_directory: &str) {
    init_logger();

    let result: Vec<Result<(), anyhow::Error>> =
        find_json_data_files(test_witness_directory, JsonFileType::Witness)
            .expect("valid json data files found")
            .into_iter()
            .map(|file_path| {
                {
                    // Read json header file of the block. We need it to check tracer output
                    // consistency
                    let mut header_file_path = file_path.clone();
                    header_file_path.set_extension("");
                    let mut block_header_file_name = header_file_path
                        .file_name()
                        .expect("valid header file name")
                        .to_os_string();
                    block_header_file_name.push("_header.json");
                    header_file_path.set_file_name(block_header_file_name);
                    let header_file = fs::File::open(header_file_path.as_path()).context(
                        format!("Unable to open header file {}", header_file_path.display()),
                    )?;
                    let mut header_reader = std::io::BufReader::new(header_file);
                    let block_header = serde_json::from_reader::<_, Vec<Header>>(
                        &mut header_reader,
                    )
                    .context(format!(
                        "Failed to deserialize header json file {}",
                        header_file_path.display()
                    ))?;
                    // Read one json witness file and get list of BlockProverInputs
                    let block_prover_inputs = read_witness_file(&file_path)?;
                    Ok(block_header
                        .into_iter()
                        .zip(block_prover_inputs.into_iter()))
                }
            })
            .flatten_ok()
            .map_ok(|(block_header, block_prover_input)| {
                let other_block_data = block_prover_input.other_data.clone();
                // Run trace decoder, create generation inputs for this block
                let block_generation_inputs = decode_generation_inputs(block_prover_input)?;
                // Verify generation inputs for this block
                verify_generation_inputs(&block_header, &other_block_data, block_generation_inputs)
            })
            .map(|it: Result<Result<(), anyhow::Error>, anyhow::Error>| it?)
            .collect();

    result.iter().for_each(|it| {
        if let Err(e) = it {
            panic!("Failed to verify generation inputs consistency: {e:?}");
        }
    });
}
