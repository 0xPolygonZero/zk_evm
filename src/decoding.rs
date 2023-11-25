use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Display, Formatter},
    iter::{empty, once},
    str::FromStr,
};

use eth_trie_utils::{
    nibbles::Nibbles,
    partial_trie::{HashedPartialTrie, Node, PartialTrie},
    trie_subsets::create_trie_subset,
};
use ethereum_types::{Address, H256, U256};
use hex_literal::hex;
use plonky2_evm::{
    generation::{mpt::AccountRlp, GenerationInputs, TrieInputs},
    proof::TrieRoots,
};
use thiserror::Error;

use crate::{
    processed_block_trace::{NodesUsedByTxn, ProcessedBlockTrace, StateTrieWrites, TxnMetaState},
    trace_protocol::TxnInfo,
    types::{
        BlockLevelData, Bloom, HashedAccountAddr, HashedNodeAddr, HashedStorageAddrNibbles,
        OtherBlockData, TrieRootHash, TxnIdx, TxnProofGenIR, EMPTY_ACCOUNT_BYTES_RLPED,
        EMPTY_TRIE_HASH, ZERO_STORAGE_SLOT_VAL_RLPED,
    },
    utils::{hash, update_val_if_some},
};

pub type TraceParsingResult<T> = Result<T, TraceParsingError>;

#[derive(Debug, Error)]
pub enum TraceParsingError {
    #[error("Failed to decode RLP bytes ({0}) as an Ethereum account due to the error: {1}")]
    AccountDecode(String, String),

    #[error("Missing account storage trie in base trie when constructing subset partial trie for txn (account: {0})")]
    MissingAccountStorageTrie(HashedAccountAddr),

    #[error("Tried accessing a non-existent key ({1}) in the {0} trie (root hash: {2:x})")]
    NonExistentTrieEntry(TrieType, Nibbles, TrieRootHash),

    // TODO: Figure out how to make this error useful/meaningful... For now this is just a
    // placeholder.
    #[error("Missing keys when creating sub-partial tries (Trie type: {0})")]
    MissingKeysCreatingSubPartialTrie(TrieType),
}

#[derive(Debug)]
pub enum TrieType {
    State,
    Storage,
    Receipt,
    Txn,
}

impl Display for TrieType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            TrieType::State => write!(f, "state"),
            TrieType::Storage => write!(f, "storage"),
            TrieType::Receipt => write!(f, "receipt"),
            TrieType::Txn => write!(f, "transaction"),
        }
    }
}

/// The current state of all tries as we process txn deltas. These are mutated
/// after every txn we process in the trace.
#[derive(Debug, Default)]
struct PartialTrieState {
    state: HashedPartialTrie,
    storage: HashMap<HashedAccountAddr, HashedPartialTrie>,
    txn: HashedPartialTrie,
    receipt: HashedPartialTrie,
}

impl ProcessedBlockTrace {
    pub(crate) fn into_txn_proof_gen_ir(
        self,
        other_data: OtherBlockData,
    ) -> TraceParsingResult<Vec<TxnProofGenIR>> {
        let mut curr_block_tries = PartialTrieState {
            state: self.tries.state.clone(),
            storage: self.tries.storage.clone(),
            ..Default::default()
        };

        // This is just a copy of `curr_block_tries`.
        let initial_tries_for_dummies = PartialTrieState {
            state: self.tries.state,
            storage: self.tries.storage,
            ..Default::default()
        };

        let mut tot_gas_used = U256::zero();
        let mut curr_bloom = Bloom::default();

        let mut txn_gen_inputs = self
            .txn_info
            .into_iter()
            .enumerate()
            .map(|(txn_idx, txn_info)| {
                let all_storage_roots = curr_block_tries
                    .state
                    .items()
                    .filter_map(|(a, v)| v.as_val().map(|v| (a, v.clone())))
                    .map(|(a, v)| (a, rlp::decode::<AccountRlp>(&v).unwrap().storage_root))
                    .collect::<Vec<_>>();

                let all_state_nodes = curr_block_tries
                    .state
                    .items()
                    .filter_map(|(a, v)| v.as_val().map(|v| (a, v.clone())))
                    .map(|(a, v)| (a, rlp::decode::<AccountRlp>(&v).unwrap()))
                    .map(|(a, d)| format!("{:x} --> {:#?}", a, d))
                    .collect::<Vec<_>>();

                println!("All state nodes: {:#?}", all_state_nodes);

                println!("All storage roots (before): {:#?}", all_storage_roots);

                println!("Full storage trie (before):");
                for (addr, trie) in curr_block_tries.storage.iter() {
                    println!("ALL (before) Storage slots for hashed addr {:x}:", addr);

                    let slots = trie
                        .items()
                        .map(|(k, v)| format!("{:x}: {:?}", k, v))
                        .collect::<Vec<_>>();
                    println!("----------");
                    println!("{:#?}", slots);
                    println!("----------\n");
                }

                let tries = Self::create_minimal_partial_tries_needed_by_txn(
                    &mut curr_block_tries,
                    &txn_info.nodes_used_by_txn,
                    txn_idx,
                    &other_data.b_data.b_meta.block_beneficiary,
                )?;

                let addresses = Self::get_known_addresses_if_enabled();

                let account_and_storage_hashes = curr_block_tries
                    .state
                    .items()
                    .filter_map(|(a, v)| v.as_val().map(|v| (a, v.clone())))
                    .map(|(a, v)| (a, rlp::decode::<AccountRlp>(&v).unwrap().storage_root))
                    .collect::<Vec<_>>();
                println!("{:#?}", account_and_storage_hashes);

                let new_tot_gas_used = tot_gas_used + txn_info.meta.gas_used;
                let new_bloom = txn_info.meta.block_bloom;

                Self::apply_deltas_to_trie_state(
                    &mut curr_block_tries,
                    txn_info.nodes_used_by_txn,
                    &txn_info.meta,
                    txn_idx,
                )?;

                // hacky_rpc_call_to_update_new_coinbase_balance(&mut curr_block_tries.state);

                // TODO: Clean up if this works...
                let trie_roots_after = TrieRoots {
                    state_root: curr_block_tries.state.hash(),
                    transactions_root: curr_block_tries.txn.hash(),
                    receipts_root: curr_block_tries.receipt.hash(),
                };

                println!("PARTIAL TRIES BEFORE: {:?}", tries);

                println!("TRIE ROOTS AFTER: {:?}", trie_roots_after);

                let gen_inputs = GenerationInputs {
                    txn_number_before: txn_idx.into(),
                    gas_used_before: tot_gas_used,
                    block_bloom_before: curr_bloom,
                    gas_used_after: new_tot_gas_used,
                    block_bloom_after: new_bloom,
                    signed_txn: txn_info.meta.txn_bytes,
                    withdrawals: Vec::new(), /* TODO: Once this is added to the trace spec, add
                                              * it here... */
                    tries,
                    trie_roots_after,
                    genesis_state_trie_root: EMPTY_TRIE_HASH, // TODO: fetch this on Jerigon side
                    contract_code: txn_info.contract_code_accessed,
                    block_metadata: other_data.b_data.b_meta.clone(),
                    block_hashes: other_data.b_data.b_hashes.clone(),
                    addresses,
                };

                println!("Code mapping: {:?}", gen_inputs.contract_code);

                let txn_proof_gen_ir = TxnProofGenIR {
                    txn_idx,
                    gen_inputs,
                };

                // println!("IR: {:#?}", txn_proof_gen_ir);

                tot_gas_used = new_tot_gas_used;
                curr_bloom = new_bloom;

                let all_storage_roots = curr_block_tries
                    .state
                    .items()
                    .filter_map(|(a, v)| v.as_val().map(|v| (a, v.clone())))
                    .map(|(a, v)| (a, rlp::decode::<AccountRlp>(&v).unwrap().storage_root))
                    .collect::<Vec<_>>();
                println!("All storage roots: {:#?}", all_storage_roots);

                println!(
                    "All state nodes: {:#?}",
                    curr_block_tries
                        .state
                        .keys()
                        .map(|k| format!("{:x}, {:x}", k, hash(&k.bytes_be())))
                        .collect::<Vec<_>>()
                );

                for (addr, trie) in curr_block_tries.storage.iter() {
                    println!("Storage slots for hashed addr {:x}:", addr);

                    let slots = trie.keys().map(|s| format!("{:x}", s)).collect::<Vec<_>>();
                    println!("----------");
                    println!("{:#?}", slots);
                    println!("----------");
                }

                Ok(txn_proof_gen_ir)
            })
            .collect::<TraceParsingResult<Vec<_>>>()?;

        Self::pad_gen_inputs_with_dummy_inputs_if_needed(
            &mut txn_gen_inputs,
            &other_data,
            &initial_tries_for_dummies,
        );
        Ok(txn_gen_inputs)
    }

    fn create_minimal_partial_tries_needed_by_txn(
        curr_block_tries: &mut PartialTrieState,
        nodes_used_by_txn: &NodesUsedByTxn,
        txn_idx: TxnIdx,
        coin_base_addr: &Address,
    ) -> TraceParsingResult<TrieInputs> {
        let hashed_coinbase = hash(coin_base_addr.as_bytes());

        // TODO: Remove once the full node adds this to the trace...
        let node_accesses_plus_coinbase = nodes_used_by_txn
            .state_accesses
            .iter()
            .cloned()
            .chain(once(hashed_coinbase));

        let state_trie = create_minimal_state_partial_trie(
            &curr_block_tries.state,
            node_accesses_plus_coinbase,
        )?;

        println!("SPECIAL QUERY ON PARTIAL");
        let res = state_trie.get(
            Nibbles::from_str("8556274a27dd7524955417c11ecd917251cc7c4c8310f4c7e4bd3c304d3d9a79")
                .unwrap(),
        );

        println!("SPECIAL QUERY ON PARTIAL RES: {:?}", res.map(hex::encode));

        let txn_k = Nibbles::from_bytes_be(&rlp::encode(&txn_idx)).unwrap();
        // TODO: Replace cast once `eth_trie_utils` supports `into` for `usize...
        let transactions_trie =
            create_trie_subset_wrapped(&curr_block_tries.txn, once(txn_k), TrieType::Txn)?;

        let receipts_trie =
            create_trie_subset_wrapped(&curr_block_tries.receipt, once(txn_k), TrieType::Receipt)?;

        let x = nodes_used_by_txn
            .storage_accesses
            .iter()
            .map(|(k, v)| (H256::from_slice(&k.bytes_be()), v.clone()))
            .collect::<Vec<_>>();

        let storage_tries = create_minimal_storage_partial_tries(
            &mut curr_block_tries.storage,
            &nodes_used_by_txn.state_accounts_with_no_accesses_but_storage_tries,
            x.iter(),
        )?;

        println!(
            "{:#?}",
            storage_tries
                .iter()
                .map(|(a, t)| format!("hashed account addr: {:x}: {}", a, t.keys().count()))
                .collect::<Vec<_>>()
        );
        Ok(TrieInputs {
            state_trie,
            transactions_trie,
            receipts_trie,
            storage_tries,
        })
    }

    fn get_accounts_with_no_storage_access_that_have_entries_in_state_trie(
        storage_accesses: &[(HashedAccountAddr, Vec<HashedStorageAddrNibbles>)],
        state_accesses: &[HashedNodeAddr],
    ) -> Vec<(HashedAccountAddr, Vec<HashedStorageAddrNibbles>)> {
        let storage_accesses_set: HashSet<HashedAccountAddr> =
            HashSet::from_iter(storage_accesses.iter().map(|(k, _)| k).cloned());
        state_accesses
            .iter()
            .filter(|h_addr| !storage_accesses_set.contains(h_addr))
            .map(|h_addr| (*h_addr, Vec::default()))
            .collect()
    }

    // It's not clear to me if the client should have an empty storage trie for when
    // a txn performs the accounts first storage access, but we're going to assume
    // they won't for now and deal with that case here.
    fn add_empty_storage_tries_that_appear_in_trace_but_not_pre_image(
        s_tries: &mut Vec<(HashedAccountAddr, HashedPartialTrie)>,
        txn_traces: &[TxnInfo],
    ) {
        // TODO: Make a bit more efficient...
        let all_addrs_that_access_storage_iter = txn_traces
            .iter()
            .flat_map(|x| x.traces.keys().map(|addr| hash(addr.as_bytes())));
        let addrs_with_storage_access_without_s_tries_iter: Vec<_> =
            all_addrs_that_access_storage_iter
                .filter(|addr| !s_tries.iter().any(|(a, _)| addr == a))
                .collect();

        s_tries.extend(
            addrs_with_storage_access_without_s_tries_iter
                .into_iter()
                .map(|k| (k, HashedPartialTrie::default())),
        );
    }

    fn apply_deltas_to_trie_state(
        trie_state: &mut PartialTrieState,
        deltas: NodesUsedByTxn,
        meta: &TxnMetaState,
        txn_idx: TxnIdx,
    ) -> TraceParsingResult<()> {
        println!("Applying deltas!");

        for (hashed_acc_addr, storage_writes) in deltas.storage_writes {
            let storage_trie = trie_state
                .storage
                .get_mut(&H256::from_slice(&hashed_acc_addr.bytes_be()))
                .ok_or(
                    TraceParsingError::MissingAccountStorageTrie(H256::zero()), // TODO!!! FIX
                )?;

            println!("Applying storage writes of {:?}", storage_writes);

            println!(
                "All storage slots before write apply: {:#?}",
                storage_trie
                    .keys()
                    .map(|k| format!("{:x}", k))
                    .collect::<Vec<_>>()
            );

            for (addr, write) in storage_writes.iter() {
                if storage_trie.get(*addr).is_none() {
                    println!(
                        "STORAGE SLOT CREATED! (h_account: {:x}) {:x} --> {}",
                        hashed_acc_addr,
                        addr,
                        hex::encode(write)
                    );
                }
            }

            for (slot, val) in storage_writes
                .into_iter()
                .map(|(k, v)| (Nibbles::from_h256_be(hash(&k.bytes_be())), v))
            {
                // If we are writing a zero, then we actually need to perform a delete.
                match val == ZERO_STORAGE_SLOT_VAL_RLPED {
                    false => storage_trie.insert(slot, val),
                    true => {
                        storage_trie.delete(slot);
                    }
                };
            }
        }

        for (hashed_acc_addr, s_trie_writes) in deltas.state_writes {
            let val_k = Nibbles::from_h256_be(hashed_acc_addr);

            // If the account was created, then it will not exist in the trie.
            let val_bytes = trie_state.state.get(val_k).unwrap_or_else(|| {
                println!("ACCOUNT CREATED DURING DELTA APPLY! {}", hashed_acc_addr);
                &EMPTY_ACCOUNT_BYTES_RLPED
            });

            println!(
                "Empty RLP account: {:?}",
                rlp::decode::<AccountRlp>(&EMPTY_ACCOUNT_BYTES_RLPED).unwrap()
            );

            let mut account: AccountRlp = rlp::decode(val_bytes).map_err(|err| {
                TraceParsingError::AccountDecode(hex::encode(val_bytes), err.to_string())
            })?;

            println!("Account for (before) {:x}: {:#?}", hashed_acc_addr, account);

            s_trie_writes.apply_writes_to_state_node(
                &mut account,
                &hashed_acc_addr,
                &trie_state.storage,
            )?;

            println!("Account for {:x}: {:#?}", hashed_acc_addr, account);

            let updated_account_bytes = rlp::encode(&account);
            trie_state
                .state
                .insert(val_k, updated_account_bytes.to_vec());
        }

        let txn_k = Nibbles::from_bytes_be(&rlp::encode(&txn_idx)).unwrap();
        trie_state.txn.insert(txn_k, meta.txn_bytes());

        // TODO: Re-evaluate if we can do this a bit nicer... Plonky2 needs this byte
        // but we don't want it for the receipt trie.
        let receipt_node_without_txn_type_byte = &meta.receipt_node_bytes[1..];

        trie_state
            .receipt
            .insert(txn_k, receipt_node_without_txn_type_byte);

        Ok(())
    }

    fn pad_gen_inputs_with_dummy_inputs_if_needed(
        gen_inputs: &mut Vec<TxnProofGenIR>,
        other_data: &OtherBlockData,
        initial_trie_state: &PartialTrieState,
    ) {
        println!("Padding len: {}", gen_inputs.len());

        match gen_inputs.len() {
            0 => {
                // Need to pad with two dummy txns.
                gen_inputs.extend(create_dummy_txn_pair_for_empty_block(
                    other_data,
                    initial_trie_state,
                ));
            }
            1 => {
                let dummy_txn = create_dummy_gen_input(other_data, initial_trie_state, 0);
                gen_inputs.insert(0, dummy_txn);
            }
            _ => (),
        }
    }

    // TODO: No idea how to implement this, so I'll come back to later...
    /// If there are known addresses, return them here.
    /// Only needed for debugging purposes.
    fn get_known_addresses_if_enabled() -> Vec<Address> {
        Vec::new() // TODO
    }
}

impl StateTrieWrites {
    fn apply_writes_to_state_node(
        &self,
        state_node: &mut AccountRlp,
        h_addr: &HashedAccountAddr,
        acc_storage_tries: &HashMap<HashedAccountAddr, HashedPartialTrie>,
    ) -> TraceParsingResult<()> {
        println!("Applying writes!");

        let storage_root_hash_change = match self.storage_trie_change {
            false => None,
            true => {
                let storage_trie = acc_storage_tries
                    .get(h_addr)
                    .ok_or(TraceParsingError::MissingAccountStorageTrie(*h_addr))?;

                Some(storage_trie.hash())
            }
        };

        if let Some(new_t) = storage_root_hash_change {
            println!("NEW STORAGE ROOT BEING APPLIED: {:x}", new_t);
        }

        update_val_if_some(&mut state_node.balance, self.balance);
        update_val_if_some(&mut state_node.nonce, self.nonce);
        update_val_if_some(&mut state_node.storage_root, storage_root_hash_change);
        update_val_if_some(&mut state_node.code_hash, self.code_hash);

        Ok(())
    }
}

fn calculate_trie_input_hashes(t_inputs: &TrieInputs) -> TrieRoots {
    TrieRoots {
        state_root: t_inputs.state_trie.hash(),
        transactions_root: t_inputs.transactions_trie.hash(),
        receipts_root: t_inputs.receipts_trie.hash(),
    }
}

fn create_dummy_txn_gen_input_single_dummy_txn(
    next_real_gen_input: &GenerationInputs,
    final_trie_state: &PartialTrieState,
) -> TxnProofGenIR {
    let partial_sub_storage_tries: Vec<_> = final_trie_state
        .storage
        .iter()
        .map(|(hashed_acc_addr, s_trie)| {
            (
                *hashed_acc_addr,
                create_fully_hashed_out_sub_partial_trie(s_trie),
            )
        })
        .collect();

    let state_trie = create_minimal_state_partial_trie(&final_trie_state.state, empty()).unwrap();

    let tries = TrieInputs {
        state_trie,
        transactions_trie: HashedPartialTrie::default(),
        receipts_trie: HashedPartialTrie::default(),
        storage_tries: partial_sub_storage_tries,
    };

    println!(
        "Orig trie hash: {:x}",
        next_real_gen_input.tries.state_trie.hash()
    );
    println!("State sub trie: {:#?}", tries.state_trie);

    assert_eq!(
        tries.state_trie.hash(),
        next_real_gen_input.trie_roots_after.state_root
    );
    println!(
        "{} == {}",
        tries.state_trie.hash(),
        next_real_gen_input.trie_roots_after.state_root
    );

    println!(
        "Fully hashed out dummy state trie: {:x}",
        tries.state_trie.hash()
    );

    let trie_roots_after = TrieRoots {
        state_root: next_real_gen_input.tries.state_trie.hash(),
        transactions_root: EMPTY_TRIE_HASH,
        receipts_root: EMPTY_TRIE_HASH,
    };

    let gen_inputs = GenerationInputs {
        txn_number_before: 0.into(),
        gas_used_before: 0.into(),
        gas_used_after: 0.into(),
        block_bloom_before: [0.into(); 8],
        block_bloom_after: [0.into(); 8],
        signed_txn: None,
        withdrawals: vec![],
        trie_roots_after,
        ..(next_real_gen_input.clone())
    };

    gen_inputs_to_ir(gen_inputs, 0)
}

// We really want to get a trie with just a hash node here, and this is an easy
// way to do it.
fn create_fully_hashed_out_sub_partial_trie(trie: &HashedPartialTrie) -> HashedPartialTrie {
    // Impossible to actually fail with an empty iter.
    create_trie_subset(trie, once(0_u64)).unwrap()
}

fn create_dummy_txn_pair_for_empty_block(
    other_data: &OtherBlockData,
    final_trie_state: &PartialTrieState,
) -> [TxnProofGenIR; 2] {
    [
        create_dummy_gen_input(other_data, final_trie_state, 0),
        create_dummy_gen_input(other_data, final_trie_state, 0),
    ]
}

fn create_dummy_gen_input(
    other_data: &OtherBlockData,
    final_trie_state: &PartialTrieState,
    txn_idx: TxnIdx,
) -> TxnProofGenIR {
    let tries = create_dummy_proof_trie_inputs(final_trie_state);

    let trie_roots_after = TrieRoots {
        state_root: tries.state_trie.hash(),
        transactions_root: EMPTY_TRIE_HASH,
        receipts_root: EMPTY_TRIE_HASH,
    };

    let gen_inputs = GenerationInputs {
        signed_txn: None,
        tries,
        trie_roots_after,
        // TODO: fetch this on Jerigon side
        genesis_state_trie_root: H256(hex!(
            "c12c57a1ecc38176fa8016fed174a23264e71d2166ea7e18cb954f0f3231e36a"
        )),
        block_metadata: other_data.b_data.b_meta.clone(),
        block_hashes: other_data.b_data.b_hashes.clone(),
        ..GenerationInputs::default()
    };

    gen_inputs_to_ir(gen_inputs, txn_idx)
}

impl TxnMetaState {
    fn txn_bytes(&self) -> Vec<u8> {
        match self.txn_bytes.as_ref() {
            Some(v) => v.clone(),
            None => Vec::default(),
        }
    }
}

fn gen_inputs_to_ir(gen_inputs: GenerationInputs, txn_idx: TxnIdx) -> TxnProofGenIR {
    TxnProofGenIR {
        txn_idx,
        gen_inputs,
    }
}

fn create_dummy_proof_trie_inputs(final_trie_state: &PartialTrieState) -> TrieInputs {
    let partial_sub_storage_tries: Vec<_> = final_trie_state
        .storage
        .iter()
        .map(|(hashed_acc_addr, s_trie)| {
            (
                *hashed_acc_addr,
                create_fully_hashed_out_sub_partial_trie(s_trie),
            )
        })
        .collect();

    TrieInputs {
        state_trie: create_fully_hashed_out_sub_partial_trie(&final_trie_state.state),
        transactions_trie: HashedPartialTrie::default(),
        receipts_trie: HashedPartialTrie::default(),
        storage_tries: partial_sub_storage_tries,
    }
}

fn create_minimal_state_partial_trie(
    state_trie: &HashedPartialTrie,
    state_accesses: impl Iterator<Item = HashedNodeAddr>,
) -> TraceParsingResult<HashedPartialTrie> {
    create_trie_subset_wrapped(
        state_trie,
        state_accesses.map(Nibbles::from_h256_be),
        TrieType::State,
    )
}

// TODO!!!: We really need to be appending the empty storage tries to the base
// trie somewhere else! This is a big hack!
fn create_minimal_storage_partial_tries<'a>(
    storage_tries: &mut HashMap<HashedAccountAddr, HashedPartialTrie>,
    state_accounts_with_no_accesses_but_storage_tries: &HashMap<HashedAccountAddr, TrieRootHash>,
    accesses_per_account: impl Iterator<Item = &'a (HashedAccountAddr, Vec<HashedStorageAddrNibbles>)>,
) -> TraceParsingResult<Vec<(HashedAccountAddr, HashedPartialTrie)>> {
    println!(
        "BASE TRIES KEYS: {:#?}",
        storage_tries.keys().collect::<Vec<_>>()
    );

    accesses_per_account
        .map(|(h_addr, mem_accesses)| {
            // TODO: Clean up...
            let base_storage_trie = match storage_tries.get(&H256(h_addr.0)) {
                Some(s_trie) => s_trie,
                None => {
                    let trie = state_accounts_with_no_accesses_but_storage_tries
                        .get(h_addr)
                        .map(|s_root| HashedPartialTrie::new(Node::Hash(*s_root)))
                        .unwrap_or_default();
                    storage_tries.insert(*h_addr, trie); // TODO: Really change this...
                    storage_tries.get(h_addr).unwrap()
                }
            };

            let partial_storage_trie = create_trie_subset_wrapped(
                base_storage_trie,
                mem_accesses.iter().cloned(),
                TrieType::Storage,
            )?;

            Ok((*h_addr, partial_storage_trie))
        })
        .collect::<TraceParsingResult<_>>()
}

fn create_trie_subset_wrapped(
    trie: &HashedPartialTrie,
    accesses: impl Iterator<Item = Nibbles>,
    trie_type: TrieType,
) -> TraceParsingResult<HashedPartialTrie> {
    create_trie_subset(trie, accesses)
        .map_err(|_| TraceParsingError::MissingKeysCreatingSubPartialTrie(trie_type))
}
