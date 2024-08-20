use core::ops::Deref;
use std::collections::HashMap;
use std::hash::Hash;

use bytes::Bytes;
use ethereum_types::{Address, BigEndianHash, H256, U256};
use keccak_hash::keccak;
use mpt_trie::nibbles::{Nibbles, NibblesIntern, ToNibbles};
use mpt_trie::partial_trie::{HashedPartialTrie, PartialTrie};
use rlp::{Decodable, DecoderError, Encodable, PayloadInfo, Rlp, RlpStream};
use rlp_derive::{RlpDecodable, RlpEncodable};
use serde::{Deserialize, Serialize};

use super::linked_list::{empty_list_mem, LinkedList};
use super::prover_input::{ACCOUNTS_LINKED_LIST_NODE_SIZE, STORAGE_LINKED_LIST_NODE_SIZE};
use super::TrimmedTrieInputs;
use crate::cpu::kernel::constants::trie_type::PartialTrieType;
use crate::generation::TrieInputs;
use crate::memory::segments::Segment;
use crate::util::{h2u, u256_to_usize};
use crate::witness::errors::{ProgramError, ProverInputError};
use crate::Node;

#[derive(RlpEncodable, RlpDecodable, Debug)]
pub struct AccountRlp {
    pub nonce: U256,
    pub balance: U256,
    pub storage_root: H256,
    pub code_hash: H256,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TrieRootPtrs {
    pub state_root_ptr: Option<usize>,
    pub txn_root_ptr: usize,
    pub receipt_root_ptr: usize,
}

impl Default for AccountRlp {
    fn default() -> Self {
        Self {
            nonce: U256::zero(),
            balance: U256::zero(),
            storage_root: HashedPartialTrie::from(Node::Empty).hash(),
            code_hash: keccak([]),
        }
    }
}

#[derive(RlpEncodable, RlpDecodable, Debug, Clone)]
pub struct LogRlp {
    pub address: Address,
    pub topics: Vec<H256>,
    pub data: Bytes,
}

#[derive(RlpEncodable, RlpDecodable, Debug, Clone)]
pub struct LegacyReceiptRlp {
    pub status: bool,
    pub cum_gas_used: U256,
    pub bloom: Bytes,
    pub logs: Vec<LogRlp>,
}

impl LegacyReceiptRlp {
    // RLP encode the receipt and prepend the tx type.
    pub fn encode(&self, tx_type: u8) -> Vec<u8> {
        let mut bytes = rlp::encode(self).to_vec();
        if tx_type != 0 {
            bytes.insert(0, tx_type);
        }
        bytes
    }
}

pub(crate) fn parse_receipts(rlp: &[u8]) -> Result<Vec<U256>, ProgramError> {
    let txn_type = match rlp.first().ok_or(ProgramError::InvalidRlp)? {
        1 => 1,
        2 => 2,
        _ => 0,
    };

    // If this is not a legacy transaction, we skip the leading byte.
    let rlp = if txn_type == 0 { rlp } else { &rlp[1..] };

    let payload_info = PayloadInfo::from(rlp).map_err(|_| ProgramError::InvalidRlp)?;
    let decoded_receipt: LegacyReceiptRlp =
        rlp::decode(rlp).map_err(|_| ProgramError::InvalidRlp)?;

    let mut parsed_receipt = if txn_type == 0 {
        Vec::new()
    } else {
        vec![txn_type.into()]
    };

    parsed_receipt.push(payload_info.value_len.into()); // payload_len of the entire receipt
    parsed_receipt.push((decoded_receipt.status as u8).into());
    parsed_receipt.push(decoded_receipt.cum_gas_used);
    parsed_receipt.extend(decoded_receipt.bloom.iter().map(|byte| U256::from(*byte)));
    let encoded_logs = rlp::encode_list(&decoded_receipt.logs);
    let logs_payload_info =
        PayloadInfo::from(&encoded_logs).map_err(|_| ProgramError::InvalidRlp)?;
    parsed_receipt.push(logs_payload_info.value_len.into()); // payload_len of all the logs
    parsed_receipt.push(decoded_receipt.logs.len().into());

    for log in decoded_receipt.logs {
        let encoded_log = rlp::encode(&log);
        let log_payload_info =
            PayloadInfo::from(&encoded_log).map_err(|_| ProgramError::InvalidRlp)?;
        parsed_receipt.push(log_payload_info.value_len.into()); // payload of one log
        parsed_receipt.push(U256::from_big_endian(&log.address.to_fixed_bytes()));
        parsed_receipt.push(log.topics.len().into());
        parsed_receipt.extend(log.topics.iter().map(|topic| U256::from(topic.as_bytes())));
        parsed_receipt.push(log.data.len().into());
        parsed_receipt.extend(log.data.iter().map(|byte| U256::from(*byte)));
    }

    Ok(parsed_receipt)
}

fn parse_storage_value(value_rlp: &[u8]) -> Result<Vec<U256>, ProgramError> {
    let value: U256 = rlp::decode(value_rlp).map_err(|_| ProgramError::InvalidRlp)?;
    Ok(vec![value])
}

const fn empty_nibbles() -> Nibbles {
    Nibbles {
        count: 0,
        packed: NibblesIntern::zero(),
    }
}

fn load_mpt<F>(
    trie: &HashedPartialTrie,
    key: Nibbles,
    trie_data: &mut Vec<Option<U256>>,
    parse_value: &F,
) -> Result<usize, ProgramError>
where
    F: Fn(&[u8]) -> Result<Vec<U256>, ProgramError>,
{
    let node_ptr = trie_data.len();
    let type_of_trie = PartialTrieType::of(trie) as u32;
    if type_of_trie > 0 {
        trie_data.push(Some(type_of_trie.into()));
    }

    match trie.deref() {
        Node::Empty => Ok(0),
        Node::Hash(h) => {
            trie_data.push(Some(U256::zero())); // Set flag is_account to 0
            trie_data.push(Some(
                key.try_into().map_err(|_| ProgramError::IntegerTooLarge)?,
            ));
            trie_data.push(Some(h2u(*h)));
            Ok(node_ptr)
        }
        Node::Branch { children, value } => {
            // First, set children pointers to 0.
            let first_child_ptr = trie_data.len();
            trie_data.extend(vec![Some(U256::zero()); 16]);
            // Then, set value.
            if value.is_empty() {
                trie_data.push(Some(U256::zero()));
            } else {
                let parsed_value = parse_value(value)?.into_iter().map(Some);
                trie_data.push(Some((trie_data.len() + 1).into()));
                trie_data.extend(parsed_value);
            }

            // Now, load all children and update their pointers.
            for (i, child) in children.iter().enumerate() {
                let extended_key = key.merge_nibbles(&Nibbles {
                    count: 1,
                    packed: i.into(),
                });
                let child_ptr = load_mpt(child, extended_key, trie_data, parse_value)?;
                trie_data[first_child_ptr + i] = Some(child_ptr.into());
            }

            Ok(node_ptr)
        }

        Node::Extension { nibbles, child } => {
            trie_data.push(Some(nibbles.count.into()));
            trie_data.push(Some(
                nibbles
                    .try_into()
                    .map_err(|_| ProgramError::IntegerTooLarge)?,
            ));
            trie_data.push(Some((trie_data.len() + 1).into()));

            let extended_key = key.merge_nibbles(nibbles);
            let child_ptr = load_mpt(child, extended_key, trie_data, parse_value)?;
            if child_ptr == 0 {
                trie_data.push(Some(0.into()));
            }

            Ok(node_ptr)
        }
        Node::Leaf { nibbles, value } => {
            trie_data.push(Some(nibbles.count.into()));
            trie_data.push(Some(
                nibbles
                    .try_into()
                    .map_err(|_| ProgramError::IntegerTooLarge)?,
            ));

            // Set `value_ptr_ptr`.
            trie_data.push(Some((trie_data.len() + 1).into()));

            let leaf = parse_value(value)?.into_iter().map(Some);
            trie_data.extend(leaf);

            Ok(node_ptr)
        }
    }
}

fn load_state_trie(
    trie: &HashedPartialTrie,
    key: Nibbles,
    trie_data: &mut Vec<Option<U256>>,
    storage_tries_by_state_key: &HashMap<Nibbles, &HashedPartialTrie>,
) -> Result<usize, ProgramError> {
    let node_ptr = trie_data.len();
    let type_of_trie = PartialTrieType::of(trie) as u32;
    if type_of_trie > 0 {
        trie_data.push(Some(type_of_trie.into()));
    }
    match trie.deref() {
        Node::Empty => Ok(0),
        Node::Hash(h) => {
            trie_data.push(Some(U256::one())); // Set flag is_account to 1
            trie_data.push(Some(
                key.try_into().map_err(|_| ProgramError::IntegerTooLarge)?,
            ));
            trie_data.push(Some(h2u(*h)));
            Ok(node_ptr)
        }
        Node::Branch { children, value } => {
            if !value.is_empty() {
                return Err(ProgramError::ProverInputError(
                    ProverInputError::InvalidMptInput,
                ));
            }
            // First, set children pointers to 0.
            let first_child_ptr = trie_data.len();
            trie_data.extend(vec![Some(U256::zero()); 16]);
            // Then, set value pointer to 0.
            trie_data.push(Some(U256::zero()));

            // Now, load all children and update their pointers.
            for (i, child) in children.iter().enumerate() {
                let extended_key = key.merge_nibbles(&Nibbles {
                    count: 1,
                    packed: i.into(),
                });
                let child_ptr =
                    load_state_trie(child, extended_key, trie_data, storage_tries_by_state_key)?;

                trie_data[first_child_ptr + i] = Some(child_ptr.into());
            }

            Ok(node_ptr)
        }
        Node::Extension { nibbles, child } => {
            trie_data.push(Some(nibbles.count.into()));
            trie_data.push(Some(
                nibbles
                    .try_into()
                    .map_err(|_| ProgramError::IntegerTooLarge)?,
            ));
            // Set `value_ptr_ptr`.
            trie_data.push(Some((trie_data.len() + 1).into()));
            let extended_key = key.merge_nibbles(nibbles);
            let child_ptr =
                load_state_trie(child, extended_key, trie_data, storage_tries_by_state_key)?;
            if child_ptr == 0 {
                trie_data.push(Some(0.into()));
            }

            Ok(node_ptr)
        }
        Node::Leaf { nibbles, value } => {
            let account: AccountRlp = rlp::decode(value).map_err(|_| ProgramError::InvalidRlp)?;
            let AccountRlp {
                nonce,
                balance,
                storage_root,
                code_hash,
            } = account;

            let storage_hash_only = HashedPartialTrie::new(Node::Hash(storage_root));
            let merged_key = key.merge_nibbles(nibbles);
            let storage_trie: &HashedPartialTrie = storage_tries_by_state_key
                .get(&merged_key)
                .copied()
                .unwrap_or(&storage_hash_only);

            assert_eq!(storage_trie.hash(), storage_root,
                "In TrieInputs, an account's storage_root didn't match the associated storage trie hash");

            trie_data.push(Some(nibbles.count.into()));
            trie_data.push(Some(
                nibbles
                    .try_into()
                    .map_err(|_| ProgramError::IntegerTooLarge)?,
            ));
            // Set `value_ptr_ptr`.
            trie_data.push(Some((trie_data.len() + 1).into()));

            trie_data.push(Some(nonce));
            trie_data.push(Some(balance));
            // Storage trie ptr.
            let storage_ptr_ptr = trie_data.len();
            trie_data.push(Some((trie_data.len() + 2).into()));
            trie_data.push(Some(code_hash.into_uint()));
            let storage_ptr = load_mpt(
                storage_trie,
                empty_nibbles(),
                trie_data,
                &parse_storage_value,
            )?;
            if storage_ptr == 0 {
                trie_data[storage_ptr_ptr] = Some(0.into());
            }

            Ok(node_ptr)
        }
    }
}

fn get_state_and_storage_leaves(
    trie: &HashedPartialTrie,
    key: Nibbles,
    state_leaves: &mut Vec<Option<U256>>,
    storage_leaves: &mut Vec<Option<U256>>,
    hash_nodes: &mut Vec<Option<U256>>,
    trie_data: &mut Vec<Option<U256>>,
    storage_tries_by_state_key: &HashMap<Nibbles, &HashedPartialTrie>,
) -> Result<(), ProgramError> {
    match trie.deref() {
        Node::Branch { children, value } => {
            if !value.is_empty() {
                return Err(ProgramError::ProverInputError(
                    ProverInputError::InvalidMptInput,
                ));
            }

            for (i, child) in children.iter().enumerate() {
                let extended_key = key.merge_nibbles(&Nibbles {
                    count: 1,
                    packed: i.into(),
                });

                get_state_and_storage_leaves(
                    child,
                    extended_key,
                    state_leaves,
                    storage_leaves,
                    hash_nodes,
                    trie_data,
                    storage_tries_by_state_key,
                )?;
            }

            Ok(())
        }
        Node::Extension { nibbles, child } => {
            let extended_key = key.merge_nibbles(nibbles);
            get_state_and_storage_leaves(
                child,
                extended_key,
                state_leaves,
                storage_leaves,
                hash_nodes,
                trie_data,
                storage_tries_by_state_key,
            )?;

            Ok(())
        }
        Node::Leaf { nibbles, value } => {
            let account: AccountRlp = rlp::decode(value).map_err(|_| ProgramError::InvalidRlp)?;
            let AccountRlp {
                nonce,
                balance,
                storage_root,
                code_hash,
            } = account;

            let storage_hash_only = HashedPartialTrie::new(Node::Hash(storage_root));
            let merged_key = key.merge_nibbles(nibbles);
            let storage_trie: &HashedPartialTrie = storage_tries_by_state_key
                .get(&merged_key)
                .copied()
                .unwrap_or(&storage_hash_only);

            assert_eq!(
                storage_trie.hash(),
                storage_root,
                "In TrieInputs, an account's storage_root didn't match the associated storage trie hash"
            );

            // The last leaf must point to the new one.
            let len = state_leaves.len();
            state_leaves[len - 1] = Some(U256::from(
                Segment::AccountsLinkedList as usize + state_leaves.len(),
            ));
            // The nibbles are the address.
            let addr_key = merged_key
                .try_into()
                .map_err(|_| ProgramError::IntegerTooLarge)?;
            state_leaves.push(Some(addr_key));
            // Set `value_ptr_ptr`.
            state_leaves.push(Some(trie_data.len().into()));
            // Set counter.
            state_leaves.push(Some(0.into()));
            // Set the next node as the initial node.
            state_leaves.push(Some((Segment::AccountsLinkedList as usize).into()));

            // Push the payload in the trie data.
            trie_data.push(Some(nonce));
            trie_data.push(Some(balance));
            // The Storage pointer is only written in the trie.
            trie_data.push(Some(0.into()));
            trie_data.push(Some(code_hash.into_uint()));
            get_storage_leaves(
                addr_key,
                empty_nibbles(),
                storage_trie,
                storage_leaves,
                hash_nodes,
                &parse_storage_value,
            )?;

            Ok(())
        }
        Node::Hash(hash) => {
            let addr_key = key.try_into().map_err(|_| ProgramError::IntegerTooLarge)?;
            hash_nodes.push(Some(addr_key));
            hash_nodes.push(Some(hash.into_uint()));
            Ok(())
        }
        _ => Ok(()),
    }
}

pub(crate) fn get_storage_leaves<F>(
    addr_key: U256,
    key: Nibbles,
    trie: &HashedPartialTrie,
    storage_leaves: &mut Vec<Option<U256>>,
    storage_hash_nodes: &mut Vec<Option<U256>>,
    parse_value: &F,
) -> Result<(), ProgramError>
where
    F: Fn(&[u8]) -> Result<Vec<U256>, ProgramError>,
{
    match trie.deref() {
        Node::Branch { children, value } => {
            // Now, load all children and update their pointers.
            for (i, child) in children.iter().enumerate() {
                let extended_key = key.merge_nibbles(&Nibbles {
                    count: 1,
                    packed: i.into(),
                });
                get_storage_leaves(
                    addr_key,
                    extended_key,
                    child,
                    storage_leaves,
                    storage_hash_nodes,
                    parse_value,
                )?;
            }

            Ok(())
        }

        Node::Extension { nibbles, child } => {
            let extended_key = key.merge_nibbles(nibbles);
            get_storage_leaves(
                addr_key,
                extended_key,
                child,
                storage_leaves,
                storage_hash_nodes,
                parse_value,
            )?;

            Ok(())
        }
        Node::Leaf { nibbles, value } => {
            // The last leaf must point to the new one.
            let len = storage_leaves.len();
            let merged_key = key.merge_nibbles(nibbles);
            storage_leaves[len - 1] = Some(U256::from(
                Segment::StorageLinkedList as usize + storage_leaves.len(),
            ));
            // Write the address.
            storage_leaves.push(Some(addr_key));
            // Write the key.
            storage_leaves.push(Some(
                merged_key
                    .try_into()
                    .map_err(|_| ProgramError::IntegerTooLarge)?,
            ));
            // Write `value_ptr_ptr`.
            let leaves = parse_value(value)?
                .into_iter()
                .map(Some)
                .collect::<Vec<_>>();
            let leaf = match leaves.len() {
                1 => leaves[0],
                _ => panic!("Slot can only store exactly one value."),
            };
            storage_leaves.push(leaf);
            // Write the counter.
            storage_leaves.push(Some(0.into()));
            // Set the next node as the initial node.
            storage_leaves.push(Some((Segment::StorageLinkedList as usize).into()));

            Ok(())
        }
        Node::Hash(hash) => {
            let slot_key = key.try_into().map_err(|_| ProgramError::IntegerTooLarge)?;
            storage_hash_nodes.push(Some(slot_key));
            storage_hash_nodes.push(Some(hash.into_uint()));
            Ok(())
        }
        _ => Ok(()),
    }
}

/// A type alias used to gather:
///     - the trie root pointers for all tries
///     - the vector of state trie leaves
///     - the vector of storage trie leaves
///     - the vector of state and storage hashed nodes
///     - the `TrieData` segment's memory content
type TriePtrsLinkedLists = (
    TrieRootPtrs,
    Vec<Option<U256>>,
    Vec<Option<U256>>,
    Vec<Option<U256>>,
    Vec<Option<U256>>,
);

pub(crate) fn load_linked_lists_and_txn_and_receipt_mpts(
    trie_inputs: &TrieInputs,
) -> Result<TriePtrsLinkedLists, ProgramError> {
    let mut state_leaves =
        empty_list_mem::<ACCOUNTS_LINKED_LIST_NODE_SIZE>(Segment::AccountsLinkedList).to_vec();
    let mut storage_leaves =
        empty_list_mem::<STORAGE_LINKED_LIST_NODE_SIZE>(Segment::StorageLinkedList).to_vec();
    let mut hash_nodes = vec![];
    let mut trie_data = vec![Some(U256::zero())];

    let storage_tries_by_state_key = trie_inputs
        .storage_tries
        .iter()
        .map(|(hashed_address, storage_trie)| {
            let key = Nibbles::from_bytes_be(hashed_address.as_bytes())
                .expect("An H256 is 32 bytes long");
            (key, storage_trie)
        })
        .collect();

    let txn_root_ptr = load_mpt(
        &trie_inputs.transactions_trie,
        empty_nibbles(),
        &mut trie_data,
        &|rlp| {
            let mut parsed_txn = vec![U256::from(rlp.len())];
            parsed_txn.extend(rlp.iter().copied().map(U256::from));
            Ok(parsed_txn)
        },
    )?;

    let receipt_root_ptr = load_mpt(
        &trie_inputs.receipts_trie,
        empty_nibbles(),
        &mut trie_data,
        &parse_receipts,
    )?;

    get_state_and_storage_leaves(
        &trie_inputs.state_trie,
        empty_nibbles(),
        &mut state_leaves,
        &mut storage_leaves,
        &mut hash_nodes,
        &mut trie_data,
        &storage_tries_by_state_key,
    );

    Ok((
        TrieRootPtrs {
            state_root_ptr: None,
            txn_root_ptr,
            receipt_root_ptr,
        },
        state_leaves,
        storage_leaves,
        hash_nodes,
        trie_data,
    ))
}

pub(crate) fn load_state_mpt(
    trie_inputs: &TrimmedTrieInputs,
    trie_data: &mut Vec<Option<U256>>,
) -> Result<usize, ProgramError> {
    let storage_tries_by_state_key = trie_inputs
        .storage_tries
        .iter()
        .map(|(hashed_address, storage_trie)| {
            let key = Nibbles::from_bytes_be(hashed_address.as_bytes())
                .expect("An H256 is 32 bytes long");
            (key, storage_trie)
        })
        .collect();

    load_state_trie(
        &trie_inputs.state_trie,
        empty_nibbles(),
        trie_data,
        &storage_tries_by_state_key,
    )
}

pub(crate) fn load_final_state_mpt(
    accounts_linked_list: LinkedList<ACCOUNTS_LINKED_LIST_NODE_SIZE>,
    storage_linked_list: &mut LinkedList<STORAGE_LINKED_LIST_NODE_SIZE>,
    hashed_nodes: Vec<Option<U256>>,
    trie_data: &mut Vec<Option<U256>>,
) -> Result<usize, ProgramError> {
    let (final_state_trie, storage_tries_by_state_key) = get_final_state_mpt(
        accounts_linked_list,
        storage_linked_list,
        hashed_nodes,
        trie_data,
    )?;
    let ref_storage_tries_by_state_key: HashMap<_, _> = storage_tries_by_state_key
        .iter()
        .map(|(&k, v)| (k, v))
        .collect();

    load_state_trie(
        &final_state_trie,
        empty_nibbles(),
        trie_data,
        &ref_storage_tries_by_state_key,
    )
}

pub(crate) fn get_final_state_mpt(
    accounts_linked_list: LinkedList<ACCOUNTS_LINKED_LIST_NODE_SIZE>,
    storage_linked_list: &mut LinkedList<STORAGE_LINKED_LIST_NODE_SIZE>,
    hashed_nodes: Vec<Option<U256>>,
    trie_data: &mut Vec<Option<U256>>,
) -> Result<(HashedPartialTrie, HashMap<Nibbles, HashedPartialTrie>), ProgramError> {
    let mut storage_tries_by_state_key = HashMap::<Nibbles, HashedPartialTrie>::new();
    let mut final_state_trie = HashedPartialTrie::from(Node::Empty);
    let mut last_slot = storage_linked_list.next();
    let mut hash_nodes = hashed_nodes.chunks(3);
    let mut last_hash_node = hash_nodes.next();

    for account in accounts_linked_list {
        let mut storage_trie = HashedPartialTrie::from(Node::Empty);
        let account_nibbles = account[0].to_nibbles();
        loop {
            if let Some(hash_node) = last_hash_node
                && hash_node[1] == Some(U256::one())
            {
                final_state_trie
                    .insert(
                        hash_node[0].unwrap_or_default().to_nibbles(),
                        H256::from_uint(&hash_node[2].unwrap_or_default()),
                    )
                    .unwrap(); // TODO: Map to a proper error.
                last_hash_node = hash_nodes.next();
            } else {
                break;
            }
        }
        loop {
            loop {
                if let Some(hash_node) = last_hash_node
                    && hash_node[1] == Some(U256::zero())
                {
                    storage_trie
                        .insert(
                            hash_node[0].unwrap_or_default().to_nibbles(),
                            H256::from_uint(&hash_node[2].unwrap_or_default()),
                        )
                        .unwrap(); // TODO: Map to a proper error.
                    last_hash_node = hash_nodes.next();
                }
            }
            if let Some(slot) = last_slot
                && slot[0] == account[0]
            {
                storage_trie
                    .insert(
                        slot[1].to_nibbles(),
                        rlp::encode(&slot[2]).freeze().to_vec(),
                    )
                    .unwrap(); // TODO: map error into ProgramError
                last_slot = storage_linked_list.next();
            } else {
                break;
            }
        }
        let payload_ptr = u256_to_usize(account[1]).unwrap(); //TODO: Catch error
        let account = AccountRlp {
            nonce: trie_data[payload_ptr].unwrap_or_default(),
            balance: trie_data[payload_ptr + 1].unwrap_or_default(),
            storage_root: storage_trie.hash(),
            code_hash: H256::from_uint(&trie_data[payload_ptr + 3].unwrap_or_default()),
        };
        final_state_trie.insert(account_nibbles, rlp::encode(&account).to_vec());
        storage_tries_by_state_key.insert(account_nibbles, storage_trie);
    }
    Ok((final_state_trie, storage_tries_by_state_key))
}

pub mod transaction_testing {
    use super::*;

    #[derive(RlpEncodable, RlpDecodable, Debug, Clone, PartialEq, Eq)]
    pub struct AccessListItemRlp {
        pub address: Address,
        pub storage_keys: Vec<U256>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct AddressOption(pub Option<Address>);

    impl Encodable for AddressOption {
        fn rlp_append(&self, s: &mut RlpStream) {
            match self.0 {
                None => s.encoder().encode_value(&[]),
                Some(value) => {
                    s.encoder().encode_value(&value.to_fixed_bytes());
                }
            }
        }
    }

    impl Decodable for AddressOption {
        fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
            if rlp.is_int() && rlp.is_empty() {
                return Ok(AddressOption(None));
            }
            if rlp.is_data() && rlp.size() == 20 {
                return Ok(AddressOption(Some(Address::decode(rlp)?)));
            }
            Err(DecoderError::RlpExpectedToBeData)
        }
    }

    #[derive(RlpEncodable, RlpDecodable, Debug, Clone, PartialEq, Eq)]
    pub struct LegacyTransactionRlp {
        pub nonce: U256,
        pub gas_price: U256,
        pub gas: U256,
        pub to: AddressOption,
        pub value: U256,
        pub data: Bytes,
        pub v: U256,
        pub r: U256,
        pub s: U256,
    }

    #[derive(RlpEncodable, RlpDecodable, Debug, Clone, PartialEq, Eq)]
    pub struct AccessListTransactionRlp {
        pub chain_id: u64,
        pub nonce: U256,
        pub gas_price: U256,
        pub gas: U256,
        pub to: AddressOption,
        pub value: U256,
        pub data: Bytes,
        pub access_list: Vec<AccessListItemRlp>,
        pub y_parity: U256,
        pub r: U256,
        pub s: U256,
    }

    #[derive(RlpEncodable, RlpDecodable, Debug, Clone, PartialEq, Eq)]
    pub struct FeeMarketTransactionRlp {
        pub chain_id: u64,
        pub nonce: U256,
        pub max_priority_fee_per_gas: U256,
        pub max_fee_per_gas: U256,
        pub gas: U256,
        pub to: AddressOption,
        pub value: U256,
        pub data: Bytes,
        pub access_list: Vec<AccessListItemRlp>,
        pub y_parity: U256,
        pub r: U256,
        pub s: U256,
    }
}
