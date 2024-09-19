use core::ops::Deref;
use std::collections::{BTreeMap, HashMap};

use bytes::Bytes;
use ethereum_types::{Address, BigEndianHash, H256, U256};
use keccak_hash::keccak;
use mpt_trie::nibbles::{Nibbles, NibblesIntern};
use mpt_trie::partial_trie::{HashedPartialTrie, PartialTrie};
use rlp::{Decodable, DecoderError, Encodable, PayloadInfo, Rlp, RlpStream};
use rlp_derive::{RlpDecodable, RlpEncodable};
use serde::{Deserialize, Serialize};
use smt_trie::code::hash_bytecode_u256;

use super::linked_list::{
    empty_list_mem, ACCOUNTS_LINKED_LIST_NODE_SIZE, STORAGE_LINKED_LIST_NODE_SIZE,
};
#[cfg(not(feature = "cdk_erigon"))]
use super::TrimmedTrieInputs;
use crate::cpu::kernel::constants::mpt_type::PartialMptType;
use crate::generation::TrieInputs;
use crate::memory::segments::Segment;
use crate::util::h2u;
use crate::witness::errors::{ProgramError, ProverInputError};
use crate::Node;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AccountRlp {
    Type1(Type1AccountRlp),
    Type2(Type2AccountRlp),
}

impl Encodable for AccountRlp {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self {
            Self::Type1(acc) => acc.rlp_append(s),
            Self::Type2(acc) => acc.rlp_append(s),
        }
    }
}

impl From<Type1AccountRlp> for AccountRlp {
    fn from(value: Type1AccountRlp) -> Self {
        Self::Type1(value)
    }
}

impl AccountRlp {
    pub fn nonce(&self) -> U256 {
        match self {
            Self::Type1(acc) => acc.nonce,
            Self::Type2(acc) => acc.nonce,
        }
    }

    pub fn set_nonce(&mut self, val: U256) {
        match self {
            Self::Type1(acc) => acc.nonce = val,
            Self::Type2(acc) => acc.nonce = val,
        }
    }

    pub fn balance(&self) -> U256 {
        match self {
            Self::Type1(acc) => acc.balance,
            Self::Type2(acc) => acc.balance,
        }
    }

    pub fn set_balance(&mut self, val: U256) {
        match self {
            Self::Type1(acc) => acc.balance = val,
            Self::Type2(acc) => acc.balance = val,
        }
    }

    pub fn code_hash(&self) -> H256 {
        match self {
            Self::Type1(acc) => acc.code_hash,
            Self::Type2(acc) => acc.code_hash,
        }
    }

    pub fn set_code_hash(&mut self, hash: H256) {
        match self {
            Self::Type1(acc) => acc.code_hash = hash,
            Self::Type2(acc) => acc.code_hash = hash,
        }
    }

    pub fn storage_root(&self) -> Option<H256> {
        match self {
            Self::Type1(acc) => Some(acc.storage_root),
            Self::Type2(_) => None,
        }
    }

    pub fn set_storage_root(&mut self, hash: H256) {
        match self {
            Self::Type1(acc) => acc.storage_root = hash,
            Self::Type2(_) => panic!("No storage root for type 2 accounts."),
        }
    }

    pub fn code_length(&self) -> Option<U256> {
        match self {
            Self::Type1(_) => None,
            Self::Type2(acc) => Some(acc.code_length),
        }
    }
}

#[derive(RlpEncodable, RlpDecodable, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Type1AccountRlp {
    pub nonce: U256,
    pub balance: U256,
    pub storage_root: H256,
    pub code_hash: H256,
}

impl Default for Type1AccountRlp {
    fn default() -> Self {
        Self {
            nonce: U256::zero(),
            balance: U256::zero(),
            storage_root: HashedPartialTrie::from(Node::Empty).hash(),
            code_hash: keccak([]),
        }
    }
}

#[derive(RlpEncodable, RlpDecodable, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Type2AccountRlp {
    pub nonce: U256,
    pub balance: U256,
    pub code_length: U256,
    pub code_hash: H256,
}

impl Default for Type2AccountRlp {
    fn default() -> Self {
        Self {
            nonce: U256::zero(),
            balance: U256::zero(),
            code_hash: keccak(vec![]),
            code_length: U256::zero(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TrieRootPtrs {
    pub state_root_ptr: Option<usize>,
    pub txn_root_ptr: usize,
    pub receipt_root_ptr: usize,
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

/// Decodes a transaction receipt from an RLP string, outputting a tuple
/// consisting of:
///   - the receipt's [`PayloadInfo`],
///   - the transaction type,
///   - the decoded [`LegacyReceiptRlp`].
pub fn decode_receipt(rlp: &[u8]) -> Result<(PayloadInfo, usize, LegacyReceiptRlp), ProgramError> {
    let txn_type = match rlp.first().ok_or(ProgramError::InvalidRlp)? {
        1 => 1,
        2 => 2,
        3 => 3,
        _ => 0,
    };

    // If this is not a legacy transaction, we skip the leading byte.
    let rlp = if txn_type == 0 { rlp } else { &rlp[1..] };

    let payload_info = PayloadInfo::from(rlp).map_err(|_| ProgramError::InvalidRlp)?;
    let decoded_receipt: LegacyReceiptRlp =
        rlp::decode(rlp).map_err(|_| ProgramError::InvalidRlp)?;

    Ok((payload_info, txn_type, decoded_receipt))
}

pub(crate) fn parse_receipts(rlp: &[u8]) -> Result<Vec<U256>, ProgramError> {
    let (payload_info, txn_type, decoded_receipt) = decode_receipt(rlp)?;
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

fn parse_storage_value_no_return(_value_rlp: &[u8]) -> Result<Vec<U256>, ProgramError> {
    Ok(vec![])
}

const fn empty_nibbles() -> Nibbles {
    Nibbles {
        count: 0,
        packed: NibblesIntern::zero(),
    }
}

fn load_mpt<F>(
    trie: &HashedPartialTrie,
    trie_data: &mut Vec<Option<U256>>,
    parse_value: &F,
) -> Result<usize, ProgramError>
where
    F: Fn(&[u8]) -> Result<Vec<U256>, ProgramError>,
{
    let node_ptr = trie_data.len();
    let type_of_trie = PartialMptType::of(trie) as u32;
    if type_of_trie > 0 {
        trie_data.push(Some(type_of_trie.into()));
    }

    match trie.deref() {
        Node::Empty => Ok(0),
        Node::Hash(h) => {
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
                let child_ptr = load_mpt(child, trie_data, parse_value)?;
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

            let child_ptr = load_mpt(child, trie_data, parse_value)?;
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

#[cfg(not(feature = "cdk_erigon"))]
fn load_state_trie(
    trie: &HashedPartialTrie,
    key: Nibbles,
    trie_data: &mut Vec<Option<U256>>,

    storage_tries_by_state_key: &HashMap<Nibbles, &HashedPartialTrie>,
) -> Result<usize, ProgramError> {
    let node_ptr = trie_data.len();
    let type_of_trie = PartialMptType::of(trie) as u32;
    if type_of_trie > 0 {
        trie_data.push(Some(type_of_trie.into()));
    }
    match trie.deref() {
        Node::Empty => Ok(0),
        Node::Hash(h) => {
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
            // We don't need to store the slot values, as they will be overwritten in
            // `mpt_set_payload`.
            let storage_ptr = load_mpt(storage_trie, trie_data, &parse_storage_value_no_return)?;
            if storage_ptr == 0 {
                trie_data[storage_ptr_ptr] = Some(0.into());
            }

            Ok(node_ptr)
        }
    }
}

#[cfg(not(feature = "cdk_erigon"))]
fn get_state_and_storage_leaves(
    trie: &HashedPartialTrie,
    key: Nibbles,
    state_leaves: &mut Vec<Option<U256>>,
    storage_leaves: &mut Vec<Option<U256>>,
    trie_data: &mut Vec<Option<U256>>,
    accounts_pointers: &mut BTreeMap<U256, usize>,
    storage_pointers: &mut BTreeMap<(U256, U256), usize>,
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
                    trie_data,
                    accounts_pointers,
                    storage_pointers,
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
                trie_data,
                accounts_pointers,
                storage_pointers,
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
            state_leaves[len - 1] = Some(U256::from(Segment::AccountsLinkedList as usize + len));
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
                storage_pointers,
                &parse_storage_value,
            )?;

            accounts_pointers.insert(addr_key, Segment::AccountsLinkedList as usize + len);

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
    storage_pointers: &mut BTreeMap<(U256, U256), usize>,
    parse_value: &F,
) -> Result<(), ProgramError>
where
    F: Fn(&[u8]) -> Result<Vec<U256>, ProgramError>,
{
    match trie.deref() {
        Node::Branch { children, value: _ } => {
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
                    storage_pointers,
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
                storage_pointers,
                parse_value,
            )?;

            Ok(())
        }
        Node::Leaf { nibbles, value } => {
            // The last leaf must point to the new one.
            let len = storage_leaves.len();
            let merged_key = key.merge_nibbles(nibbles);
            storage_leaves[len - 1] = Some(U256::from(Segment::StorageLinkedList as usize + len));
            // Write the address.
            storage_leaves.push(Some(addr_key));
            // Write the key.
            let slot_key = merged_key
                .try_into()
                .map_err(|_| ProgramError::IntegerTooLarge)?;
            storage_leaves.push(Some(slot_key));
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

            storage_pointers.insert(
                (addr_key, slot_key),
                Segment::StorageLinkedList as usize + len,
            );

            Ok(())
        }
        _ => Ok(()),
    }
}

/// A type alias used to gather:
///     - the trie root pointers for all tries
///     - the vector of state trie leaves
///     - the vector of storage trie leaves
///     - the `TrieData` segment's memory content
type TriePtrsLinkedLists = (
    TrieRootPtrs,
    Vec<Option<U256>>,
    Vec<Option<U256>>,
    Vec<Option<U256>>,
);

#[cfg(not(feature = "cdk_erigon"))]
pub(crate) fn load_linked_lists_and_txn_and_receipt_mpts(
    accounts_pointers: &mut BTreeMap<U256, usize>,
    storage_pointers: &mut BTreeMap<(U256, U256), usize>,
    trie_inputs: &TrieInputs,
) -> Result<TriePtrsLinkedLists, ProgramError> {
    let mut state_leaves =
        empty_list_mem::<ACCOUNTS_LINKED_LIST_NODE_SIZE>(Segment::AccountsLinkedList).to_vec();
    let mut storage_leaves =
        empty_list_mem::<STORAGE_LINKED_LIST_NODE_SIZE>(Segment::StorageLinkedList).to_vec();
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

    let txn_root_ptr = load_mpt(&trie_inputs.transactions_trie, &mut trie_data, &|rlp| {
        let mut parsed_txn = vec![U256::from(rlp.len())];
        parsed_txn.extend(rlp.iter().copied().map(U256::from));
        Ok(parsed_txn)
    })?;

    let receipt_root_ptr = load_mpt(&trie_inputs.receipts_trie, &mut trie_data, &parse_receipts)?;

    get_state_and_storage_leaves(
        &trie_inputs.state_trie,
        empty_nibbles(),
        &mut state_leaves,
        &mut storage_leaves,
        &mut trie_data,
        accounts_pointers,
        storage_pointers,
        &storage_tries_by_state_key,
    )?;

    Ok((
        TrieRootPtrs {
            state_root_ptr: None,
            txn_root_ptr,
            receipt_root_ptr,
        },
        state_leaves,
        storage_leaves,
        trie_data,
    ))
}

#[cfg(feature = "cdk_erigon")]
pub(crate) fn load_linked_lists_and_txn_and_receipt_mpts(
    trie_inputs: &TrieInputs,
) -> Result<TriePtrsLinkedLists, ProgramError> {
    unimplemented!()
}

#[cfg(not(feature = "cdk_erigon"))]
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

pub mod transaction_testing {
    use ethereum_types::H160;

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

    #[derive(RlpEncodable, RlpDecodable, Debug, Clone, PartialEq, Eq)]
    pub struct BlobTransactionRlp {
        pub chain_id: u64,
        pub nonce: U256,
        pub max_priority_fee_per_gas: U256,
        pub max_fee_per_gas: U256,
        pub gas: U256,
        // As per EIP-4844, blob transactions cannot have the form of a create transaction.
        pub to: H160,
        pub value: U256,
        pub data: Bytes,
        pub access_list: Vec<AccessListItemRlp>,
        pub max_fee_per_blob_gas: U256,
        pub blob_versioned_hashes: Vec<H256>,
        pub y_parity: U256,
        pub r: U256,
        pub s: U256,
    }
}
