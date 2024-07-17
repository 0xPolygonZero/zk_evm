//! Code for extracting trie data after witness generation. This is intended
//! only for debugging.

use ethereum_types::{BigEndianHash, H256, U256};
use mpt_trie::nibbles::{Nibbles, NibblesIntern};
use mpt_trie::partial_trie::{HashedPartialTrie, Node, PartialTrie, WrappedNode};

use super::mpt::{AccountRlp, LegacyReceiptRlp, LogRlp};
use crate::cpu::kernel::constants::trie_type::PartialTrieType;
use crate::memory::segments::Segment;
use crate::util::{u256_to_bool, u256_to_h160, u256_to_u8, u256_to_usize};
use crate::witness::errors::ProgramError;
use crate::witness::memory::{MemoryAddress, MemoryState};

pub(crate) fn read_storage_trie_value(slice: &[Option<U256>]) -> U256 {
    slice[0].unwrap_or_default()
}

pub(crate) fn read_receipt_trie_value(
    slice: &[Option<U256>],
) -> Result<(Option<u8>, LegacyReceiptRlp), ProgramError> {
    let first_value = slice[0].unwrap_or_default();
    // Skip two elements for non-legacy Receipts, and only one otherwise.
    let (first_byte, slice) = if first_value == U256::one() || first_value == U256::from(2u8) {
        (Some(first_value.as_u32() as u8), &slice[2..])
    } else {
        (None, &slice[1..])
    };

    let status = u256_to_bool(slice[0].unwrap_or_default())?;
    let cum_gas_used = slice[1].unwrap_or_default();
    let bloom = slice[2..2 + 256]
        .iter()
        .map(|&x| u256_to_u8(x.unwrap_or_default()))
        .collect::<Result<_, _>>()?;
    // We read the number of logs at position `2 + 256 + 1`, and skip over the next
    // element before parsing the logs.
    let logs = read_logs(
        u256_to_usize(slice[2 + 256 + 1].unwrap_or_default())?,
        &slice[2 + 256 + 3..],
    )?;

    Ok((
        first_byte,
        LegacyReceiptRlp {
            status,
            cum_gas_used,
            bloom,
            logs,
        },
    ))
}

pub(crate) fn read_logs(
    num_logs: usize,
    slice: &[Option<U256>],
) -> Result<Vec<LogRlp>, ProgramError> {
    let mut offset = 0;
    (0..num_logs)
        .map(|_| {
            let address = u256_to_h160(slice[offset].unwrap_or_default())?;
            offset += 1;

            let num_topics = u256_to_usize(slice[offset].unwrap_or_default())?;
            offset += 1;

            let topics = (0..num_topics)
                .map(|i| H256::from_uint(&slice[offset + i].unwrap_or_default()))
                .collect();
            offset += num_topics;

            let data_len = u256_to_usize(slice[offset].unwrap_or_default())?;
            offset += 1;

            let data = slice[offset..offset + data_len]
                .iter()
                .map(|&x| u256_to_u8(x.unwrap_or_default()))
                .collect::<Result<_, _>>()?;
            offset += data_len + 1; // We need to skip one extra element before looping.

            let log = LogRlp {
                address,
                topics,
                data,
            };

            Ok(log)
        })
        .collect()
}

pub(crate) fn read_state_rlp_value(
    memory: &MemoryState,
    slice: &MemoryValues,
) -> Result<Vec<u8>, ProgramError> {
    let storage_trie: HashedPartialTrie =
        get_trie(memory, slice[2].unwrap_or_default().as_usize(), |_, x| {
            Ok(rlp::encode(&read_storage_trie_value(x)).to_vec())
        })?;
    let account = AccountRlp {
        nonce: slice[0].unwrap_or_default(),
        balance: slice[1].unwrap_or_default(),
        storage_root: storage_trie.hash(),
        code_hash: H256::from_uint(&slice[3].unwrap_or_default()),
    };
    Ok(rlp::encode(&account).to_vec())
}

pub(crate) fn read_txn_rlp_value(
    _memory: &MemoryState,
    slice: &MemoryValues,
) -> Result<Vec<u8>, ProgramError> {
    let txn_rlp_len = u256_to_usize(slice[0].unwrap_or_default())?;
    slice[1..txn_rlp_len + 1]
        .iter()
        .map(|&x| u256_to_u8(x.unwrap_or_default()))
        .collect::<Result<_, _>>()
}

pub(crate) fn read_receipt_rlp_value(
    _memory: &MemoryState,
    slice: &MemoryValues,
) -> Result<Vec<u8>, ProgramError> {
    let (first_byte, receipt) = read_receipt_trie_value(slice)?;
    let mut bytes = rlp::encode(&receipt).to_vec();
    if let Some(txn_byte) = first_byte {
        bytes.insert(0, txn_byte);
    }

    Ok(bytes)
}

pub(crate) fn get_state_trie<N: PartialTrie>(
    memory: &MemoryState,
    ptr: usize,
) -> Result<N, ProgramError> {
    get_trie(memory, ptr, read_state_rlp_value)
}

pub(crate) fn get_txn_trie<N: PartialTrie>(
    memory: &MemoryState,
    ptr: usize,
) -> Result<N, ProgramError> {
    get_trie(memory, ptr, read_txn_rlp_value)
}

pub(crate) fn get_receipt_trie<N: PartialTrie>(
    memory: &MemoryState,
    ptr: usize,
) -> Result<N, ProgramError> {
    get_trie(memory, ptr, read_receipt_rlp_value)
}

type MemoryValues = Vec<Option<U256>>;
pub(crate) fn get_trie<N: PartialTrie>(
    memory: &MemoryState,
    ptr: usize,
    read_rlp_value: fn(&MemoryState, &MemoryValues) -> Result<Vec<u8>, ProgramError>,
) -> Result<N, ProgramError> {
    let empty_nibbles = Nibbles {
        count: 0,
        packed: NibblesIntern::zero(),
    };
    Ok(N::new(get_trie_helper(
        memory,
        ptr,
        read_rlp_value,
        empty_nibbles,
    )?))
}

pub(crate) fn get_trie_helper<N: PartialTrie>(
    memory: &MemoryState,
    ptr: usize,
    read_value: fn(&MemoryState, &MemoryValues) -> Result<Vec<u8>, ProgramError>,
    prefix: Nibbles,
) -> Result<Node<N>, ProgramError> {
    let load = |offset| {
        memory.get(MemoryAddress {
            context: 0,
            segment: Segment::TrieData.unscale(),
            virt: offset,
        })
    };
    let load_slice_from = |init_offset| {
        &memory.contexts[0].segments[Segment::TrieData.unscale()].content[init_offset..]
    };

    let trie_type = PartialTrieType::all()[u256_to_usize(load(ptr).unwrap_or_default())?];
    match trie_type {
        PartialTrieType::Empty => Ok(Node::Empty),
        PartialTrieType::Hash => {
            let ptr_payload = ptr + 1;
            let hash = H256::from_uint(&load(ptr_payload).unwrap_or_default());
            Ok(Node::Hash(hash))
        }
        PartialTrieType::Branch => {
            let ptr_payload = ptr + 1;
            let children = (0..16)
                .map(|i| {
                    let child_ptr =
                        u256_to_usize(load(ptr_payload + i as usize).unwrap_or_default())?;
                    get_trie_helper(memory, child_ptr, read_value, prefix.merge_nibble(i as u8))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let children = core::array::from_fn(|i| WrappedNode::from(children[i].clone()));
            let value_ptr = u256_to_usize(load(ptr_payload + 16).unwrap_or_default())?;
            let mut value: Vec<u8> = vec![];
            if value_ptr != 0 {
                value = read_value(memory, &load_slice_from(value_ptr).to_vec())?;
            };
            Ok(Node::Branch { children, value })
        }
        PartialTrieType::Extension => {
            let count = u256_to_usize(load(ptr + 1).unwrap_or_default())?;
            let packed = load(ptr + 2).unwrap_or_default();
            let nibbles = Nibbles {
                count,
                packed: packed.into(),
            };
            let child_ptr = u256_to_usize(load(ptr + 3).unwrap_or_default())?;
            let child = WrappedNode::from(get_trie_helper(
                memory,
                child_ptr,
                read_value,
                prefix.merge_nibbles(&nibbles),
            )?);
            Ok(Node::Extension { nibbles, child })
        }
        PartialTrieType::Leaf => {
            let count = u256_to_usize(load(ptr + 1).unwrap_or_default())?;
            let packed = load(ptr + 2).unwrap_or_default();
            let nibbles = Nibbles {
                count,
                packed: packed.into(),
            };
            let value_ptr = u256_to_usize(load(ptr + 3).unwrap_or_default())?;
            let value = read_value(memory, &load_slice_from(value_ptr).to_vec())?;
            Ok(Node::Leaf { nibbles, value })
        }
    }
}
