mod common;

use std::collections::{BTreeMap, BTreeSet};

use alloy::{
    consensus::Account,
    primitives::{Address, B256},
};
use alloy_compat::Compat as _;
use common::{hpt, key::TrieKey, repr};
use mpt_trie::{
    nibbles::Nibbles,
    partial_trie::{HashedPartialTrie, PartialTrie as _},
};
use trace_decoder::{
    BlockTrace, BlockTraceTriePreImages, OtherBlockData, SeparateStorageTriesPreImage,
    SeparateTriePreImage, SeparateTriePreImages, TxnInfo,
};

/// Hey Aatif, is there a way in the current API to pass in a key (on the
/// decoder side) to the state trie, and know whether we have a Leaf | Empty
/// (both considered valid) or a Hash node?
///
/// The get() implementation of the PartialTrie trait does not differentiate
/// Empty vs Hash at the moment Some more context:
/// > On the test chain, block 466, parsing the 2nd txn in the block is
/// > currently failing when marking address
/// > 0xf967cad20b8773e4edd62e26a37a96c66adb458b
/// > (state key
/// > 0x999ab198e16ec720bdfc058d582149b9938ceeee4b87fa29b302deabfa92221a) as
/// > touched in the initial state trie.
/// > It looks like so in the block payload fetched from Jerigon:
/// > ```
/// > "0xf967cad20b8773e4edd62e26a37a96c66adb458b": {}
/// > ```
/// > hence will be deleted post application of the deltas.
/// > The issue is that we technically don't need to have this address in the
/// > pre-state as the txn will abort before needing to insert this / do some
/// > ops on the created account, and hence Jerigon initial state trie does not
/// > contain the full path down the trie. This is then causing an issue as we
/// > have technically a state_access to this address, and we try to mark it
/// > before trimming the state trie. Ideally, we would still want Jerigon to
/// > not include the key in the initial state trie, as it would lead to a
/// > bigger witness and be heavier for the prover to prove. However, this is
/// > indistinguishable on the decoder side from a account to be deleted that
/// > first needs to be touched / created, and that needs to be part of the
/// > initial trie.
///
/// If we assume Jerigon payloads are always correct (which we technically
/// already do for the collapse logic), then we could either ignore the error
/// when hitting hash nodes while marking for those payloads, or we could alter
/// the deltas ahead by removing any created account for which the initial state
/// trie does not contain a path yielding a Leaf / Empty
#[test]
fn repro() {}

fn run(
    state: impl Into<BTreeMap<Address, Account>>,
    deferred_state: impl Into<BTreeMap<TrieKey, B256>>,
    storage: impl Into<BTreeMap<Address, HashedPartialTrie>>,
    code_db: impl Into<BTreeSet<Vec<u8>>>,
    txn_info: impl Into<Vec<TxnInfo>>,
    obd: impl Into<OtherBlockData>,
) -> Vec<repr::GenerationInputs> {
    trace_decoder::entrypoint_old(
        BlockTrace {
            trie_pre_images: BlockTraceTriePreImages::Separate(SeparateTriePreImages {
                state: {
                    let mut hpt = hpt();
                    for (addr, acct) in state.into() {
                        hpt.insert(
                            Nibbles::from_h256_be(keccak_hash::keccak(addr)),
                            alloy::rlp::encode(acct),
                        )
                        .unwrap();
                    }
                    for (key, hash) in deferred_state.into() {
                        hpt.insert(key.into_nibbles(), hash.compat()).unwrap();
                    }
                    SeparateTriePreImage::Direct(hpt)
                },
                storage: SeparateStorageTriesPreImage::MultipleTries(
                    storage
                        .into()
                        .into_iter()
                        .map(|(addr, hpt)| {
                            (keccak_hash::keccak(addr), SeparateTriePreImage::Direct(hpt))
                        })
                        .collect(),
                ),
            }),
            code_db: code_db.into(),
            txn_info: txn_info.into(),
        },
        obd.into(),
        1,
        false,
    )
    .unwrap()
    .into_iter()
    .map(Into::into)
    .collect()
}
