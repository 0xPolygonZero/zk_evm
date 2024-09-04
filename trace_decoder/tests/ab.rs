//! Test that the new implementation produces the same results as the old.

mod common;

use std::collections::{BTreeMap, BTreeSet, HashMap};

use alloy::{
    consensus::Account,
    primitives::{Address, B256},
};
use alloy_compat::Compat as _;
use common::{acct, hpt, key::TrieKey, obd, pos, rcpt, stg, txn, ALICE, BEACON};
use ethereum_types::U256;
use mpt_trie::{
    nibbles::Nibbles,
    partial_trie::{HashedPartialTrie, PartialTrie as _},
};
use trace_decoder::{
    BlockTrace, BlockTraceTriePreImages, OtherBlockData, SeparateStorageTriesPreImage,
    SeparateTriePreImage, SeparateTriePreImages, TxnInfo, TxnTrace,
};

#[test]
fn empty2() {
    do_test(
        [(BEACON, acct()), (ALICE, acct())],
        [],
        [(BEACON, hpt())],
        [],
        [
            txn([], [], rcpt(true, 0, []), 0),
            txn([], [], rcpt(true, 0, []), 0),
        ],
        obd(),
    )
}
#[test]
fn pad1() {
    do_test(
        [(BEACON, acct()), (ALICE, acct())],
        [],
        [(BEACON, hpt())],
        [],
        [txn([], [], rcpt(true, 0, []), 0)],
        obd(),
    )
}

#[test]
#[should_panic = "TODO(0xaatif): fix"]
fn pad2() {
    do_test([(BEACON, acct())], [], [(BEACON, hpt())], [], [], obd());
}

#[test]
fn alice_changes_balance() {
    do_test(
        [(BEACON, acct()), (ALICE, acct())],
        [],
        // TODO(0xaatif): if alice is missing from the storage:
        //                - subject gives her a Node::Hash($EMPTY_TRIE_HASH).
        //                - reference gives her a Node::Empty.
        //                neither error.
        [(BEACON, hpt()), (ALICE, hpt())],
        [],
        [
            txn(
                [(
                    ALICE,
                    TxnTrace {
                        storage_read: [].into(),
                        ..Default::default()
                    },
                )],
                [],
                rcpt(true, 0, []),
                0,
            ),
            txn([], [], rcpt(true, 0, []), 0),
        ],
        obd(),
    )
}

#[test]
fn alice_changes_nonce() {
    do_test(
        [(BEACON, acct()), (ALICE, acct())],
        [],
        [(BEACON, hpt()), (ALICE, hpt())],
        [],
        [
            txn(
                [(
                    ALICE,
                    TxnTrace {
                        nonce: Some(U256::from(1)),
                        ..Default::default()
                    },
                )],
                [],
                rcpt(true, 0, []),
                0,
            ),
            txn([], [], rcpt(true, 0, []), 0),
        ],
        obd(),
    )
}

#[test]
fn alice_reads_existing() {
    let alice_stg = stg(
        [
            (pos(ALICE, 0), b"zero".into()),
            (pos(ALICE, 1), b"one".into()),
            (pos(ALICE, 2), b"two".into()),
        ],
        [],
    );
    do_test(
        [
            (BEACON, acct()),
            (
                ALICE,
                Account {
                    storage_root: alice_stg.hash().compat(),
                    ..Default::default()
                },
            ),
        ],
        [],
        [(BEACON, hpt()), (ALICE, alice_stg)],
        [],
        [
            txn(
                [(
                    ALICE,
                    TxnTrace {
                        storage_read: [pos(ALICE, 1)].into(),
                        ..Default::default()
                    },
                )],
                [],
                rcpt(true, 0, []),
                0,
            ),
            txn([], [], rcpt(true, 0, []), 0),
        ],
        obd(),
    )
}

#[test]
fn alice_reads_absent() {
    do_test(
        [(BEACON, acct()), (ALICE, acct())],
        [],
        [(BEACON, hpt()), (ALICE, hpt())],
        [],
        [
            txn(
                [(
                    ALICE,
                    TxnTrace {
                        storage_read: [pos(ALICE, 0)].into(),
                        ..Default::default()
                    },
                )],
                [],
                rcpt(true, 0, []),
                0,
            ),
            txn([], [], rcpt(true, 0, []), 0),
        ],
        obd(),
    )
}

#[test]
fn alice_writes() {
    do_test(
        [(BEACON, acct()), (ALICE, acct())],
        [],
        [(BEACON, hpt()), (ALICE, hpt())],
        [],
        [
            txn(
                [(
                    ALICE,
                    TxnTrace {
                        storage_written: [(pos(ALICE, 0), 42.into())].into(),
                        ..Default::default()
                    },
                )],
                [],
                rcpt(true, 0, []),
                0,
            ),
            txn([], [], rcpt(true, 0, []), 0),
        ],
        obd(),
    )
}

#[test]
fn alice_writes_then_reads() {
    do_test(
        [(BEACON, acct()), (ALICE, acct())],
        [],
        [(BEACON, hpt()), (ALICE, hpt())],
        [],
        [
            txn(
                [(
                    ALICE,
                    TxnTrace {
                        storage_written: [(pos(ALICE, 0), 42.into())].into(),
                        ..Default::default()
                    },
                )],
                [],
                rcpt(true, 0, []),
                0,
            ),
            txn(
                [(
                    ALICE,
                    TxnTrace {
                        storage_read: [pos(ALICE, 0)].into(),
                        ..Default::default()
                    },
                )],
                [],
                rcpt(true, 0, []),
                0,
            ),
        ],
        obd(),
    )
}

fn do_test(
    state: impl Into<BTreeMap<Address, Account>>,
    deferred_state: impl Into<BTreeMap<TrieKey, B256>>,
    storage: impl Into<HashMap<Address, HashedPartialTrie>>,
    code_db: impl Into<BTreeSet<Vec<u8>>>,
    txn_info: impl Into<Vec<TxnInfo>>,
    obd: impl Into<OtherBlockData>,
) {
    let obd = obd.into();
    let bt = BlockTrace {
        trie_pre_images: BlockTraceTriePreImages::Separate(SeparateTriePreImages {
            state: SeparateTriePreImage::Direct({
                let mut hpt = HashedPartialTrie::default();
                for (k, v) in state.into() {
                    hpt.insert(
                        Nibbles::from_h256_be(keccak_hash::keccak(k)),
                        alloy::rlp::encode(v),
                    )
                    .unwrap()
                }
                for (k, h) in deferred_state.into() {
                    hpt.insert(k.into_nibbles(), h.compat()).unwrap()
                }
                hpt
            }),
            storage: SeparateStorageTriesPreImage::MultipleTries(
                storage
                    .into()
                    .into_iter()
                    .map(|(k, v)| (keccak_hash::keccak(k), SeparateTriePreImage::Direct(v)))
                    .collect(),
            ),
        }),
        code_db: code_db.into(),
        txn_info: txn_info.into(),
    };

    eprintln!("generate reference...");
    let mut reference = trace_decoder::entrypoint_old(bt.clone(), obd.clone(), 1, false)
        .expect("couldn't generate reference");
    eprintln!("generate subject...");
    let subject =
        trace_decoder::entrypoint_new(bt, obd, 1, false).expect("couldn't generate subject");

    for gi in &mut reference {
        gi.contract_code.insert(keccak_hash::keccak([]), vec![]);
    }

    let reference = str_repr(reference);
    pretty_assertions::assert_str_eq!(
        reference,
        str_repr(subject),
        "reference (left) != (right) subject"
    );
    println!("{reference}");

    #[track_caller]
    fn str_repr(src: Vec<evm_arithmetization::GenerationInputs>) -> String {
        serde_json::to_string_pretty(
            &src.into_iter()
                .map(common::repr::GenerationInputs::from)
                .collect::<Vec<_>>(),
        )
        .expect("unable to serialize")
    }
}
