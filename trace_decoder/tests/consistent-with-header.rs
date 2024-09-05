//! Check that the [`evm_arithmetization::GenerationInputs`] produced by
//! [`trace_decoder`] are consistent between each other, and with the block
//! header obtained over RPC.

mod common;

use alloy_compat::Compat as _;
use assert2::check;
use common::{cases, Case};
use itertools::Itertools;
use libtest_mimic::{Arguments, Trial};
use mpt_trie::partial_trie::PartialTrie as _;

fn main() -> anyhow::Result<()> {
    let mut trials = vec![];
    for Case {
        name,
        header,
        trace,
        other,
    } in cases()?
    {
        trials.push(Trial::test(name, move || {
            let gis = trace_decoder::entrypoint(trace.clone(), other.clone(), 3, false)
                .map_err(|e| format!("{e:?}"))?; // get the full cause chain
            check!(gis.len() >= 2);
            check!(other.checkpoint_state_trie_root == gis[0].tries.state_trie.hash());
            let pairs = || gis.iter().tuple_windows::<(_, _)>();
            check!(
                pairs().position(|(before, after)| {
                    before.trie_roots_after.state_root != after.tries.state_trie.hash()
                }) == None
            );
            check!(
                pairs().position(|(before, after)| {
                    before.trie_roots_after.receipts_root != after.tries.receipts_trie.hash()
                }) == None
            );
            check!(
                pairs().position(|(before, after)| {
                    before.trie_roots_after.transactions_root
                        != after.tries.transactions_trie.hash()
                }) == None
            );
            check!(
                gis.last().map(|it| it.trie_roots_after.state_root.compat())
                    == Some(header.state_root)
            );
            check!(
                gis.iter()
                    .position(|it| it.block_metadata.block_timestamp != header.timestamp.into())
                    == None
            );
            check!(
                gis.iter().position(|it| it
                    .block_hashes
                    .prev_hashes
                    .last()
                    .is_some_and(|it| *it != header.parent_hash.compat()))
                    == None
            );
            Ok(())
        }));
    }
    libtest_mimic::run(&Arguments::from_args(), trials).exit()
}
