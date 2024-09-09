use common::{cases, Case};
use itertools::Itertools;
use mpt_trie::partial_trie::PartialTrie;
use trace_decoder::{BlockTraceTriePreImages, CombinedPreImages};

mod common;

fn main() -> anyhow::Result<()> {
    for Case { name, trace, .. } in cases().unwrap() {
        let BlockTraceTriePreImages::Combined(CombinedPreImages { compact }) =
            trace.trie_pre_images
        else {
            panic!()
        };
        let whole = trace_decoder::frontend(trace_decoder::parse(&compact).unwrap())
            .unwrap()
            .state
            .as_hashed_partial_trie()
            .clone();
        let all_keys = whole.keys().collect::<Vec<_>>();
        let len = all_keys.len();
        for n in 0..len {
            println!("{name}\t{n}\t{len}");
            for comb in all_keys.iter().copied().combinations(n) {
                if let Ok(sub) = mpt_trie::trie_subsets::create_trie_subset(&whole, comb.clone()) {
                    assert_eq!(sub.hash(), whole.hash(), "{comb:?}")
                }
            }
        }
    }
    Ok(())
}
