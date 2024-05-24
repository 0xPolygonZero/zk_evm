use crate::cfg_if;

pub mod compact_debug_tools;
pub(crate) mod compact_processing_common;

#[cfg(test)]
mod compact_testing;

cfg_if! {
    if #[cfg(feature = "mpt")] {
        pub mod compact_mpt_processing;
        pub mod compact_to_mpt_trie;
    } else if #[cfg(feature = "smt")] {
        pub mod compact_smt_processing;
        pub mod compact_to_smt_trie;
    }
}
