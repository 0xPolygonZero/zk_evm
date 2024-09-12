//! An _Ethereum Node_ executes _transactions_ in _blocks_.
//!
//! Execution mutates two key data structures:
//! - [The state trie](https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/#state-trie).
//! - [The storage tries](https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/#storage-trie).
//!
//! Ethereum nodes expose information about the transactions over RPC, e.g:
//! - [The specific changes to the storage tries](TxnTrace::storage_written).
//! - [Changes to account balance in the state trie](TxnTrace::balance).
//!
//! The state execution correctness is then asserted by the zkEVM prover in
//! [`evm_arithmetization`], relying on `starky` and [`plonky2`].
//!
//! **Prover perfomance is a high priority.**
//!
//! The aformentioned trie structures may have subtries _hashed out_.
//! That is, any node (and its children!) may be replaced by its hash,
//! while maintaining provability of its contents:
//!
//! ```text
//!     A               A
//!    / \             / \
//!   B   C     ->    H   C
//!  / \   \               \
//! D   E   F               F
//! ```
//! (where `H` is the hash of the `D/B\E` subtrie).
//!
//! The principle concern of this module is to step through the transactions,
//! and reproduce the _intermediate tries_,
//! while hashing out all possible subtries to minimise prover load
//! (since prover performance is sensitive to the size of the trie).
//! The prover can therefore prove each batch of transactions independently.
//!
//! # Non-goals
//! - Performance - this will never be the bottleneck in any proving stack.
//! - Robustness - this library depends on other libraries that are not robust,
//!   so may panic at any time.

#![deny(rustdoc::broken_intra_doc_links)]
#![warn(missing_debug_implementations)]
#![warn(missing_docs)]

zk_evm_common::check_chain_features!();

/// Over RPC, ethereum nodes expose their tries as a series of binary
/// [`wire::Instruction`]s in a node-dependant format.
///
/// These are parsed into the relevant trie depending on the node:
///    - [`type2`], which contains an [`smt_trie`].
///    - [`type1`], which contains an [`mpt_trie`].
///
/// After getting the tries,
/// we can continue to do the main work of "executing" the transactions.
const _DEVELOPER_DOCS: () = ();

mod interface;

pub use interface::*;

mod type1;
// TODO(0xaatif): https://github.com/0xPolygonZero/zk_evm/issues/275
//                add backend/prod support for type 2
#[cfg(test)]
#[allow(dead_code)]
mod type2;
mod typed_mpt;
mod wire;

pub use core::entrypoint;

mod core;

/// Like `#[serde(with = "hex")`, but tolerates and emits leading `0x` prefixes
mod hex {
    use serde::{de::Error as _, Deserialize as _, Deserializer, Serializer};

    pub fn serialize<S: Serializer, T>(data: T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: hex::ToHex,
    {
        let s = data.encode_hex::<String>();
        serializer.serialize_str(&format!("0x{}", s))
    }

    pub fn deserialize<'de, D: Deserializer<'de>, T>(deserializer: D) -> Result<T, D::Error>
    where
        T: hex::FromHex,
        T::Error: std::fmt::Display,
    {
        let s = String::deserialize(deserializer)?;
        match s.strip_prefix("0x") {
            Some(rest) => T::from_hex(rest),
            None => T::from_hex(&*s),
        }
        .map_err(D::Error::custom)
    }
}

#[cfg(test)]
#[derive(serde::Deserialize)]
struct Case {
    #[serde(with = "hex")]
    pub bytes: Vec<u8>,
    #[serde(deserialize_with = "h256")]
    pub expected_state_root: ethereum_types::H256,
}

#[cfg(test)]
fn h256<'de, D: serde::Deserializer<'de>>(it: D) -> Result<ethereum_types::H256, D::Error> {
    Ok(ethereum_types::H256(hex::deserialize(it)?))
}
