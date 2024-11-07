//! An _Ethereum Node_ executes _transactions_ in _blocks_.
//!
//! Execution mutates two key data structures:
//! - [The state](https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/#state-trie),
//!   which tracks, e.g the account balance.
//! - [The storage](https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/#storage-trie),
//!   which is a huge array of integers, per-account.
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
//! The aformentioned data structures are represented as tries,
//! which may have subtries _hashed out_.
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

/// Over RPC, ethereum nodes expose their tries as a series of binary
/// [`wire::Instruction`]s in a node-dependant format.
///
/// These are parsed into the relevant state and storage data structures,
/// depending on the node:
///    - [`type2`], which contains an [`smt_trie`].
///    - [`type1`], which contains an [`mpt_trie`].
///
/// After getting the tries,
/// we can continue to do the main work of "executing" the transactions.
///
/// The core of this library is agnostic over the (combined)
/// state and storage representation - see [`evm_arithmetization::world::World`]
/// for more.
const _DEVELOPER_DOCS: () = ();

mod interface;
pub use interface::*;

mod type1;
mod type2;
mod wire;

mod core;
pub use core::{entrypoint, WireDisposition};

/// Implementation of the observer for the trace decoder.
pub mod observer;
