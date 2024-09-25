zk_evm_common::check_chain_features!();

pub mod block_interval;
pub mod debug_utils;
pub mod env;
pub mod fs;
pub mod intra_block_tries;
pub mod ops;
pub mod parsing;
pub mod pre_checks;
pub mod proof_types;
pub mod prover;
pub mod prover_state;
pub mod provider;
pub mod rpc;
pub mod trace_decoder;
pub mod tracing;
pub mod trie_diff;
pub mod typed_mpt;
pub mod wire_tries;

/// Size of the channel used to send block prover inputs to the per block
/// proving task. If the proving task is slow and can not consume inputs fast
/// enough retrieval of the block prover inputs will block until the proving
/// task consumes some of the inputs.
pub const BLOCK_CHANNEL_SIZE: usize = 16;

/// Common information for the `--version` CLI flags.
pub fn version() -> String {
    let pkg_name = env!("CARGO_PKG_NAME");
    let git_describe = env!("VERGEN_GIT_DESCRIBE");
    let timestamp = env!("VERGEN_BUILD_TIMESTAMP");
    let kernel_hash = &**prover_state::persistence::KERNEL_HASH;
    format!("{pkg_name} ({git_describe}) (kernel hash: {kernel_hash}) [built: {timestamp}]")
}

/// Like `#[serde(with = "::hex")]`, but tolerates and emits leading `0x`
/// prefixes
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
