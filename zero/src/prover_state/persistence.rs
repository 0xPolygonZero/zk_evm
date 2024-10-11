use std::{
    fmt::{Debug, Display},
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use alloy::hex;
use anyhow::anyhow;
use directories::ProjectDirs;
use evm_arithmetization::{
    cpu::kernel::aggregator::KERNEL, AllRecursiveCircuits, RecursionConfig,
    RecursiveCircuitsForTableSize, VerifierData, EXTENSION_DEGREE,
};
use once_cell::sync::Lazy;
use plonky2::util::serialization::{
    Buffer, DefaultGateSerializer, DefaultGeneratorSerializer, IoError,
};
use thiserror::Error;

use super::circuit::{Circuit, CircuitConfig};

const PROVER_STATE_FILE_PREFIX: &str = "prover_state";
const VERIFIER_STATE_FILE_PREFIX: &str = "verifier_state";
const ZK_EVM_CACHE_DIR_NAME: &str = "zk_evm_circuit_cache";
const ZK_EVM_CACHE_DIR_ENV: &str = "ZK_EVM_CACHE_DIR";

/// We version serialized circuits by the kernel hash they were serialized with,
/// but we really only need a few of the starting hex nibbles to reliably
/// differentiate.
const KERNEL_HASH_PREFIX: usize = 8;

/// When we serialize/deserialize circuits, we rely on the hash of the plonky
/// kernel to determine if the circuit is compatible with our current binary. If
/// the kernel hash of the circuit that we are loading in from disk differs,
/// then using these circuits would cause failures during proof generation
pub static KERNEL_HASH: Lazy<&'static str> = Lazy::new(|| {
    String::leak(
        hex::encode(KERNEL.hash())
            .chars()
            .take(KERNEL_HASH_PREFIX)
            .collect(),
    )
});

fn get_serializers() -> (
    DefaultGateSerializer,
    DefaultGeneratorSerializer<RecursionConfig, EXTENSION_DEGREE>,
) {
    let gate_serializer = DefaultGateSerializer;
    let witness_serializer: DefaultGeneratorSerializer<RecursionConfig, EXTENSION_DEGREE> =
        DefaultGeneratorSerializer::default();

    (gate_serializer, witness_serializer)
}

#[derive(Error, Debug)]
pub(crate) enum DiskResourceError<E> {
    #[error("Serialization error: {0}")]
    Serialization(E),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// A trait for generic resources that may be written to and read from disk,
/// each with their own serialization and deserialization logic.
pub(crate) trait DiskResource {
    /// The type of error that may arise while serializing or deserializing the
    /// resource.
    type Error: Debug + Display;
    /// The type of resource being serialized, deserialized, and written to
    /// disk.
    type Resource;
    /// The input type / configuration used to generate a unique path to the
    /// resource on disk.
    type PathConstrutor;

    /// Returns the path to the resource on disk.
    fn path(p: &Self::PathConstrutor) -> impl AsRef<Path>;

    /// Serializes the resource to bytes.
    fn serialize(r: &Self::Resource) -> Result<Vec<u8>, DiskResourceError<Self::Error>>;

    /// Deserializes the resource from bytes.
    fn deserialize(bytes: &[u8]) -> Result<Self::Resource, DiskResourceError<Self::Error>>;

    /// Reads the resource from disk and deserializes it.
    fn get(p: &Self::PathConstrutor) -> Result<Self::Resource, DiskResourceError<Self::Error>> {
        Self::deserialize(&fs::read(Self::path(p))?)
    }

    /// Writes the resource to disk after serializing it.
    fn put(
        p: &Self::PathConstrutor,
        r: &Self::Resource,
    ) -> Result<(), DiskResourceError<Self::Error>> {
        let circuits_dir = circuit_dir();

        // Create the base folder if non-existent.
        if std::fs::metadata(&circuits_dir).is_err() {
            std::fs::create_dir_all(&circuits_dir).map_err(|err| {
                DiskResourceError::IoError::<Self::Error>(std::io::Error::other(format!(
                    "Could not create circuits folder at {} (err: {})",
                    err, circuits_dir
                )))
            })?;
        }

        Ok(OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(Self::path(p))?
            .write_all(&Self::serialize(r)?)?)
    }
}

/// Pre-generated circuits containing just the three higher-level circuits.
/// These are sufficient for generating aggregation proofs and block
/// proofs, but not for transaction proofs.
#[derive(Debug, Default)]
pub(crate) struct BaseProverResource;

impl DiskResource for BaseProverResource {
    type Resource = AllRecursiveCircuits;
    type Error = IoError;
    type PathConstrutor = CircuitConfig;

    fn path(p: &Self::PathConstrutor) -> impl AsRef<Path> {
        format!(
            "{}/{}_base_{}_{}",
            circuit_dir(),
            PROVER_STATE_FILE_PREFIX,
            *KERNEL_HASH,
            p.get_configuration_digest()
        )
    }

    fn serialize(r: &Self::Resource) -> Result<Vec<u8>, DiskResourceError<Self::Error>> {
        let (gate_serializer, witness_serializer) = get_serializers();

        r
            // Note we are using the `true` flag to write only the upper circuits.
            // The individual circuit tables are written separately below.
            .to_bytes(true, &gate_serializer, &witness_serializer)
            .map_err(DiskResourceError::Serialization)
    }

    fn deserialize(bytes: &[u8]) -> Result<AllRecursiveCircuits, DiskResourceError<Self::Error>> {
        let (gate_serializer, witness_serializer) = get_serializers();
        AllRecursiveCircuits::from_bytes(bytes, true, &gate_serializer, &witness_serializer)
            .map_err(DiskResourceError::Serialization)
    }
}

/// Pre-generated circuits containing all circuits.
#[derive(Debug, Default)]
pub(crate) struct MonolithicProverResource;

impl DiskResource for MonolithicProverResource {
    type Resource = AllRecursiveCircuits;
    type Error = IoError;
    type PathConstrutor = CircuitConfig;

    fn path(p: &Self::PathConstrutor) -> impl AsRef<Path> {
        format!(
            "{}/{}_monolithic_{}_{}",
            circuit_dir(),
            PROVER_STATE_FILE_PREFIX,
            *KERNEL_HASH,
            p.get_configuration_digest()
        )
    }

    fn serialize(r: &Self::Resource) -> Result<Vec<u8>, DiskResourceError<Self::Error>> {
        let (gate_serializer, witness_serializer) = get_serializers();

        r
            // Note we are using the `false` flag to write all circuits.
            .to_bytes(false, &gate_serializer, &witness_serializer)
            .map_err(DiskResourceError::Serialization)
    }

    fn deserialize(bytes: &[u8]) -> Result<AllRecursiveCircuits, DiskResourceError<Self::Error>> {
        let (gate_serializer, witness_serializer) = get_serializers();
        AllRecursiveCircuits::from_bytes(bytes, false, &gate_serializer, &witness_serializer)
            .map_err(DiskResourceError::Serialization)
    }
}

/// An individual circuit table with a specific size.
#[derive(Debug, Default)]
pub(crate) struct RecursiveCircuitResource;

impl DiskResource for RecursiveCircuitResource {
    type Resource = RecursiveCircuitsForTableSize;
    type Error = IoError;
    type PathConstrutor = (Circuit, usize);

    fn path((circuit_type, size): &Self::PathConstrutor) -> impl AsRef<Path> {
        format!(
            "{}/{}_{}_{}_{}",
            circuit_dir(),
            PROVER_STATE_FILE_PREFIX,
            *KERNEL_HASH,
            circuit_type.as_short_str(),
            size
        )
    }

    fn serialize(r: &Self::Resource) -> Result<Vec<u8>, DiskResourceError<Self::Error>> {
        let (gate_serializer, witness_serializer) = get_serializers();
        let mut buf = Vec::new();

        r.to_buffer(&mut buf, &gate_serializer, &witness_serializer)
            .map_err(DiskResourceError::Serialization)?;

        Ok(buf)
    }

    fn deserialize(
        bytes: &[u8],
    ) -> Result<RecursiveCircuitsForTableSize, DiskResourceError<Self::Error>> {
        let (gate_serializer, witness_serializer) = get_serializers();
        let mut buffer = Buffer::new(bytes);
        RecursiveCircuitsForTableSize::from_buffer(
            &mut buffer,
            &gate_serializer,
            &witness_serializer,
        )
        .map_err(DiskResourceError::Serialization)
    }
}

/// An individual circuit table with a specific size.
#[derive(Debug, Default)]
pub(crate) struct VerifierResource;

impl DiskResource for VerifierResource {
    type Resource = VerifierData;
    type Error = IoError;
    type PathConstrutor = CircuitConfig;

    fn path(p: &Self::PathConstrutor) -> impl AsRef<Path> {
        format!(
            "{}/{}_{}_{}",
            circuit_dir(),
            VERIFIER_STATE_FILE_PREFIX,
            *KERNEL_HASH,
            p.get_configuration_digest()
        )
    }

    fn serialize(r: &Self::Resource) -> Result<Vec<u8>, DiskResourceError<Self::Error>> {
        let (gate_serializer, _witness_serializer) = get_serializers();
        r.to_bytes(&gate_serializer)
            .map_err(DiskResourceError::Serialization)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self::Resource, DiskResourceError<Self::Error>> {
        let (gate_serializer, _) = get_serializers();
        VerifierData::from_bytes(bytes.to_vec(), &gate_serializer)
            .map_err(DiskResourceError::Serialization)
    }
}

/// Writes the provided [`AllRecursiveCircuits`] to disk with all
/// configurations, along with the associated [`VerifierData`].
pub fn persist_all_to_disk(
    circuits: &AllRecursiveCircuits,
    circuit_config: &CircuitConfig,
) -> anyhow::Result<()> {
    prover_to_disk(circuit_config, circuits)?;
    VerifierResource::put(circuit_config, &circuits.final_verifier_data())?;

    Ok(())
}

/// Flushes all existing prover state configurations and associated circuits
/// that have been written to disk.
pub fn delete_all() -> anyhow::Result<()> {
    let circuit_dir = circuit_dir();
    let path = Path::new(&circuit_dir);

    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let file_path = entry.path();

            if file_path.is_file()
                && (entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("prover_state")
                    || entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with("verifier_state"))
            {
                // Delete all circuit files.
                fs::remove_file(file_path)?;
            }
        }
    }

    Ok(())
}

/// Writes the provided [`AllRecursiveCircuits`] to disk.
///
/// In particular, we cover both the monolothic and base prover states, as well
/// as the individual circuit tables.
fn prover_to_disk(
    circuit_config: &CircuitConfig,
    circuits: &AllRecursiveCircuits,
) -> Result<(), DiskResourceError<IoError>> {
    BaseProverResource::put(circuit_config, circuits)?;
    MonolithicProverResource::put(circuit_config, circuits)?;

    // Write individual circuit tables to disk, by circuit type and size. This
    // allows us to load only the necessary tables when needed.
    for (circuit_type, tables) in circuits.by_table.iter().enumerate() {
        let circuit_type: Circuit = circuit_type.into();
        for (size, table) in tables.by_stark_size.iter() {
            RecursiveCircuitResource::put(&(circuit_type, *size), table)?;
        }
    }

    Ok(())
}

fn circuit_dir() -> String {
    // Guaranteed to be set by the binary if not set by the user.
    std::env::var(ZK_EVM_CACHE_DIR_ENV).unwrap_or_else(|_| {
        panic!(
            "expected the env var \"{}\" to be set",
            ZK_EVM_CACHE_DIR_ENV
        )
    })
}

/// We store serialized circuits inside the cache directory specified by an env
/// variable. If the user does not set this, then we set it base to the OS's
/// standard location for the cache directory.
pub fn set_circuit_cache_dir_env_if_not_set() -> anyhow::Result<()> {
    let circuit_cache_dir = if let Some(path_str) = std::env::var_os(ZK_EVM_CACHE_DIR_ENV) {
        PathBuf::from(&path_str)
    } else {
        match ProjectDirs::from("", "", ZK_EVM_CACHE_DIR_NAME) {
            Some(proj_dir) => proj_dir.cache_dir().to_path_buf(),
            None => std::env::current_dir()?,
        }
    };

    // Sanity check on naming convention for the circuit cache directory.
    if let Some(path_str) = Path::new(&circuit_cache_dir).to_str() {
        if !path_str.ends_with("_circuit_cache") {
            return Err(anyhow!(
            "zkEVM circuit cache directory {:?} does not follow convention of ending with \"_circuit_cache\".", path_str
        ));
        }
    }

    std::env::set_var(ZK_EVM_CACHE_DIR_ENV, circuit_cache_dir);

    Ok(())
}
