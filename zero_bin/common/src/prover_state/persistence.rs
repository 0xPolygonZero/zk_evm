use std::env;
use std::{
    fmt::{Debug, Display},
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

use plonky2::util::serialization::{
    Buffer, DefaultGateSerializer, DefaultGeneratorSerializer, IoError,
};
use proof_gen::types::{AllRecursiveCircuits, VerifierData};
use thiserror::Error;

use super::{
    circuit::{Circuit, CircuitConfig},
    Config, RecursiveCircuitsForTableSize, SIZE,
};

const CIRCUITS_FOLDER: &str = "./circuits";
const PROVER_STATE_FILE_PREFIX: &str = "prover_state";
const VERIFIER_STATE_FILE_PREFIX: &str = "verifier_state";

fn get_serializers() -> (
    DefaultGateSerializer,
    DefaultGeneratorSerializer<Config, SIZE>,
) {
    let gate_serializer = DefaultGateSerializer;
    let witness_serializer: DefaultGeneratorSerializer<Config, SIZE> =
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
        // Create the base folder if non-existent.
        if std::fs::metadata(CIRCUITS_FOLDER).is_err() {
            std::fs::create_dir(CIRCUITS_FOLDER).map_err(|_| {
                DiskResourceError::IoError::<Self::Error>(std::io::Error::other(
                    "Could not create circuits folder",
                ))
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
            CIRCUITS_FOLDER,
            PROVER_STATE_FILE_PREFIX,
            env::var("EVM_ARITHMETIZATION_PKG_VER").unwrap_or("NA".to_string()),
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
            CIRCUITS_FOLDER,
            PROVER_STATE_FILE_PREFIX,
            env::var("EVM_ARITHMETIZATION_PKG_VER").unwrap_or("NA".to_string()),
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
            CIRCUITS_FOLDER,
            PROVER_STATE_FILE_PREFIX,
            env::var("EVM_ARITHMETIZATION_PKG_VER").unwrap_or("NA".to_string()),
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
            CIRCUITS_FOLDER,
            VERIFIER_STATE_FILE_PREFIX,
            env::var("EVM_ARITHMETIZATION_PKG_VER").unwrap_or("NA".to_string()),
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
