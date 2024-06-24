//! Output for provers
// std imports
use std::{env::VarError, fs::create_dir_all, path::PathBuf};

use proof_gen::proof_types::GeneratedBlockProof;
use serde_json::to_writer;
// 3rd party imports
use tracing::{debug, error, info, warn};

#[derive(Debug)]
pub enum ProofOutputError {
    FileCreationError(anyhow::Error),
    FileWritingError(anyhow::Error),
    MethodDataMismatch,
}

impl std::fmt::Display for ProofOutputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self, f)
    }
}

impl std::error::Error for ProofOutputError {}

#[derive(Debug)]
pub enum ProofOutputBuildError {
    DirectoryCreation(anyhow::Error),
}

impl std::fmt::Display for ProofOutputBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self, f)
    }
}

impl std::error::Error for ProofOutputBuildError {}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ProofOutputMethod {
    /// Stores the proofs locally
    LocalDirectory {
        /// The prefix to attach to the proofs, where it would be prefix_1 for
        /// block 1, prefix_n for block n, etc
        prefix: String,
    },
}

#[derive(Debug, Clone)]
pub enum ProofOutputData {
    LocalDirectory { dirpath: PathBuf },
    NotApplicable,
}

#[derive(Debug)]
pub struct ProofOutput {
    /// The configuration of the ProofOutput
    pub method: ProofOutputMethod,
    /// The proof outpudata data dependent on the config.
    pub data: ProofOutputData,
}

pub const PROOF_OUT_LOCAL_DIR_ENVKEY: &str = "PROOF_OUT_LOCAL_DIRPATH";
pub const PROOF_OUT_LOCAL_DIR_DFLT: &str = "proofs_out/";

impl ProofOutput {
    pub fn from_method(method: &ProofOutputMethod) -> Result<Self, ProofOutputBuildError> {
        match method {
            ProofOutputMethod::LocalDirectory { prefix: _ } => {
                let dirpath = match std::env::var(PROOF_OUT_LOCAL_DIR_ENVKEY) {
                    Ok(dirpath_str) => {
                        info!("Using {} for proof output directory path", dirpath_str);
                        PathBuf::from(dirpath_str)
                    }
                    Err(VarError::NotPresent) => {
                        warn!(
                            "No proof out directory, using default: {}",
                            PROOF_OUT_LOCAL_DIR_DFLT
                        );
                        PathBuf::from(PROOF_OUT_LOCAL_DIR_DFLT)
                    }
                    Err(VarError::NotUnicode(os_str)) => {
                        panic!("Non-Unicode proof out local directory: {:?}", os_str);
                    }
                };

                match (dirpath.exists(), dirpath.is_dir()) {
                    (true, true) => debug!("`{:?}` is pre-existing directory", dirpath),
                    (true, false) => {
                        panic!("ProofOutput directory is not a directory: {:?}", dirpath)
                    }
                    (false, _) => {
                        info!("Creating directory: {:?}", dirpath);
                        match create_dir_all(dirpath.clone()) {
                            Ok(_) => debug!("Successfully created directory: {:?}", dirpath),
                            Err(err) => {
                                error!("Failed to create directory {:?}: {}", dirpath, err);
                                return Err(ProofOutputBuildError::DirectoryCreation(err.into()));
                            }
                        }
                    }
                };

                Ok(Self {
                    method: method.clone(),
                    data: ProofOutputData::LocalDirectory { dirpath },
                })
            }
        }
    }

    pub fn write(&self, proof: &GeneratedBlockProof) -> Result<(), ProofOutputError> {
        debug!("Attempting to output proof for block {}", proof.b_height);
        match (&self.method, &self.data) {
            (
                ProofOutputMethod::LocalDirectory { prefix },
                ProofOutputData::LocalDirectory { dirpath },
            ) => {
                let filepath = dirpath.join(format!("{}_{}.json", prefix, proof.b_height));
                // Attempt to create the file
                let file = match std::fs::File::create(filepath.clone()) {
                    Ok(file) => file,
                    Err(err) => {
                        error!("Failed to create file `{:?}`: {}", filepath, err);
                        return Err(ProofOutputError::FileCreationError(err.into()));
                    }
                };
                // Attempt to write to file
                match to_writer(file, &proof.intern) {
                    Ok(_) => info!("Sucessfully wrote proof to {:?}", filepath),
                    Err(err) => {
                        error!("Failed to write to file `{:?}`: {}", filepath, err);
                        return Err(ProofOutputError::FileWritingError(err.into()));
                    }
                }
                Ok(())
            }
            (_, _) => Err(ProofOutputError::MethodDataMismatch),
        }
    }
}
