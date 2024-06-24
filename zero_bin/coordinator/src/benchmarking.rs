//! This module contains a lot of the important data for benchmarking purposes.
//!
//! TODO: Switch to using the CSV trait, it'll probably be easier
use std::{fs::create_dir_all, io::Write, path::PathBuf, thread::sleep, time::Duration};

use chrono::{DateTime, Utc};
use google_cloud_storage::{
    client::{Client, ClientConfig},
    http::objects::upload::{Media, UploadObjectRequest, UploadType},
};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

//==================================================================================
// Benchmarking Statistics
//==================================================================================

/// The Benchmarking Statistics used during the proof of a singular Block.
#[derive(Debug, Clone)]
pub struct BenchmarkingStats {
    /// The block number of the block proved
    pub block_number: u64,
    /// The number of transactions in the block proved
    pub n_txs: u64,
    /// The cumulative transaction count.  This is the number of transactions
    /// from this block and all blocks beforehand.  None implies data not
    /// available, not 0.
    pub cumulative_n_txs: Option<u64>,
    /// The duration fo time took to fetch [prover::ProverInput], stored as a
    /// [Duration].
    pub fetch_duration: Duration,
    /// The amount of time elapsed during the process of proving this block,
    /// stored as a [Duration]
    pub total_proof_duration: Duration,

    pub prep_duration: Option<Duration>,
    pub txproof_duration: Option<Duration>,
    pub agg_duration: Option<Duration>,
    /// The start time of the proof.  [BenchmarkingStats::proof_duration] is a
    /// more reliable value to use for the proof duration.  Timestamps measured
    /// in UTC.
    pub start_time: DateTime<Utc>,
    /// The end time of the proof.  [BenchmarkingStats::proof_duration] is a
    /// more reliable value to use for the proof duration.  Timestamps measured
    /// in UTC.
    pub end_time: DateTime<Utc>,
    /// The number of seconds elapsed from the first block in the benchmarking
    /// process and the end of the current block being proven
    pub overall_elapsed_seconds: Option<u64>,
    /// The amount of time elapsed during the process of saving this block's
    /// proof to its output, stored as a [Duration]
    pub proof_out_duration: Option<Duration>,
    /// The gas used by the block we proved
    pub gas_used: u64,
    /// The gas used per transaction in the block in the original chain
    pub gas_used_per_tx: Vec<u64>,
    /// The cumulative gas used by the block we proved.  None implies
    /// not filled in, not 0.
    pub cumulative_gas_used: Option<u64>,
    /// The difficulty of the block we proved
    pub difficulty: u64,
}

impl BenchmarkingStats {
    /// Returns a header row
    pub fn header_row() -> String {
        String::from(
            "block_number, number_txs, cumulative_number_txs, fetch_duration, unique_proof_duration, prep_duration, txproof_duration, agg_duration, start_time, end_time, cumulative_elapsed_time, proof_out_duration, gas_used, cumulative_gas_used, difficulty, gas_used_per_tx",
        )
    }

    /// Given a vector of [BenchmarkingStats],
    pub fn vec_to_string(vector: Vec<BenchmarkingStats>) -> String {
        vector
            .into_iter()
            .map(|bs| bs.as_csv_row())
            .collect::<Vec<String>>()
            .join("\n")
    }

    /// Given a vector of [BenchmarkingStats], returns a String of the CSV
    /// Header.
    pub fn vec_to_csv_string(vector: Vec<BenchmarkingStats>) -> String {
        format!("{}\n{}", Self::header_row(), Self::vec_to_string(vector))
    }

    fn unwrap_to_string<T: ToString>(item: Option<T>) -> String {
        match item {
            Some(item) => item.to_string(),
            None => String::from(""),
        }
    }

    fn unwrap_duration_to_string(item: Option<Duration>) -> String {
        match item {
            Some(item) => item.as_secs_f64().to_string(),
            None => String::from(""),
        }
    }

    /// Turns [BenchmarkingStats] into a CSV Row
    #[allow(clippy::format_in_format_args)]
    pub fn as_csv_row(&self) -> String {
        format!(
            "{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, \"{}\"",
            self.block_number,
            self.n_txs,
            Self::unwrap_to_string(self.cumulative_n_txs),
            self.fetch_duration.as_secs_f64(),
            self.total_proof_duration.as_secs_f64(),
            Self::unwrap_duration_to_string(self.prep_duration),
            Self::unwrap_duration_to_string(self.txproof_duration),
            Self::unwrap_duration_to_string(self.agg_duration),
            self.start_time.format("%d-%m-%Y %H:%M:%S"),
            self.end_time.format("%d-%m-%Y %H:%M:%S"),
            Self::unwrap_to_string(self.overall_elapsed_seconds),
            Self::unwrap_duration_to_string(self.proof_out_duration),
            self.gas_used,
            Self::unwrap_to_string(self.cumulative_gas_used),
            self.difficulty,
            self.gas_used_per_tx
                .iter()
                .map(|gas| gas.to_string())
                .collect::<Vec<String>>()
                .join(";"),
        )
    }
}

//==================================================================================
// Benchmarking Output
//==================================================================================

//----------------------------------------------------------------------------------
// Benchmarking Output Config
//----------------------------------------------------------------------------------

/// The output method for benchmarking statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BenchmarkOutputConfig {
    /// Store the csv file locally
    LocalCsv {
        /// The name of the file to be used
        file_name: String,
    },
    /// Store the csv file output on Google Cloud Storage
    GoogleCloudStorageCsv {
        /// The name of the file (gcs obj) to be used
        file_name: String,
        /// The name of the bucket to be used
        bucket: String,
    },
}

//----------------------------------------------------------------------------------
// Benchmarking Output Building
//----------------------------------------------------------------------------------
#[derive(Debug)]
pub enum BenchmarkingOutputBuildError {
    GoogleCloudAuth(anyhow::Error),
    Directory(Option<anyhow::Error>),
}

impl std::fmt::Display for BenchmarkingOutputBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self, f)
    }
}

impl std::error::Error for BenchmarkingOutputBuildError {}

#[derive(Clone)]
pub enum BenchmarkingOutputData {
    /// The GoogleCloudStorage client
    GoogleCloudStorageCsv { gcs_client: Client },
    /// The LocalCsv directory path
    LocalCsv { dirpath: PathBuf },
    /// When additional data is not necessary, this is returned.
    NotApplicable,
}

impl BenchmarkingOutputData {
    pub async fn from_config(
        config: &BenchmarkOutputConfig,
    ) -> Result<Self, BenchmarkingOutputBuildError> {
        match config {
            BenchmarkOutputConfig::GoogleCloudStorageCsv {
                file_name: _,
                bucket: _,
            } => {
                // Produce the GCP Config
                let gcp_config = match ClientConfig::default().with_auth().await {
                    Ok(gcp_config) => {
                        info!("GCS ClientConfig generated with auth");
                        gcp_config
                    }
                    Err(err) => {
                        error!("Failed to authenticate with GCS: {}", err);
                        return Err(BenchmarkingOutputBuildError::GoogleCloudAuth(err.into()));
                    }
                };
                // Return the Client
                info!("Returning GCS Client");
                Ok(Self::GoogleCloudStorageCsv {
                    gcs_client: Client::new(gcp_config),
                })
            }
            BenchmarkOutputConfig::LocalCsv { file_name: _ } => {
                let output_dir_str = match std::env::var(BENCHMARK_OUT_DIR_ENVKEY) {
                    Ok(dirpath_str) => dirpath_str,
                    Err(std::env::VarError::NotPresent) => {
                        warn!(
                            "Using default output benchmark directory: {}",
                            BENCHMARK_OUT_DIR_DFLT
                        );
                        String::from(BENCHMARK_OUT_DIR_DFLT)
                    }
                    Err(std::env::VarError::NotUnicode(os_str)) => {
                        error!("Non-Unicode output benchmark directory: {:?}", os_str);
                        panic!("Non-Unicode output benchmark directory: {:?}", os_str);
                    }
                };

                let dirpath = PathBuf::from(output_dir_str);

                match (dirpath.exists(), dirpath.is_dir()) {
                    (false, _) => match create_dir_all(dirpath.clone()) {
                        Ok(_) => {
                            info!("Created directory for benchmark out: {:?}", dirpath);
                        }
                        Err(err) => {
                            error!("Failed to create directory {:?}: {}", dirpath, err);
                            return Err(BenchmarkingOutputBuildError::Directory(Some(err.into())));
                        }
                    },
                    (true, false) => {
                        error!("Directory path is not a directory: {:?}", dirpath);
                        return Err(BenchmarkingOutputBuildError::Directory(None));
                    }
                    (true, true) => {
                        info!(
                            "Using pre-existing directory for benchmark output: {:?}",
                            dirpath
                        );
                    }
                }

                Ok(Self::LocalCsv { dirpath })
            }
            #[allow(unreachable_patterns)]
            _ => Ok(Self::NotApplicable),
        }
    }
}

//----------------------------------------------------------------------------------
// Benchmarking Output Object
//----------------------------------------------------------------------------------
#[derive(Debug)]
pub enum BenchmarkingOutputError {
    InvalidOutputConfigOrData,
    /// Returned whenever we fail to upload to GCS.  Contains the last
    /// error returned
    GoogleCloudStorageFailedUpload(anyhow::Error),
    FileCreation(PathBuf, anyhow::Error),
    FileWrite(PathBuf, anyhow::Error),
}

impl std::fmt::Display for BenchmarkingOutputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self, f)
    }
}

impl std::error::Error for BenchmarkingOutputError {}

//      GCS CONSTANTS
/// The maximum number of attempts to upload to GCS
pub const MAX_GCS_UPLOAD_ATTEMPTS: u64 = 50;
/// The number of seconds to wait between attempts to upload to GCS
pub const GCS_FAILED_UPLOAD_SLEEP_SECS: u64 = 5;
//      LOCAL CSV CONSTANTS
/// The environment key to get the benchmark output
pub const BENCHMARK_OUT_DIR_ENVKEY: &str = "BENCHMARK_OUTDIR";
/// The default directory for benchmark out
pub const BENCHMARK_OUT_DIR_DFLT: &str = "benchmark_out/";

/// The [BenchmarkingOutput] is the means of outputting
pub struct BenchmarkingOutput {
    config: BenchmarkOutputConfig,
    data: BenchmarkingOutputData,
    pub stats: Vec<BenchmarkingStats>,
}

impl BenchmarkingOutput {
    pub async fn from_config(
        config: BenchmarkOutputConfig,
        init_capacity: Option<u64>,
    ) -> Result<Self, BenchmarkingOutputBuildError> {
        Ok(BenchmarkingOutput {
            data: BenchmarkingOutputData::from_config(&config).await?,
            config,
            stats: match init_capacity {
                Some(capacity) => Vec::with_capacity(capacity as usize),
                None => Vec::new(),
            },
        })
    }

    /// Pushes a [BenchmarkingOutput] to the list of stats we are storing to
    /// later be published.
    pub fn push(&mut self, benchmark_stats: BenchmarkingStats) {
        self.stats.push(benchmark_stats)
    }

    /// Finalizes the output (i.e. pushes to bucket, outputs file, etc)
    pub async fn publish(&self) -> Result<(), BenchmarkingOutputError> {
        match (&self.config, &self.data) {
            (
                BenchmarkOutputConfig::GoogleCloudStorageCsv { file_name, bucket },
                BenchmarkingOutputData::GoogleCloudStorageCsv { gcs_client },
            ) => {
                info!("Attempting to upload to GCS");
                let csv_string = BenchmarkingStats::vec_to_csv_string(self.stats.clone());
                debug!("Benchmark stats successfully turned into CSV string.");
                let mut attempt_n: u64 = 0;
                loop {
                    debug!("Starting attempt n {} to upload", attempt_n);
                    let uploaded = gcs_client
                        .upload_object(
                            &UploadObjectRequest {
                                bucket: bucket.clone(),
                                ..Default::default()
                            },
                            csv_string.clone(),
                            &UploadType::Simple(Media::new(file_name.clone())),
                        )
                        .await;

                    match uploaded {
                        Ok(_) => {
                            info!(
                                "Successfully uploaded {} to GCS bucket {}",
                                file_name, bucket
                            );
                            return Ok(());
                        }
                        // Catch error if less than allotted attempts
                        Err(err) if attempt_n < MAX_GCS_UPLOAD_ATTEMPTS => {
                            error!(
                                "Failed attempt #{} to upload {} to GCS bucket {}: {}",
                                attempt_n, file_name, bucket, err
                            );
                            info!("Waiting {} seconds before attempting to upload {} to GCS bucket {} again...", GCS_FAILED_UPLOAD_SLEEP_SECS, file_name, bucket);
                            attempt_n += 1;
                            sleep(Duration::from_secs(GCS_FAILED_UPLOAD_SLEEP_SECS));
                            continue;
                        }
                        // Give up
                        Err(err) => {
                            error!("Failed attempt #{} to upload {} to GCS bucket {} too many times: {}", attempt_n, file_name, bucket, err);
                            return Err(BenchmarkingOutputError::GoogleCloudStorageFailedUpload(
                                err.into(),
                            ));
                        }
                    }
                }
            }
            (
                BenchmarkOutputConfig::LocalCsv { file_name },
                BenchmarkingOutputData::LocalCsv { dirpath },
            ) => {
                let file_path = dirpath.join(file_name);
                debug!("Attempting to create file: {:?}", file_path);
                let mut file = match std::fs::File::create(file_path.clone()) {
                    Ok(file) => {
                        info!("Created file: {}", file_name);
                        file
                    }
                    Err(err) => {
                        error!("Failed to create file {} due to {}", file_name, err);
                        return Err(BenchmarkingOutputError::FileCreation(
                            file_path.clone(),
                            err.into(),
                        ));
                    }
                };
                debug!("Attempting to write benchmark stats to {:?}", file_path);
                match file
                    .write_all(BenchmarkingStats::vec_to_csv_string(self.stats.clone()).as_bytes())
                {
                    Ok(_) => info!("Successfully wrote benchmark stats to {:?}", file_path),
                    Err(err) => {
                        error!("Failed to write to file `{:?}`: {}", file_path, err);
                        return Err(BenchmarkingOutputError::FileWrite(
                            file_path.clone(),
                            err.into(),
                        ));
                    }
                }
                Ok(())
            }
            (_, _) => {
                error!("Cannot publish, invalid output config / data combination");
                Err(BenchmarkingOutputError::InvalidOutputConfigOrData)
            }
        }
    }
}
