use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use alloy::primitives::U256;
use anyhow::{bail, Result};
use axum::{http::StatusCode, routing::post, Json, Router};
use paladin::runtime::Runtime;
use serde::{Deserialize, Serialize};
use serde_json::to_writer;
use tracing::{debug, error, info};
use zero::proof_types::GeneratedBlockProof;
use zero::prover::{BlockProverInput, ProverConfig};

/// The main function for the HTTP mode.
pub(crate) async fn http_main(
    runtime: Arc<Runtime>,
    port: u16,
    output_dir: PathBuf,
    prover_config: Arc<ProverConfig>,
) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    debug!("listening on {}", addr);

    let app = Router::new().route(
        "/prove",
        post({
            let runtime = runtime.clone();
            move |body| prove(body, runtime, output_dir.clone(), prover_config)
        }),
    );
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    Ok(axum::serve(listener, app).await?)
}

/// Writes the generated block proof to a file.
///
/// Returns the fully qualified file name.
fn write_to_file(
    output_dir: PathBuf,
    block_number: U256,
    generated_block_proof: &GeneratedBlockProof,
) -> Result<PathBuf> {
    let file_name = format!("proof-{}.json", block_number);
    let fully_qualified_file_name = output_dir.join(file_name);
    let file = std::fs::File::create(fully_qualified_file_name.clone());

    match file {
        Ok(file) => {
            to_writer(file, &generated_block_proof)?;
            Ok(fully_qualified_file_name)
        }
        Err(e) => {
            bail!("Error while writing to file: {e:#?}");
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct HttpProverInput {
    prover_input: BlockProverInput,
    previous: Option<GeneratedBlockProof>,
}

async fn prove(
    Json(payload): Json<HttpProverInput>,
    runtime: Arc<Runtime>,
    output_dir: PathBuf,
    prover_config: Arc<ProverConfig>,
) -> StatusCode {
    debug!("Received payload: {:#?}", payload);

    let block_number = payload.prover_input.get_block_number();

    let proof_res = if prover_config.test_only {
        payload
            .prover_input
            .prove_test(
                runtime,
                payload.previous.map(futures::future::ok),
                prover_config,
            )
            .await
    } else {
        payload
            .prover_input
            .prove(
                runtime,
                payload.previous.map(futures::future::ok),
                prover_config,
            )
            .await
    };

    match proof_res {
        Ok(b_proof) => match write_to_file(output_dir, block_number, &b_proof) {
            Ok(file) => {
                info!("Successfully wrote proof to {}", file.display());
                StatusCode::OK
            }
            Err(e) => {
                error!("{e}");
                StatusCode::INTERNAL_SERVER_ERROR
            }
        },
        Err(e) => {
            error!("Error while proving block {block_number}: {e:#?}");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}
