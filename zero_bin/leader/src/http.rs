use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::{bail, Result};
use axum::{http::StatusCode, routing::post, Json, Router};
use ethereum_types::U256;
use paladin::runtime::Runtime;
use proof_gen::{proof_types::GeneratedBlockProof, types::PlonkyProofIntern};
use prover::ProverInput;
use serde::{Deserialize, Serialize};
use serde_json::to_writer;
use tracing::{debug, error, info};

/// The main function for the HTTP mode.
pub(crate) async fn http_main(runtime: Runtime, port: u16, output_dir: PathBuf) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    debug!("listening on {}", addr);

    let runtime = Arc::new(runtime);
    let app = Router::new().route(
        "/prove",
        post({
            let runtime = runtime.clone();
            move |body| prove(body, runtime, output_dir.clone())
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
            to_writer(file, &generated_block_proof.intern)?;
            Ok(fully_qualified_file_name)
        }
        Err(e) => {
            bail!("Error while writing to file: {e:#?}");
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct HttpProverInput {
    prover_input: ProverInput,
    previous: Option<PlonkyProofIntern>,
}

async fn prove(
    Json(payload): Json<HttpProverInput>,
    runtime: Arc<Runtime>,
    output_dir: PathBuf,
) -> StatusCode {
    debug!("Received payload: {:#?}", payload);

    let block_number = payload.prover_input.get_block_number();

    match payload.prover_input.prove(&runtime, payload.previous).await {
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
