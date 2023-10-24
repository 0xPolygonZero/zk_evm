use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;
use axum::{http::StatusCode, routing::post, Json, Router};
use paladin::runtime::Runtime;
use tracing::{debug, error, info};

use crate::prover_input::ProverInput;

/// The main function for the HTTP mode.
pub(crate) async fn http_main(runtime: Runtime, port: u16) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    debug!("listening on {}", addr);

    let runtime = Arc::new(runtime);
    let app = Router::new().route(
        "/prove",
        post({
            let runtime = runtime.clone();
            move |body| prove(body, runtime)
        }),
    );

    Ok(axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?)
}

async fn prove(Json(payload): Json<ProverInput>, runtime: Arc<Runtime>) -> StatusCode {
    debug!("Received payload: {:#?}", payload);

    match payload.prove(&runtime).await {
        Ok(b_proof) => {
            info!("Successfully proved {b_proof:#?}");
            StatusCode::OK
        }
        Err(e) => {
            error!("Error while proving: {e:#?}");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}
