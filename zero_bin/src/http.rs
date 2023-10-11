use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;
use axum::{http::StatusCode, routing::post, Json, Router};
use plonky_block_proof_gen::prover_state::ProverState;
use tracing::{debug, error, info};

use crate::prover_input::ProverInput;

/// The main function for the HTTP mode.
pub(crate) async fn http_main(p_state: ProverState, port: u16) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    debug!("listening on {}", addr);

    let p_state = Arc::new(p_state);
    let app = Router::new()
        .route(
            "/prove",
            post({
                let p_state = p_state.clone();
                move |body| prove(body, p_state)
            }),
        )
        .with_state(Arc::new(p_state));

    Ok(axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?)
}

async fn prove(Json(payload): Json<ProverInput>, p_state: Arc<ProverState>) -> StatusCode {
    debug!("Received payload: {:#?}", payload);

    match payload.prove(p_state.as_ref()) {
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
