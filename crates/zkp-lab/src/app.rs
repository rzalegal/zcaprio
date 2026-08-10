//! Route definitions and network binding configuration.

use std::net::SocketAddr;

use axum::{Router, http::StatusCode, routing::get};

/// Returns the loopback address on which the teaching application listens.
pub fn bind_address() -> SocketAddr {
    let port = std::env::var("ZKP_LAB_PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(3000);

    SocketAddr::from(([127, 0, 0, 1], port))
}

/// Returns the HTTP router for the teaching application.
pub fn router() -> Router {
    Router::new().route("/api/health", get(|| async { StatusCode::OK }))
}
