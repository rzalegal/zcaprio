//! Binary entry point for the ZK protocol lab.

use tokio::net::TcpListener;
use zkp_lab::app;

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind(app::bind_address())
        .await
        .expect("the ZK protocol lab should bind to its configured loopback address");

    axum::serve(listener, app::router())
        .await
        .expect("the ZK protocol lab server should run");
}
