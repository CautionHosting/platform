use axum::{routing::get, Json, Router};
use std::collections::BTreeMap;

async fn get_env() -> Json<BTreeMap<String, String>> {
    Json(std::env::vars().collect())
}

#[tokio::main]
async fn main() {
    let app = Router::new().route("/env", get(get_env));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080")
        .await
        .expect("failed to bind");
    axum::serve(listener, app)
        .await
        .expect("server error");
}
