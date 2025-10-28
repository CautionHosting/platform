// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use nsm_api::api::{Request, Response};
use nsm_api::driver;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use warp::Filter;

#[derive(Debug, Serialize)]
struct AttestationResponse {
    attestation_document: String,
    pcrs: Option<Vec<String>>,
    manifest: Option<serde_json::Value>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AttestationRequest {
    #[serde(default)]
    user_data: Option<Vec<u8>>,
    #[serde(default)]
    nonce: Option<Vec<u8>>,
    #[serde(default)]
    public_key: Option<Vec<u8>>,
}

/// Read manifest.json from filesystem if it exists
fn read_manifest() -> Option<serde_json::Value> {
    std::fs::read_to_string("/manifest.json")
        .ok()
        .and_then(|content| serde_json::from_str(&content).ok())
}

/// Get attestation document from NSM device using official AWS API
fn get_attestation_document(
    user_data: Option<&[u8]>,
    nonce: Option<&[u8]>,
    public_key: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    // Initialize NSM driver
    let nsm_fd = driver::nsm_init();
    if nsm_fd < 0 {
        return Err("Failed to initialize NSM device".to_string());
    }

    // Build request using official NSM API structures
    let request = Request::Attestation {
        user_data: user_data.map(|d| ByteBuf::from(d.to_vec())),
        nonce: nonce.map(|n| ByteBuf::from(n.to_vec())),
        public_key: public_key.map(|pk| ByteBuf::from(pk.to_vec())),
    };

    // Send request to NSM device
    let response = driver::nsm_process_request(nsm_fd, request);

    // Clean up
    driver::nsm_exit(nsm_fd);

    // Extract attestation document from response
    match response {
        Response::Attestation { document } => Ok(document),
        Response::Error(err) => Err(format!("NSM error: {:?}", err)),
        _ => Err("Unexpected NSM response".to_string()),
    }
}

#[tokio::main]
async fn main() {
    println!("Starting Attestation Service on port 5000...");

    // Health check endpoint
    let health = warp::path("health")
        .map(|| warp::reply::json(&serde_json::json!({
            "status": "ok",
            "service": "attestation"
        })));

    // Attestation with nonce challenge endpoint (POST)
    // REQUIRED: nonce field must be provided to prevent replay attacks
    let attestation_post = warp::path("attestation")
        .and(warp::post())
        .and(warp::body::json())
        .map(|req: AttestationRequest| {
            // Read manifest once at the start
            let manifest = read_manifest();

            // Require nonce for replay attack protection
            let nonce = match req.nonce {
                Some(n) if !n.is_empty() => n,
                _ => {
                    eprintln!("ERROR: Attestation request missing nonce field");
                    return warp::reply::json(&AttestationResponse {
                        attestation_document: String::new(),
                        pcrs: None,
                        manifest,
                        error: Some("Nonce is required for attestation requests (replay attack protection)".to_string()),
                    });
                }
            };

            println!("Attestation request with nonce ({} bytes)", nonce.len());

            match get_attestation_document(
                req.user_data.as_deref(),
                Some(&nonce),
                req.public_key.as_deref(),
            ) {
                Ok(doc) => {
                    let encoded = base64::encode(&doc);
                    println!("Attestation document generated: {} bytes", encoded.len());
                    warp::reply::json(&AttestationResponse {
                        attestation_document: encoded,
                        pcrs: None,
                        manifest,
                        error: None,
                    })
                }
                Err(e) => {
                    eprintln!("Attestation error: {}", e);
                    warp::reply::json(&AttestationResponse {
                        attestation_document: String::new(),
                        pcrs: None,
                        manifest,
                        error: Some(e),
                    })
                }
            }
        });

    let routes = health
        .or(attestation)
        .or(attestation_post);

    println!("Attestation service ready!");
    warp::serve(routes)
        .run(([0, 0, 0, 0], 5000))
        .await;
}
