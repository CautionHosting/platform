//! Optional display metadata. Never an input to release authorization.
use crate::types::AppState;
use locksmith::release::Prepared;
use sequoia_openpgp::{parse::Parse, Cert};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{net::SocketAddr, time::Duration};
use uuid::Uuid;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DisplayContext {
    pub application_id: Uuid,
    pub destination_address: SocketAddr,
    pub custody_url: String,
    /// Sent by CLIs releasing to one deployment (`send-shard -d`). Gateways ship
    /// before such CLIs because this context rejects unknown fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_id: Option<Uuid>,
}
impl DisplayContext {
    pub fn valid(&self) -> bool {
        self.custody_url.len() <= 2048
            && url::Url::parse(&self.custody_url).is_ok_and(|url| {
                matches!(url.scheme(), "http" | "https")
                    && url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none()
            })
    }
}

pub(crate) async fn get(state: &AppState, user: Uuid, path: &str) -> Option<Value> {
    let mut request = state
        .http_client
        .get(format!(
            "{}{path}",
            state.api_service_url.trim_end_matches('/')
        ))
        .header("X-Authenticated-User-ID", user.to_string())
        .timeout(Duration::from_secs(3));
    if let Some(secret) = &state.internal_service_secret {
        request = request.header("X-Internal-Service-Secret", secret);
    }
    let mut response = request.send().await.ok()?.error_for_status().ok()?;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        if bytes.len() + chunk.len() > 4 * 1024 * 1024 {
            return None;
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).ok()
}

fn bundle_metadata(rows: &Value, prepared: &Prepared) -> Option<Value> {
    let context = &prepared.context;
    let org = Uuid::from_bytes(context.organization_id).to_string();
    let mut found = None;
    for row in rows.as_array()? {
        if row["organization_id"].as_str() != Some(&org) {
            continue;
        }
        let Ok(proof) = serde_json::from_value::<
            keymaker_models::generate_quorum::GenerateQuorumResponse,
        >(row["data"].clone()) else {
            continue;
        };
        let Ok(hash) = keymaker_models::generate_quorum::deterministic_bundle_hash(&proof.data)
        else {
            continue;
        };
        if hex::encode(hash) != context.bundle_hash {
            continue;
        }
        let bundle = proof.data.to_latest();
        if bundle.bundle_id != context.bundle_id {
            continue;
        }
        let key = bundle.keyring.get(usize::from(context.holder_position))?;
        let keymaker_models::generate_quorum::v1::Key::WebAuthn { cert, credential } = key else {
            return None;
        };
        if Cert::from_bytes(cert.as_bytes())
            .ok()?
            .fingerprint()
            .to_string()
            != context.holder
        {
            return None;
        }
        let holder = row["holders"]
            .as_array()
            .filter(|holders| holders.len() == bundle.keyring.len())
            .and_then(|holders| holders.get(usize::from(context.holder_position)))
            .filter(|holder| {
                holder["fingerprint"].as_str() == Some(context.holder.as_str())
                    && holder["custody"] == "caution_backed"
            });
        let metadata = json!({"name":row["name"], "threshold":bundle.threshold, "holders":bundle.max,
            "username":holder.map(|h| &h["username"]), "eligible_passkeys":credential.len()});
        if found.as_ref().is_some_and(|prior| prior != &metadata) {
            return None;
        }
        found = Some(metadata);
    }
    found
}

fn app_metadata(app: Value, id: Uuid, org: Uuid) -> Option<Value> {
    if app["id"].as_str()? != id.to_string() || app["organization_id"].as_str()? != org.to_string()
    {
        return None;
    }
    Some(
        json!({"id":app["id"], "name":app["resource_name"], "domain":app["domain"],
        "public_ip":app["public_ip"], "state":app["state"]}),
    )
}

fn deployment_metadata(view: Value, app: Uuid, id: Uuid) -> Option<Value> {
    if view["id"].as_str()? != id.to_string() || view["app_id"].as_str()? != app.to_string() {
        return None;
    }
    Some(
        json!({"id":view["id"], "role":view["role"], "status":view["status"],
        "commit_sha":view["commit_sha"], "commit_subject":view["commit_subject"],
        "pushed_ref":view["pushed_ref"], "public_ip":view["public_ip"]}),
    )
}

/// Labels for the displayed app and deployment. A deployment is labelled only
/// when its app is the displayed one and belongs to the release's organization.
fn display_metadata(
    app: Option<Value>,
    deployment: Option<Value>,
    display: Option<&DisplayContext>,
    org: Uuid,
) -> (Option<Value>, Option<Value>) {
    let Some(display) = display else {
        return (None, None);
    };
    let application = app.and_then(|app| app_metadata(app, display.application_id, org));
    let deployment = application.as_ref().and(deployment).and_then(|view| {
        display
            .deployment_id
            .and_then(|id| deployment_metadata(view, display.application_id, id))
    });
    (application, deployment)
}

pub async fn load(
    state: &AppState,
    user: Uuid,
    prepared: &Prepared,
    display: Option<&DisplayContext>,
) -> Value {
    let org = Uuid::from_bytes(prepared.context.organization_id);
    let lookup = async {
        // Existing API endpoint enforces membership. Do not enrich inaccessible contexts.
        let organization = get(state, user, &format!("/organizations/{org}")).await?;
        if organization["id"].as_str()? != org.to_string() {
            return None;
        }
        let (rows, app, deployment) = tokio::join!(
            get(state, user, "/quorum-bundles"),
            async {
                match display {
                    Some(d) => get(state, user, &format!("/resources/{}", d.application_id)).await,
                    None => None,
                }
            },
            async {
                match display.and_then(|d| d.deployment_id.map(|id| (d.application_id, id))) {
                    Some((app, id)) => {
                        get(state, user, &format!("/resources/{app}/deployments/{id}")).await
                    }
                    None => None,
                }
            },
        );
        let (application, deployment) = display_metadata(app, deployment, display, org);
        Some(json!({"organization":{"name":organization["name"]},
            "bundle":rows.as_ref().and_then(|rows| bundle_metadata(rows, prepared)),
            "application":application, "deployment":deployment}))
    };
    tokio::time::timeout(Duration::from_secs(4), lookup)
        .await
        .ok()
        .flatten()
        .unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;
    use keymaker_models::generate_quorum::{deterministic_bundle_hash, v1, GenerateQuorumBundle};
    use sequoia_openpgp::{cert::CertBuilder, serialize::Serialize};

    #[test]
    fn display_context_rejects_names_and_secret_bearing_urls() {
        let mut value = json!({"application_id":Uuid::new_v4(),"destination_address":"203.0.113.42:49504","custody_url":"https://custody.example.test"});
        assert!(serde_json::from_value::<DisplayContext>(value.clone())
            .unwrap()
            .valid());
        value["name"] = json!("Trusted payroll");
        assert!(serde_json::from_value::<DisplayContext>(value.clone()).is_err());
        value.as_object_mut().unwrap().remove("name");
        for url in [
            "https://u:password@example.test",
            "https://example.test/?token=secret",
            "file:///tmp/data",
            "https://example.test/#token",
        ] {
            value["custody_url"] = json!(url);
            assert!(!serde_json::from_value::<DisplayContext>(value.clone())
                .unwrap()
                .valid());
        }
    }

    #[test]
    fn display_context_accepts_an_optional_deployment() {
        let (app, deployment) = (Uuid::new_v4(), Uuid::new_v4());
        let base = json!({"application_id": app, "destination_address": "203.0.113.9:49504",
                          "custody_url": "https://keys.example.com"});
        let without: DisplayContext = serde_json::from_value(base.clone()).unwrap();
        assert_eq!(without.deployment_id, None);
        assert!(
            !serde_json::to_string(&without)
                .unwrap()
                .contains("deployment_id")
        );
        let mut with = base;
        with["deployment_id"] = json!(deployment);
        let with: DisplayContext = serde_json::from_value(with).unwrap();
        assert_eq!(with.deployment_id, Some(deployment));
    }

    #[test]
    fn deployment_metadata_requires_the_displayed_app_and_deployment() {
        let (app, deployment) = (Uuid::new_v4(), Uuid::new_v4());
        let view = json!({"id": deployment, "app_id": app, "role": "candidate", "status": "running",
                          "commit_sha": "b6e8c92", "commit_subject": "Fix", "pushed_ref": "main",
                          "public_ip": "203.0.113.9", "instance_id": "i-0abc"});
        let shown = deployment_metadata(view.clone(), app, deployment).unwrap();
        assert_eq!(shown["public_ip"], "203.0.113.9");
        assert!(shown.get("instance_id").is_none());
        assert!(deployment_metadata(view.clone(), Uuid::new_v4(), deployment).is_none());
        assert!(deployment_metadata(view, app, Uuid::new_v4()).is_none());
    }

    #[test]
    fn deployment_labels_require_the_release_organization() {
        let (org, other, app, deployment) = (
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
        );
        let display: DisplayContext = serde_json::from_value(json!({"application_id": app,
            "destination_address": "203.0.113.9:49504", "custody_url": "https://keys.example.com",
            "deployment_id": deployment}))
        .unwrap();
        let view = json!({"id": deployment, "app_id": app, "role": "candidate", "public_ip": "203.0.113.9"});
        let app_in =
            |org: Uuid| json!({"id": app, "organization_id": org, "resource_name": "key-service"});
        let (application, shown) =
            display_metadata(Some(app_in(org)), Some(view.clone()), Some(&display), org);
        assert!(application.is_some() && shown.is_some());
        assert_eq!(
            display_metadata(Some(app_in(other)), Some(view), Some(&display), org),
            (None, None)
        );
    }

    #[test]
    fn app_records_must_match_the_requested_app_and_authenticated_organization() {
        let id = Uuid::new_v4();
        let org = Uuid::new_v4();
        let app = json!({"id":id, "organization_id":org,"resource_name":"example", "public_ip":"203.0.113.42", "private_configuration":"never displayed"});
        let metadata = app_metadata(app.clone(), id, org).unwrap();
        assert!(metadata.get("private_configuration").is_none());
        assert!(app_metadata(app.clone(), Uuid::new_v4(), org).is_none());
        assert!(app_metadata(app, id, Uuid::new_v4()).is_none());
        assert!(app_metadata(Value::Null, id, org).is_none());
    }

    #[test]
    fn bundle_details_require_matching_hash_position_certificate_and_org() {
        let (cert, _) = CertBuilder::general_purpose(None, Some("holder"))
            .generate()
            .unwrap();
        let mut armor = Vec::new();
        cert.armored().serialize(&mut armor).unwrap();
        let bundle = GenerateQuorumBundle::V1(v1::GenerateQuorumResponse {
            bundle_id: [1; 16],
            label: Default::default(),
            threshold: 1,
            max: 1,
            keyring: vec![v1::Key::WebAuthn {
                cert: String::from_utf8(armor).unwrap(),
                credential: vec!["credential-a".into(), "credential-b".into()],
            }],
            shardfile: "ciphertext".into(),
            public_key: "public".into(),
        });
        let mut prepared = super::super::verification_tests::fixture().0.prepared.data;
        prepared.context.bundle_hash = hex::encode(deterministic_bundle_hash(&bundle).unwrap());
        prepared.context.holder = cert.fingerprint().to_string();
        let row = json!({"organization_id":Uuid::from_bytes([2;16]),"name":"quorum", "data":{"data":bundle,"necroproof":[]},
            "holders":[{"username":"alice","custody":"caution_backed","fingerprint":prepared.context.holder}]});
        let metadata = bundle_metadata(&json!([row.clone()]), &prepared).unwrap();
        assert_eq!(metadata["eligible_passkeys"], 2);
        assert_eq!(metadata["username"], "alice");
        let mut wrong = row.clone();
        wrong["holders"][0]["fingerprint"] = json!("wrong");
        assert!(bundle_metadata(&json!([wrong]), &prepared).unwrap()["username"].is_null());
        let mut wrong = row.clone();
        wrong["organization_id"] = json!(Uuid::new_v4());
        assert!(bundle_metadata(&json!([wrong]), &prepared).is_none());
        let mut wrong = row.clone();
        wrong["data"]["data"]["threshold"] = json!(2);
        assert!(bundle_metadata(&json!([wrong]), &prepared).is_none());
        for (position, holder) in [(1, prepared.context.holder.clone()), (0, "wrong".into())] {
            let mut changed = prepared.clone();
            changed.context.holder_position = position;
            changed.context.holder = holder;
            assert!(bundle_metadata(&json!([row.clone()]), &changed).is_none());
        }
        assert!(bundle_metadata(&Value::Null, &prepared).is_none());
    }
}
