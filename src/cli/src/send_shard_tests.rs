// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::*;
use serde_json::json;

#[test]
fn deployment_release_uses_only_the_recorded_bundle() {
    let org = vec![
        json!({"bundle_hash": "aa", "data": {"n": 1}}),
        json!({"bundle_hash": "bb", "data": {"n": 2}}),
    ];
    // The recorded hash picks its organization bundle, never the first one.
    assert_eq!(
        select_deployment_bundle(Some("bb"), None, None, &org).unwrap(),
        ReleaseBundle::Org(json!({"n": 2}))
    );
    // A matching local bundle is used as is; a different one is ignored.
    assert_eq!(
        select_deployment_bundle(Some("bb"), None, Some(Some("bb")), &org).unwrap(),
        ReleaseBundle::Local
    );
    assert_eq!(
        select_deployment_bundle(Some("bb"), None, Some(Some("aa")), &org).unwrap(),
        ReleaseBundle::Org(json!({"n": 2}))
    );
    assert!(matches!(
        select_deployment_bundle(Some("cc"), None, Some(Some("aa")), &org),
        Err(BundleSelection::NotFound { .. })
    ));
    // An explicit bundle must be the one the deployment was built with.
    assert!(matches!(
        select_deployment_bundle(Some("bb"), Some(Some("aa")), None, &org),
        Err(BundleSelection::Mismatch { .. })
    ));
    assert!(matches!(
        select_deployment_bundle(Some("bb"), Some(None), None, &org),
        Err(BundleSelection::Mismatch { .. })
    ));
    assert_eq!(
        select_deployment_bundle(Some("bb"), Some(Some("bb")), None, &org).unwrap(),
        ReleaseBundle::Explicit
    );
    // Nothing recorded: only an explicit bundle is accepted.
    assert!(matches!(
        select_deployment_bundle(None, None, Some(Some("aa")), &org),
        Err(BundleSelection::NotRecorded { .. })
    ));
    assert_eq!(
        select_deployment_bundle(None, Some(None), None, &org).unwrap(),
        ReleaseBundle::Explicit
    );
}

/// The API's `canonical_hash` of the same fixture (`BUNDLE` in the
/// `app_deployments::admission` tests). `bundle_text_hash` is a cross-crate
/// copy, so this literal, taken from the API's output, is the only thing that
/// ties the two together.
const BUNDLE_FIXTURE_HASH: &str =
    "0331123d7171622a4a4440ff3916f9d85e99199a7e146388fac2fe3e5ca79ae3";

#[test]
fn bundle_text_hash_matches_the_api_canonical_hash() {
    let text = r#"{"data":{"version":"V1","bundle_id":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],"label":{"a":"1","b":"2"},"keyring":[],"threshold":1,"max":1,"shardfile":"shares","public_key":"key"},"necroproof":[]}"#;
    assert_eq!(bundle_text_hash(text).as_deref(), Some(BUNDLE_FIXTURE_HASH));
    let reordered = text.replace(
        r#""label":{"a":"1","b":"2"}"#,
        r#""label":{"b":"2","a":"1"}"#,
    );
    assert_eq!(bundle_text_hash(text), bundle_text_hash(&reordered));
    assert_eq!(bundle_text_hash("{}"), None);
}
