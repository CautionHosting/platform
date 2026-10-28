// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Integration tests for `#[derive(ProviderError)]`.
//!
//! These live outside the library so the generated `caution_error::...` paths
//! resolve exactly as they do for a downstream crate.

use caution_error::{ProviderError, request_ref, request_ref_in_chain, request_value};

#[derive(Debug, thiserror::Error, ProviderError)]
#[error("upstream returned {status}")]
struct Upstream {
    #[provide]
    request_id: String,
    status: u16,
}

#[test]
fn provides_marked_reference_without_cloning() {
    let err = Upstream {
        request_id: "req-7".to_string(),
        status: 503,
    };

    let provided = request_ref::<String>(&err).expect("request_id is provided");
    assert!(
        std::ptr::eq(provided, &err.request_id),
        "shared, not cloned"
    );
}

#[test]
fn skips_unmarked_fields() {
    let err = Upstream {
        request_id: "req-7".to_string(),
        status: 503,
    };

    assert!(request_ref::<u16>(&err).is_none(), "status is not marked");
    assert!(request_value::<u16>(&err).is_none());
}

#[derive(Debug, thiserror::Error, ProviderError)]
enum Failure {
    #[error("missing {name}")]
    Missing {
        #[provide]
        name: String,
        #[provide]
        key: u32,
        cause: Option<String>,
    },
    #[error("timeout after {0} ms")]
    Timeout(u64),
    #[error("tuple")]
    Tuple(#[provide] String, u16),
}

#[test]
fn enum_named_variant_provides_marked_fields() {
    let err = Failure::Missing {
        name: "region".to_string(),
        key: 3,
        cause: Some("unset".to_string()),
    };

    assert_eq!(
        request_ref::<String>(&err).map(String::as_str),
        Some("region")
    );
    assert_eq!(request_ref::<u32>(&err), Some(&3));
    assert!(
        request_ref::<Option<String>>(&err).is_none(),
        "cause is not marked"
    );
}

#[test]
fn enum_unit_and_unmarked_variants_provide_nothing() {
    assert!(request_ref::<u64>(&Failure::Timeout(10)).is_none());
}

#[test]
fn enum_tuple_variant_provides_marked_position() {
    let err = Failure::Tuple("value".to_string(), 7);

    assert_eq!(
        request_ref::<String>(&err).map(String::as_str),
        Some("value")
    );
    assert!(
        request_ref::<u16>(&err).is_none(),
        "position 1 is not marked"
    );
}

/// A `dterror`-style error: `thiserror` owns the `std::error::Error` impl,
/// `dterror` owns the context constructor, and this derive adds only the
/// provider impl.
#[derive(Debug, thiserror::Error, dterror::CtxError, ProviderError)]
#[error("could not read config '{path}' [{location}]")]
struct ConfigError {
    #[provide]
    path: String,

    #[location]
    location: dterror::Location,

    #[source]
    source: dterror::BoxError,
}

#[test]
fn composes_with_dterror_and_thiserror() {
    let err = ConfigError {
        path: "app.hcl".to_string(),
        location: std::panic::Location::caller(),
        source: Box::new(std::io::Error::other("permission denied")),
    };

    assert_eq!(
        request_ref::<String>(&err).map(String::as_str),
        Some("app.hcl")
    );
    assert_eq!(
        std::error::Error::source(&err).map(ToString::to_string),
        Some("permission denied".to_string()),
        "thiserror still owns the std source",
    );
}

#[derive(Debug, thiserror::Error, ProviderError)]
#[error("no such device")]
struct Inner {
    #[provide]
    device: String,
}

#[derive(Debug, thiserror::Error, ProviderError)]
#[error("read failed")]
struct ReadFailed {
    #[source]
    cause: Inner,
}

#[test]
fn typed_source_is_wired_automatically() {
    let err = ReadFailed {
        cause: Inner {
            device: "nvme0".to_string(),
        },
    };

    assert!(
        request_ref::<String>(&err).is_none(),
        "root holds no device"
    );
    assert_eq!(
        request_ref_in_chain::<String>(&err).map(String::as_str),
        Some("nvme0"),
    );
    assert!(ProviderError::provider_source(&err).is_some());
}

/// A source of a type that is not a `ProviderError` must still compile; the
/// probe returns `None` for it.
#[derive(Debug, thiserror::Error, ProviderError)]
#[error("io failed")]
struct IoFailed {
    #[source]
    cause: std::io::Error,
}

#[test]
fn non_provider_source_builds_and_wires_nothing() {
    let err = IoFailed {
        cause: std::io::Error::other("boom"),
    };

    assert!(ProviderError::provider_source(&err).is_none());
    assert!(request_ref_in_chain::<String>(&err).is_none());
}

#[derive(Debug, thiserror::Error, ProviderError)]
enum Wrapped {
    #[error("wrapped")]
    Inner {
        #[source]
        cause: Inner,
    },
    #[error("bare")]
    Bare,
}

#[test]
fn enum_variant_source_is_wired() {
    let err = Wrapped::Inner {
        cause: Inner {
            device: "disk1".to_string(),
        },
    };

    assert_eq!(
        request_ref_in_chain::<String>(&err).map(String::as_str),
        Some("disk1"),
    );
    assert!(ProviderError::provider_source(&Wrapped::Bare).is_none());
}
