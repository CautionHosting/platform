// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Integration tests for `#[derive(ProviderError)]`.
//!
//! These live outside the library so the generated `caution_error::...` paths
//! resolve exactly as they do for a downstream crate.

use caution_error::{
    ErrorReport, Note, ProviderError, Warning, request_ref, request_ref_in_chain, request_value,
};
use std::fmt;

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

/// Source is an owning box of a concrete error.
#[derive(Debug, ProviderError)]
struct BoxedSource {
    #[source]
    cause: Box<Inner>,
}

impl fmt::Display for BoxedSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("boxed failed")
    }
}

impl std::error::Error for BoxedSource {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.cause)
    }
}

#[test]
fn boxed_typed_source_is_wired() {
    let err = BoxedSource {
        cause: Box::new(Inner {
            device: "boxed".to_string(),
        }),
    };

    assert_eq!(
        request_ref_in_chain::<String>(&err).map(String::as_str),
        Some("boxed"),
    );
}

/// Source is a boxed trait object.
#[derive(Debug, ProviderError)]
struct BoxedDynSource {
    #[source]
    cause: Box<dyn ProviderError>,
}

impl fmt::Display for BoxedDynSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("boxed dyn failed")
    }
}

impl std::error::Error for BoxedDynSource {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.cause)
    }
}

#[test]
fn boxed_dyn_source_is_wired() {
    let cause: Box<dyn ProviderError> = Box::new(Inner {
        device: "boxed-dyn".to_string(),
    });
    let err = BoxedDynSource { cause };

    assert_eq!(
        request_ref_in_chain::<String>(&err).map(String::as_str),
        Some("boxed-dyn"),
    );
}

/// Source is a shared reference to a trait object.
#[derive(Debug, ProviderError)]
struct SharedDynSource {
    #[source]
    cause: &'static dyn ProviderError,
}

impl fmt::Display for SharedDynSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("shared dyn failed")
    }
}

impl std::error::Error for SharedDynSource {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.cause)
    }
}

#[test]
fn shared_dyn_source_is_wired() {
    let leaked: &'static Inner = Box::leak(Box::new(Inner {
        device: "shared-dyn".to_string(),
    }));
    let cause: &'static dyn ProviderError = leaked;
    let err = SharedDynSource { cause };

    assert_eq!(
        request_ref_in_chain::<String>(&err).map(String::as_str),
        Some("shared-dyn"),
    );
}

/// Source is optional; `Some` chains and `None` does not.
#[derive(Debug, ProviderError)]
struct OptionalSource {
    #[source]
    cause: Option<Inner>,
}

impl fmt::Display for OptionalSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("optional failed")
    }
}

impl std::error::Error for OptionalSource {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause.as_ref().map(|cause| {
            let cause: &(dyn std::error::Error + 'static) = cause;
            cause
        })
    }
}

#[test]
fn optional_source_some_is_wired() {
    let err = OptionalSource {
        cause: Some(Inner {
            device: "optional".to_string(),
        }),
    };

    assert_eq!(
        request_ref_in_chain::<String>(&err).map(String::as_str),
        Some("optional"),
    );
}

#[test]
fn optional_source_none_wires_nothing() {
    let err = OptionalSource { cause: None };

    assert!(ProviderError::provider_source(&err).is_none());
    assert!(request_ref_in_chain::<String>(&err).is_none());
}

/// A field named `source` but not marked `#[source]` must not be wired.
#[derive(Debug, ProviderError)]
struct NamedSource {
    source: Inner,
}

impl fmt::Display for NamedSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("named source failed")
    }
}

impl std::error::Error for NamedSource {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

#[test]
fn unannotated_source_field_is_not_wired() {
    let err = NamedSource {
        source: Inner {
            device: "named".to_string(),
        },
    };

    assert!(ProviderError::provider_source(&err).is_none());
    assert!(
        std::error::Error::source(&err).is_some(),
        "std source still works"
    );
    assert!(request_ref_in_chain::<String>(&err).is_none());
}

/// dterror 0.4 typed sources, driven through `with_context`.
mod dterror_typed {
    use caution_error::{ProviderError, request_ref_in_chain};
    use dterror::ResultExt;

    #[derive(Debug, thiserror::Error, dterror::CtxError, ProviderError)]
    #[error("no such device '{device}'")]
    struct TypedInner {
        #[provide]
        device: String,
    }

    #[derive(Debug, thiserror::Error, dterror::CtxError, ProviderError)]
    #[error("mount failed")]
    struct TypedOuter {
        #[source]
        source: TypedInner,
    }

    #[test]
    fn typed_source_is_chained() {
        let inner: Result<(), TypedInner> = Err(TypedInner {
            device: "nvme0".to_string(),
        });
        let err: TypedOuter = inner.with_context(TypedOuterCtx::new()).unwrap_err();

        assert!(ProviderError::provider_source(&err).is_some());
        assert_eq!(
            request_ref_in_chain::<String>(&err).map(String::as_str),
            Some("nvme0"),
        );
        assert!(std::error::Error::source(&err).is_some());
    }

    #[derive(Debug, thiserror::Error, dterror::CtxError, ProviderError)]
    #[error("optional mount failed")]
    struct OptionalOuter {
        #[source]
        source: Option<TypedInner>,
    }

    #[test]
    fn optional_typed_source_is_chained() {
        let err = OptionalOuter {
            source: Some(TypedInner {
                device: "sda1".to_string(),
            }),
        };

        assert_eq!(
            request_ref_in_chain::<String>(&err).map(String::as_str),
            Some("sda1"),
        );

        let err = OptionalOuter { source: None };
        assert!(ProviderError::provider_source(&err).is_none());
    }

    #[derive(Debug, thiserror::Error, dterror::CtxError, ProviderError)]
    enum Mixed {
        #[error("inner failed")]
        Inner {
            #[source]
            source: TypedInner,
        },
        #[error("io failed")]
        Io {
            #[source]
            source: std::io::Error,
        },
    }

    #[test]
    fn sum_typed_sources_chain_only_when_provider() {
        let inner: Result<(), TypedInner> = Err(TypedInner {
            device: "loop0".to_string(),
        });
        let err: Mixed = inner.with_context(MixedCtx::inner()).unwrap_err();

        assert_eq!(
            request_ref_in_chain::<String>(&err).map(String::as_str),
            Some("loop0"),
        );

        let io: Result<(), std::io::Error> = Err(std::io::Error::other("boom"));
        let err: Mixed = io.with_context(MixedCtx::io()).unwrap_err();
        assert!(ProviderError::provider_source(&err).is_none());
    }
}

#[derive(Debug, thiserror::Error, ProviderError)]
#[error("quota exceeded")]
struct QuotaError {
    #[provide(notes)]
    notes: Vec<Note>,

    #[provide(warnings)]
    warnings: Vec<Warning>,

    #[location]
    location: &'static std::panic::Location<'static>,
}

#[test]
fn notes_warnings_and_location_are_provided() {
    let err = QuotaError {
        notes: vec![Note("upgrade your plan".to_string())],
        warnings: vec![Warning("this may take a while".to_string())],
        location: std::panic::Location::caller(),
    };

    assert_eq!(
        request_ref::<[Note]>(&err).expect("notes are provided")[0].0,
        "upgrade your plan",
    );
    assert_eq!(
        request_ref::<[Warning]>(&err).expect("warnings are provided")[0].0,
        "this may take a while",
    );
    assert!(caution_error::location(&err).is_some());

    let report = ErrorReport::from_error(&err);
    assert_eq!(report.error, "quota exceeded");
    assert_eq!(report.errors[0].notes[0].0, "upgrade your plan");
    assert_eq!(report.errors[0].warnings[0].0, "this may take a while");
}

#[derive(Debug, thiserror::Error, ProviderError)]
enum Guided {
    #[error("denied")]
    Denied {
        #[provide(notes)]
        notes: Vec<Note>,
    },
}

#[test]
fn enum_variant_notes_are_provided() {
    let err = Guided::Denied {
        notes: vec![Note("request access first".to_string())],
    };

    assert_eq!(
        request_ref::<[Note]>(&err).expect("notes are provided")[0].0,
        "request access first",
    );
}
