// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::Request;

/// An error that also exposes context through the stable generic member access
/// API.
///
/// `ProviderError` is a plain [`std::error::Error`] with the platform's usual
/// additional bounds, [`Send`], [`Sync`], and `'static`, plus a single
/// [`provide`](ProviderError::provide) hook. Because the standard error trait is a
/// supertrait, every method it already defines (`source`, `cause`,
/// [`Display`](std::fmt::Display), [`Debug`](std::fmt::Debug)) stays available
/// on `T: ProviderError` and on `dyn ProviderError`; this trait does not redeclare them.
///
/// The default [`provide`](ProviderError::provide) implementation does not satisfy
/// any request, so implementors only override it when they have context worth
/// reporting:
///
/// ```rust
/// use caution_error::{request_ref, Request, ProviderError};
///
/// #[derive(Debug)]
/// struct RetryAfter(std::time::Duration);
///
/// #[derive(Debug)]
/// struct RateLimited;
///
/// impl std::fmt::Display for RateLimited {
///     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
///         f.write_str("rate limited")
///     }
/// }
///
/// impl std::error::Error for RateLimited {}
///
/// impl ProviderError for RateLimited {
///     fn provide<'a>(&'a self, request: &mut Request<'a>) {
///         request.provide_value::<RetryAfter>(RetryAfter(
///             std::time::Duration::from_secs(30),
///         ));
///     }
/// }
///
/// let err = RateLimited;
/// let retry = request_ref::<RetryAfter>(&err);
/// # let _ = retry;
/// ```
///
/// # Why not a blanket implementation?
///
/// A blanket
/// `impl<T: std::error::Error + Send + Sync + 'static> ProviderError for T` would
/// make the trait automatic, but it would also fix [`provide`](ProviderError::provide)
/// for every error type and leave no way to override it. The provider API only
/// has value when an implementor replaces the default, so types opt in with an
/// explicit `impl ProviderError for MyError {}`.
///
/// # Delegation
///
/// Do not forward [`provide`](ProviderError::provide) to a wrapped source error.
/// The source chain already surfaces it, and forwarding duplicates its context
/// under two errors in the report. To make a typed source's context reachable,
/// wire [`provider_source`](ProviderError::provider_source) instead; the
/// `request_*_in_chain` helpers then walk the chain explicitly.
pub trait ProviderError: std::error::Error + Send + Sync + 'static {
    /// Attempts to satisfy `request` with context owned by this error.
    ///
    /// The default implementation satisfies nothing. Implementors call the
    /// `provide_value` / `provide_ref` family on `request`; a request that has
    /// already been satisfied ignores later values of the same type, so the
    /// first error in a chain to answer wins.
    #[allow(unused_variables, reason = "the default deliberately offers nothing")]
    fn provide<'a>(&'a self, request: &mut Request<'a>) {}

    /// Returns this error's source as a [`ProviderError`], when the source is
    /// itself one.
    ///
    /// [`std::error::Error::source`] erases the source to
    /// `&dyn std::error::Error`, and a `dyn` standard error has no provider API
    /// on stable. An error whose source is a typed [`ProviderError`] widens the
    /// field here, so the chain helpers
    /// ([`request_ref_in_chain`](crate::request_ref_in_chain) and
    /// [`request_value_in_chain`](crate::request_value_in_chain)) can reach the
    /// source's context without the consumer naming the source's type.
    ///
    /// The default is `None`. The returned trait object is bounded by
    /// `'static`, which always holds because [`ProviderError`] requires it.
    ///
    /// ```rust
    /// use caution_error::{ProviderError, Request, request_value_in_chain};
    /// use std::fmt;
    ///
    /// #[derive(Debug)]
    /// struct Source {
    ///     depth: u8,
    /// }
    ///
    /// #[derive(Debug)]
    /// struct Outer {
    ///     source: Source,
    /// }
    ///
    /// impl fmt::Display for Source {
    ///     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    ///         f.write_str("source failed")
    ///     }
    /// }
    ///
    /// impl fmt::Display for Outer {
    ///     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    ///         f.write_str("outer failed")
    ///     }
    /// }
    ///
    /// impl std::error::Error for Source {}
    /// impl std::error::Error for Outer {
    ///     fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    ///         Some(&self.source)
    ///     }
    /// }
    ///
    /// impl ProviderError for Source {
    ///     fn provide<'a>(&'a self, request: &mut Request<'a>) {
    ///         request.provide_value::<u8>(self.depth);
    ///     }
    /// }
    ///
    /// impl ProviderError for Outer {
    ///     fn provider_source(&self) -> Option<&(dyn ProviderError + 'static)> {
    ///         Some(&self.source)
    ///     }
    /// }
    ///
    /// let outer = Outer { source: Source { depth: 3 } };
    /// assert_eq!(request_value_in_chain::<u8>(&outer), Some(3));
    /// ```
    fn provider_source(&self) -> Option<&(dyn ProviderError + 'static)> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::ProviderError;
    use crate::{Request, request_ref, request_value};
    use std::fmt;

    #[derive(Debug)]
    struct Marker;

    #[derive(Debug)]
    struct Parent {
        value: u32,
    }

    #[derive(Debug)]
    struct Child {
        parent: Parent,
    }

    impl fmt::Display for Parent {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("parent failed")
        }
    }

    impl fmt::Display for Child {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("child failed")
        }
    }

    impl std::error::Error for Parent {}

    impl std::error::Error for Child {}

    impl ProviderError for Parent {
        fn provide<'a>(&'a self, request: &mut Request<'a>) {
            request.provide_value::<u32>(self.value);
        }
    }

    impl ProviderError for Child {
        fn provide<'a>(&'a self, request: &mut Request<'a>) {
            request.provide_ref::<Parent>(&self.parent);
        }
    }

    #[test]
    fn default_provide_satisfies_nothing() {
        #[derive(Debug)]
        struct Plain;
        impl fmt::Display for Plain {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("plain")
            }
        }
        impl std::error::Error for Plain {}
        impl ProviderError for Plain {}

        assert!(request_value::<u32>(&Plain).is_none());
        assert!(request_ref::<Marker>(&Plain).is_none());
    }

    #[test]
    fn provide_forwards_owned_value() {
        let parent = Parent { value: 5 };
        assert_eq!(request_value::<u32>(&parent), Some(5));
    }

    #[test]
    fn provide_forwards_reference() {
        let child = Child {
            parent: Parent { value: 9 },
        };
        assert_eq!(request_ref::<Parent>(&child).map(|p| p.value), Some(9));
    }
}
