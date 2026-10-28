// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Support code emitted by `#[derive(ProviderError)]`. Not a public API.

use crate::ProviderError;

/// Probe wrapper used to wire `provider_source` for a `#[source]` field whose
/// type may or may not implement [`ProviderError`].
///
/// Rust has no stable way to write two conditional impls for the same type, so
/// the generated code goes through this wrapper instead. For a source type that
/// implements [`ProviderError`], the inherent
/// [`as_provider_source`](ProviderSource::as_provider_source) is chosen and
/// returns `Some`. For any other type, the inherent method does not apply and
/// the [`ProviderSourceFallback`] trait method is chosen, returning `None`.
/// Resolution is by inherent-method preference, so the choice is made at compile
/// time and both paths typecheck. The lifetime on the returned reference is the
/// lifetime of the wrapped field, not of this wrapper, so the probe may be built
/// as a temporary.
pub struct ProviderSource<T>(pub T);

impl<'a, T: ProviderError> ProviderSource<&'a T> {
    /// Chosen when the wrapped source is itself a [`ProviderError`].
    #[must_use]
    pub fn as_provider_source(&self) -> Option<&'a (dyn ProviderError + 'static)> {
        Some(self.0)
    }
}

/// Fallback for `#[source]` fields whose type is not a [`ProviderError`].
///
/// Always in scope in generated code. Resolution prefers the inherent method
/// above when it applies, so this is reached only for other source types.
pub trait ProviderSourceFallback<'a> {
    /// Reports that the wrapped source cannot be reached as a
    /// [`ProviderError`].
    #[must_use]
    fn as_provider_source(&self) -> Option<&'a (dyn ProviderError + 'static)> {
        None
    }
}

impl<'a, T: ?Sized> ProviderSourceFallback<'a> for ProviderSource<&'a T> {}

#[cfg(test)]
mod tests {
    use super::{ProviderSource, ProviderSourceFallback};
    use crate::ProviderError;

    #[derive(Debug)]
    struct Typed;

    impl std::fmt::Display for Typed {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("typed")
        }
    }

    impl std::error::Error for Typed {}
    impl ProviderError for Typed {}

    #[derive(Debug)]
    struct Opaque;

    impl std::fmt::Display for Opaque {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("opaque")
        }
    }

    impl std::error::Error for Opaque {}

    #[test]
    fn typed_source_is_reached() {
        let source = Typed;
        let probe = ProviderSource(&source).as_provider_source();
        assert!(probe.is_some());
    }

    #[test]
    fn opaque_source_falls_back_to_none() {
        use ProviderSourceFallback as _;
        let source = Opaque;
        let probe = ProviderSource(&source).as_provider_source();
        assert!(probe.is_none());
    }
}
