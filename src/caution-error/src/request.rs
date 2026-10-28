// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Stable reimplementation of the standard library's generic member access
//! ("provider") API.
//!
//! The types and functions here mirror `core::error::{Request, request_ref,
//! request_value}` and `core::any::*`. They are a byte-for-byte port of the
//! standard-library implementation, with the single change that `provide` is
//! reached through [`crate::ProviderError`] instead of the unstable
//! `std::error::Error::provide`. See the crate root for the rationale.

use std::any::TypeId;
use std::fmt::{self, Debug, Formatter};

use crate::ProviderError;

/// A request for context of a specific type, passed to
/// [`ProviderError::provide`](crate::ProviderError::provide).
///
/// The consumer of an error creates a `Request` for a concrete type and asks
/// the error to satisfy it with [`provide_value`](Request::provide_value) or
/// [`provide_ref`](Request::provide_ref). The error fills the request only when
/// it has a value of that exact type. Consumers usually do not name `Request`
/// directly; they call [`request_value`] or [`request_ref`].
///
/// `Request` is unsized. It is always used behind a reference, as the argument
/// to [`ProviderError::provide`](crate::ProviderError::provide).
#[repr(transparent)]
pub struct Request<'a>(Tagged<dyn Erased<'a> + 'a>);

impl<'a> Request<'a> {
    /// Provides a value with only a `'static` lifetime, if the request is for
    /// exactly this type and no value has been provided yet.
    pub fn provide_value<T>(&mut self, value: T) -> &mut Self
    where
        T: 'static,
    {
        self.provide::<tags::Value<T>>(value)
    }

    /// Provides a `'static` value computed lazily, if the request is for
    /// exactly this type and no value has been provided yet.
    ///
    /// `fulfil` runs only when the request matches, so an expensive value costs
    /// nothing when nobody asked for it.
    pub fn provide_value_with<T>(&mut self, fulfil: impl FnOnce() -> T) -> &mut Self
    where
        T: 'static,
    {
        self.provide_with::<tags::Value<T>>(fulfil)
    }

    /// Provides a reference, if the request is for exactly this type and no
    /// value has been provided yet.
    ///
    /// The referee must be `'static`, but it may be unsized (for example
    /// `str`).
    pub fn provide_ref<T: ?Sized + 'static>(&mut self, value: &'a T) -> &mut Self {
        self.provide::<tags::Ref<tags::MaybeSizedValue<T>>>(value)
    }

    /// Provides a reference computed lazily, if the request is for exactly this
    /// type and no value has been provided yet.
    ///
    /// `fulfil` runs only when the request matches.
    pub fn provide_ref_with<T: ?Sized + 'static>(
        &mut self,
        fulfil: impl FnOnce() -> &'a T,
    ) -> &mut Self {
        self.provide_with::<tags::Ref<tags::MaybeSizedValue<T>>>(fulfil)
    }

    /// Reports whether a value of type `T` is still wanted.
    ///
    /// Returns `false` once the request holds a value of type `T`, or when the
    /// request is for a different type.
    pub fn would_be_satisfied_by_value_of<T>(&self) -> bool
    where
        T: 'static,
    {
        self.would_be_satisfied_by::<tags::Value<T>>()
    }

    /// Reports whether a reference to `T` is still wanted.
    ///
    /// Returns `false` once the request holds a reference to `T`, or when the
    /// request is for a different type.
    pub fn would_be_satisfied_by_ref_of<T>(&self) -> bool
    where
        T: ?Sized + 'static,
    {
        self.would_be_satisfied_by::<tags::Ref<tags::MaybeSizedValue<T>>>()
    }

    /// Provides a value with the given type tag.
    fn provide<I>(&mut self, value: I::Reified) -> &mut Self
    where
        I: tags::Type<'a>,
    {
        if let Some(res @ TaggedOption(None)) = self.0.downcast_mut::<I>() {
            res.0 = Some(value);
        }
        self
    }

    /// Provides a lazily computed value with the given type tag.
    fn provide_with<I>(&mut self, fulfil: impl FnOnce() -> I::Reified) -> &mut Self
    where
        I: tags::Type<'a>,
    {
        if let Some(res @ TaggedOption(None)) = self.0.downcast_mut::<I>() {
            res.0 = Some(fulfil());
        }
        self
    }

    /// Reports whether the request is still unsatisfied for the given tag.
    fn would_be_satisfied_by<I>(&self) -> bool
    where
        I: tags::Type<'a>,
    {
        matches!(self.0.downcast::<I>(), Some(TaggedOption(None)))
    }
}

impl<'a> Debug for Request<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request").finish_non_exhaustive()
    }
}

/// Requests a value of type `T` from the given error.
///
/// Returns `Some` when the error (or, if it chose to forward, an error it
/// wraps) provides a value of exactly `T`. The requested type must be
/// `'static`.
///
/// ```rust
/// use caution_error::{request_value, Request, ProviderError};
///
/// struct ExitCode(u8);
///
/// #[derive(Debug)]
/// struct Failed;
///
/// impl std::fmt::Display for Failed {
///     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
///         f.write_str("failed")
///     }
/// }
///
/// impl std::error::Error for Failed {}
///
/// impl ProviderError for Failed {
///     fn provide<'a>(&'a self, request: &mut Request<'a>) {
///         request.provide_value::<ExitCode>(ExitCode(2));
///     }
/// }
///
/// assert_eq!(request_value::<ExitCode>(&Failed).map(|c| c.0), Some(2));
/// ```
pub fn request_value<'a, T>(err: &'a (impl ProviderError + ?Sized)) -> Option<T>
where
    T: 'static,
{
    request_by_type_tag::<'a, tags::Value<T>>(err)
}

/// Requests a reference of type `T` from the given error.
///
/// Returns `Some` when the error (or, if it chose to forward, an error it
/// wraps) provides a reference of exactly `T`. The requested type must be
/// `'static` but may be unsized, for example `str`.
///
/// ```rust
/// use caution_error::{request_ref, Request, ProviderError};
///
/// #[derive(Debug)]
/// struct RequestId(String);
///
/// #[derive(Debug)]
/// struct Failed {
///     request_id: RequestId,
/// }
///
/// impl std::fmt::Display for Failed {
///     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
///         f.write_str("failed")
///     }
/// }
///
/// impl std::error::Error for Failed {}
///
/// impl ProviderError for Failed {
///     fn provide<'a>(&'a self, request: &mut Request<'a>) {
///         request.provide_ref::<str>(&self.request_id.0);
///     }
/// }
///
/// let err = Failed { request_id: RequestId("req-7".into()) };
/// assert_eq!(request_ref::<str>(&err), Some("req-7"));
/// ```
pub fn request_ref<'a, T>(err: &'a (impl ProviderError + ?Sized)) -> Option<&'a T>
where
    T: 'static + ?Sized,
{
    request_by_type_tag::<'a, tags::Ref<tags::MaybeSizedValue<T>>>(err)
}

/// Requests a value by type tag from the error.
fn request_by_type_tag<'a, I>(err: &'a (impl ProviderError + ?Sized)) -> Option<I::Reified>
where
    I: tags::Type<'a>,
{
    let mut tagged = Tagged {
        tag_id: TypeId::of::<I>(),
        value: TaggedOption::<'a, I>(None),
    };
    ProviderError::provide(err, tagged.as_request());
    tagged.value.0
}

/// Type tags identify a requested type with a separate, `'static` value.
///
/// A tag carries the `'static` type used for the [`TypeId`] comparison while
/// the reified value may borrow (for example `&'a str`). This is what lets a
/// request name a borrowed type.
mod tags {
    use std::marker::PhantomData;

    /// Describes a type that can be requested for a given lifetime `'a`.
    pub(super) trait Type<'a>: Sized + 'static {
        /// The type of value that this tag reifies to for the lifetime `'a`.
        type Reified: 'a;
    }

    /// Like [`Type`], but for possibly unsized types such as `str`.
    pub(super) trait MaybeSizedType<'a>: Sized + 'static {
        type Reified: 'a + ?Sized;
    }

    impl<'a, T: Type<'a>> MaybeSizedType<'a> for T {
        type Reified = T::Reified;
    }

    /// Tag for a value that is bounded by `'static`.
    #[derive(Debug)]
    pub(super) struct Value<T: 'static>(PhantomData<T>);

    impl<'a, T: 'static> Type<'a> for Value<T> {
        type Reified = T;
    }

    /// Tag for a possibly unsized value bounded by `'static`.
    #[derive(Debug)]
    pub(super) struct MaybeSizedValue<T: ?Sized + 'static>(PhantomData<T>);

    impl<'a, T: ?Sized + 'static> MaybeSizedType<'a> for MaybeSizedValue<T> {
        type Reified = T;
    }

    /// Tag for a reference `&'a T`.
    #[derive(Debug)]
    pub(super) struct Ref<I>(PhantomData<I>);

    impl<'a, I: MaybeSizedType<'a>> Type<'a> for Ref<I> {
        type Reified = &'a I::Reified;
    }
}

/// An `Option` with a type tag `I`.
///
/// The concrete type is erased behind [`Erased`] so that a [`Request`] can hold
/// any tag; the [`TypeId`] recorded alongside it makes the downcast sound.
#[repr(transparent)]
struct TaggedOption<'a, I: tags::Type<'a>>(Option<I::Reified>);

impl<'a, I: tags::Type<'a>> Tagged<TaggedOption<'a, I>> {
    /// Views this concrete tagged option as a type-erased [`Request`].
    fn as_request(&mut self) -> &mut Request<'a> {
        let erased = self as &mut Tagged<dyn Erased<'a> + 'a>;
        // SAFETY: `Request` is `#[repr(transparent)]` over exactly
        // `Tagged<dyn Erased<'a> + 'a>`, so the two have the same layout.
        unsafe { &mut *(erased as *mut Tagged<dyn Erased<'a>> as *mut Request<'a>) }
    }
}

/// A type-erased but identifiable object.
///
/// Implemented only by [`TaggedOption`], whose tagged type provides the
/// [`TypeId`] needed to make a downcast sound.
///
/// # Safety
///
/// Every implementation must be a [`TaggedOption`], so that a `Tagged<E>`
/// whose `tag_id` equals `TypeId::of::<I>()` is in fact a
/// `Tagged<TaggedOption<I>>`.
unsafe trait Erased<'a>: 'a {}

// SAFETY: only `TaggedOption` is ever erased, and each records the `TypeId` of
// its own tag, which is what the downcasts below check before converting.
unsafe impl<'a, I: tags::Type<'a>> Erased<'a> for TaggedOption<'a, I> {}

/// Pairs a tag's [`TypeId`] with the erased option that the tag describes.
struct Tagged<E: ?Sized> {
    tag_id: TypeId,
    value: E,
}

impl<'a> Tagged<dyn Erased<'a> + 'a> {
    /// Returns a reference to the option when it is tagged with `I`.
    fn downcast<I>(&self) -> Option<&TaggedOption<'a, I>>
    where
        I: tags::Type<'a>,
    {
        if self.tag_id == TypeId::of::<I>() {
            // SAFETY: the `tag_id` check above proves the erased value is a
            // `Tagged<TaggedOption<'a, I>>`; `Tagged` is `repr(Rust)` but the
            // concrete layout is identical for every `I`.
            Some(&unsafe { &*(self as *const Self).cast::<Tagged<TaggedOption<'a, I>>>() }.value)
        } else {
            None
        }
    }

    /// Returns a mutable reference to the option when it is tagged with `I`.
    fn downcast_mut<I>(&mut self) -> Option<&mut TaggedOption<'a, I>>
    where
        I: tags::Type<'a>,
    {
        if self.tag_id == TypeId::of::<I>() {
            // SAFETY: as in `downcast`, the `tag_id` check above proves the
            // erased value is a `Tagged<TaggedOption<'a, I>>`.
            Some(
                &mut unsafe { &mut *(self as *mut Self).cast::<Tagged<TaggedOption<'a, I>>>() }
                    .value,
            )
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Request, request_ref, request_value};
    use crate::ProviderError;
    use std::fmt;

    #[derive(Debug)]
    struct Backtrace;

    #[derive(Debug)]
    struct TeaPot;

    #[derive(Debug)]
    struct Source {
        depth: u8,
    }

    #[derive(Debug)]
    struct Error {
        backtrace: Backtrace,
        name: String,
        code: u16,
        source: Source,
    }

    impl fmt::Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("example error")
        }
    }

    impl std::error::Error for Error {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.source)
        }
    }

    impl fmt::Display for Source {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("source error")
        }
    }

    impl std::error::Error for Source {}

    impl ProviderError for Error {
        fn provide<'a>(&'a self, request: &mut Request<'a>) {
            request.provide_ref::<Backtrace>(&self.backtrace);
            request.provide_ref::<str>(&self.name);
            request.provide_value::<u16>(self.code);
        }
    }

    impl ProviderError for Source {
        fn provide<'a>(&'a self, request: &mut Request<'a>) {
            request.provide_value::<u8>(self.depth);
        }
    }

    fn error() -> Error {
        Error {
            backtrace: Backtrace,
            name: "edge".to_string(),
            code: 503,
            source: Source { depth: 2 },
        }
    }

    #[test]
    fn request_ref_finds_reference() {
        let err = error();
        let bt = request_ref::<Backtrace>(&err).expect("backtrace provided");
        assert!(std::ptr::eq(bt, &err.backtrace));
    }

    #[test]
    fn request_ref_supports_unsized() {
        let err = error();
        assert_eq!(request_ref::<str>(&err), Some("edge"));
    }

    #[test]
    fn request_value_copies_value() {
        let err = error();
        assert_eq!(request_value::<u16>(&err), Some(503));
    }

    #[test]
    fn unmet_request_is_none() {
        let err = error();
        assert!(request_ref::<TeaPot>(&err).is_none());
        assert!(request_value::<usize>(&err).is_none());
    }

    #[test]
    fn source_is_reachable_through_the_supertrait() {
        let err = error();
        let source = std::error::Error::source(&err).expect("source present");
        assert_eq!(source.to_string(), "source error");
        assert_eq!(request_value::<u8>(&err), None, "source is not forwarded");
    }

    #[test]
    fn lazy_value_is_only_computed_when_requested() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        #[derive(Debug)]
        struct Lazy {
            calls: Arc<AtomicU32>,
        }

        impl fmt::Display for Lazy {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("lazy")
            }
        }

        impl std::error::Error for Lazy {}

        impl ProviderError for Lazy {
            fn provide<'a>(&'a self, request: &mut Request<'a>) {
                request.provide_value_with::<u32>(|| {
                    self.calls.fetch_add(1, Ordering::SeqCst);
                    1
                });
            }
        }

        let calls = Arc::new(AtomicU32::new(0));
        let err = Lazy {
            calls: Arc::clone(&calls),
        };

        assert!(request_value::<u64>(&err).is_none());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "unmatched request ran closure"
        );

        assert_eq!(request_value::<u32>(&err), Some(1));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn first_provider_wins() {
        #[derive(Debug)]
        struct Outer {
            inner: Inner,
        }

        #[derive(Debug)]
        struct Inner;

        impl fmt::Display for Outer {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("outer")
            }
        }

        impl fmt::Display for Inner {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("inner")
            }
        }

        impl std::error::Error for Outer {}
        impl std::error::Error for Inner {}

        impl ProviderError for Inner {
            fn provide<'a>(&'a self, request: &mut Request<'a>) {
                request.provide_value::<u8>(2);
                assert!(!request.would_be_satisfied_by_value_of::<u8>());
            }
        }

        impl ProviderError for Outer {
            fn provide<'a>(&'a self, request: &mut Request<'a>) {
                request.provide_value::<u8>(1);
                ProviderError::provide(&self.inner, request);
            }
        }

        let outer = Outer { inner: Inner };
        assert_eq!(request_value::<u8>(&outer), Some(1));
    }
}
