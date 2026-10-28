// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Derive macro for [`caution_error::ProviderError`].
//!
//! See `caution_error` for the trait and the generated API. The derive emits
//! only the `ProviderError` implementation; it never implements
//! `std::error::Error`, so it composes with `thiserror` (and therefore with
//! `dterror`), which are the crates that own the standard error impl.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream};
use syn::{
    Data, DataEnum, DeriveInput, Field, Fields, GenericArgument, Index, Meta, PathArguments, Token,
    Type, parse_macro_input,
};

/// Derives [`caution_error::ProviderError`] for a struct or enum.
///
/// A field is provided only when it carries `#[provide]`, and always by
/// reference with `provide_ref`, so nothing is cloned.
///
/// - `#[provide]` exposes the field's own declared type:
///   `provide_ref::<FieldType>(&self.field)`.
/// - `#[provide(ref = T)]` exposes a reference to `T` instead:
///   `provide_ref::<T>(&self.field)`. The field is deref-coerced to `&T`, so a
///   `Vec<Note>` field with `ref = [Note]` provides `&[Note]`, and a
///   `&'static std::panic::Location<'static>` field with
///   `ref = caution_error::Location` provides `&Location`. This names the type
///   explicitly, so it also works when the field is spelled with an alias.
///
/// A field marked `#[source]` (or `#[from]`) wires `provider_source`
/// automatically. The source's type is not required to implement the trait: the
/// generated code probes it at compile time, returning `Some` for a
/// [`caution_error::ProviderError`] and `None` otherwise, so a typed source and
/// a `Box<dyn Error + Send + Sync>` source both build.
///
/// `Option<T>` sources are unwrapped first: `None` yields `None`, and `Some` is
/// probed like any other source. `Box<T>`, `Box<dyn ProviderError>`, and
/// `&'static dyn ProviderError` sources are reachable, because those types are
/// themselves [`caution_error::ProviderError`].
///
/// The derive does not implement `std::error::Error`; the type must get that
/// from `thiserror` (or an equivalent), which is how `dterror` errors are
/// built.
///
/// ```ignore
/// #[derive(Debug, thiserror::Error, dterror::CtxError, caution_error::ProviderError)]
/// #[error("upstream returned {status}")]
/// struct UpstreamError {
///     #[provide]
///     request_id: String,
///     #[provide(ref = [caution_error::Note])]
///     notes: Vec<caution_error::Note>,
///     #[provide(ref = [caution_error::Warning])]
///     warnings: Vec<caution_error::Warning>,
///     #[provide(ref = caution_error::Location)]
///     #[location]
///     location: dterror::Location,
///     #[source]
///     cause: SomeTypedError,
///     status: u16,
/// }
/// ```
#[proc_macro_derive(ProviderError, attributes(provide, source, from))]
pub fn derive_provider_error(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand(&input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// The type a `#[provide]` field is exposed as.
enum ProvideTarget {
    /// The field's own declared type.
    FieldType,
    /// The type named by `#[provide(ref = T)]`.
    Explicit(Box<Type>),
}

/// The parsed contents of `#[provide(ref = Type)]`.
struct RefProvide {
    target: Type,
}

impl Parse for RefProvide {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        input.parse::<Token![ref]>()?;
        input.parse::<Token![=]>()?;
        let target: Type = input.parse()?;
        Ok(Self { target })
    }
}

/// Expands the derive for one item.
fn expand(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let (provide_body, provider_source) = match &input.data {
        Data::Struct(data) => (
            struct_provide_body(&data.fields)?,
            struct_provider_source(&data.fields),
        ),
        Data::Enum(data) => (enum_provide_body(data)?, enum_provider_source(data)),
        Data::Union(_) => {
            return Err(syn::Error::new_spanned(
                name,
                "ProviderError cannot be derived for unions",
            ));
        }
    };

    let provider_source_method = provider_source.map(|body| {
        quote! {
            fn provider_source(&self) -> Option<&(dyn caution_error::ProviderError + 'static)> {
                #body
            }
        }
    });

    Ok(quote! {
        impl #impl_generics caution_error::ProviderError for #name #ty_generics #where_clause {
            fn provide<'a>(&'a self, request: &mut caution_error::Request<'a>) {
                #provide_body
            }

            #provider_source_method
        }
    })
}

/// Builds the `provide` body for a struct.
fn struct_provide_body(fields: &Fields) -> syn::Result<TokenStream2> {
    let mut body = TokenStream2::new();
    for (position, field) in fields.iter().enumerate() {
        let Some(target) = provide_target(field)? else {
            continue;
        };
        let reference = field_reference(field, position);
        body.extend(provide_statement(&target, &field.ty, reference));
    }
    Ok(body)
}

/// Builds the `provide` body for an enum.
fn enum_provide_body(data: &DataEnum) -> syn::Result<TokenStream2> {
    if !data.variants.iter().any(variant_contributes) {
        return Ok(TokenStream2::new());
    }

    let mut arms = TokenStream2::new();
    for variant in &data.variants {
        let variant_ident = &variant.ident;
        let arm = match &variant.fields {
            Fields::Unit => quote! { Self::#variant_ident => {} },
            Fields::Named(named) => {
                let mut bindings = Vec::new();
                let mut stmts = TokenStream2::new();
                for field in &named.named {
                    let Some(target) = provide_target(field)? else {
                        continue;
                    };
                    let ident = named_field_ident(field);
                    stmts.extend(provide_statement(&target, &field.ty, quote!(#ident)));
                    bindings.push(quote!(#ident));
                }
                quote! { Self::#variant_ident { #(#bindings,)* .. } => { #stmts } }
            }
            Fields::Unnamed(unnamed) => {
                let mut patterns = Vec::new();
                let mut stmts = TokenStream2::new();
                for (position, field) in unnamed.unnamed.iter().enumerate() {
                    let Some(target) = provide_target(field)? else {
                        patterns.push(quote!(_));
                        continue;
                    };
                    let binding = format_ident!("__provide_{}", position);
                    stmts.extend(provide_statement(&target, &field.ty, quote!(#binding)));
                    patterns.push(quote!(#binding));
                }
                quote! { Self::#variant_ident(#(#patterns),*) => { #stmts } }
            }
        };
        arms.extend(quote! { #arm, });
    }

    Ok(quote! { match self { #arms } })
}

/// Builds the `provider_source` body for a struct, when it has a source field.
fn struct_provider_source(fields: &Fields) -> Option<TokenStream2> {
    let (position, field) = fields
        .iter()
        .enumerate()
        .find(|(_, field)| is_source(field))?;
    let access = field_reference(field, position);
    Some(source_probe(access, &field.ty))
}

/// Builds the `provider_source` body for an enum, when any variant has a source
/// field.
fn enum_provider_source(data: &DataEnum) -> Option<TokenStream2> {
    if !data.variants.iter().any(variant_has_source) {
        return None;
    }

    let mut arms = TokenStream2::new();
    for variant in &data.variants {
        let variant_ident = &variant.ident;
        let arm = match &variant.fields {
            Fields::Unit => quote! { Self::#variant_ident => None },
            Fields::Named(named) => match named.named.iter().find(|f| is_source(f)) {
                Some(field) => {
                    let ident = named_field_ident(field);
                    let body = source_probe(quote!(#ident), &field.ty);
                    quote! { Self::#variant_ident { #ident, .. } => #body }
                }
                None => quote! { Self::#variant_ident { .. } => None },
            },
            Fields::Unnamed(unnamed) => {
                let mut patterns = Vec::new();
                let mut binding = None;
                for (position, field) in unnamed.unnamed.iter().enumerate() {
                    if is_source(field) && binding.is_none() {
                        let ident = format_ident!("__source_{}", position);
                        patterns.push(quote!(#ident));
                        binding = Some((ident, &field.ty));
                    } else {
                        patterns.push(quote!(_));
                    }
                }
                match binding {
                    Some((ident, ty)) => {
                        let body = source_probe(quote!(#ident), ty);
                        quote! { Self::#variant_ident(#(#patterns),*) => #body }
                    }
                    None => quote! { Self::#variant_ident(#(#patterns),*) => None },
                }
            }
        };
        arms.extend(quote! { #arm, });
    }

    Some(quote! { match self { #arms } })
}

/// Builds one `provide_ref` statement for a field.
///
/// `reference` is a reference to the field. Its type may differ from the target
/// (`&Vec<Note>` for `[Note]`, `&&Location` for `Location`); the compiler
/// deref-coerces it at this call site.
fn provide_statement(
    target: &ProvideTarget,
    field_type: &Type,
    reference: TokenStream2,
) -> TokenStream2 {
    let target: &Type = match target {
        ProvideTarget::FieldType => field_type,
        ProvideTarget::Explicit(target) => target,
    };
    quote! { request.provide_ref::<#target>(#reference); }
}

/// Builds the `provider_source` expression for a source field.
///
/// An `Option<T>` source is unwrapped first, so `None` yields `None` and `Some`
/// is probed like any other source. Every other type is probed directly.
fn source_probe(access: TokenStream2, ty: &Type) -> TokenStream2 {
    match option_inner(ty) {
        Some(_) => {
            let inner = probe(quote!(__provider_source));
            quote! {
                (#access).as_ref().and_then(|__provider_source| #inner)
            }
        }
        None => probe(access),
    }
}

/// Returns the `T` of an `Option<T>` type, spelled with any `Option` path or
/// fully qualified.
fn option_inner(ty: &Type) -> Option<&Type> {
    let Type::Path(path) = ty else {
        return None;
    };
    let segment = path.path.segments.last()?;
    if segment.ident != "Option" {
        return None;
    }
    let PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return None;
    };
    let mut types = arguments.args.iter().filter_map(|argument| match argument {
        GenericArgument::Type(ty) => Some(ty),
        _ => None,
    });
    let inner = types.next()?;
    types.next().is_none().then_some(inner)
}

/// Builds an expression that resolves a reference to an already-borrowed field
/// to `Option<&dyn ProviderError>` through the compile-time probe.
fn probe(reference: TokenStream2) -> TokenStream2 {
    quote! {
        {
            #[allow(unused_imports, reason = "only used by the fallback path")]
            use caution_error::__private::ProviderSourceFallback as _;
            caution_error::__private::ProviderSource(#reference).as_provider_source()
        }
    }
}

/// Returns the `&self.<field>` accessor for a struct field.
fn field_reference(field: &Field, position: usize) -> TokenStream2 {
    match &field.ident {
        Some(ident) => quote!(&self.#ident),
        None => {
            let index = Index::from(position);
            quote!(&self.#index)
        }
    }
}

/// Returns the identifier of a named field.
fn named_field_ident(field: &Field) -> &syn::Ident {
    field
        .ident
        .as_ref()
        .expect("named field always has an identifier")
}

/// Returns how a field is provided, when it is.
fn provide_target(field: &Field) -> syn::Result<Option<ProvideTarget>> {
    let Some(attribute) = field
        .attrs
        .iter()
        .find(|attribute| attribute.path().is_ident("provide"))
    else {
        return Ok(None);
    };

    match &attribute.meta {
        Meta::Path(_) => Ok(Some(ProvideTarget::FieldType)),
        Meta::List(list) if list.tokens.is_empty() => Ok(Some(ProvideTarget::FieldType)),
        Meta::List(list) => {
            let parsed: RefProvide = list.parse_args().map_err(|_| {
                syn::Error::new_spanned(
                    list,
                    "unsupported #[provide(...)]; use `#[provide]` or `#[provide(ref = Type)]`",
                )
            })?;
            Ok(Some(ProvideTarget::Explicit(Box::new(parsed.target))))
        }
        Meta::NameValue(_) => Err(syn::Error::new_spanned(
            attribute,
            "unsupported #[provide = ...]; use `#[provide]` or `#[provide(ref = Type)]`",
        )),
    }
}

/// Returns true when a variant holds at least one provided field.
fn variant_contributes(variant: &syn::Variant) -> bool {
    variant
        .fields
        .iter()
        .any(|field| has_attribute(field, "provide"))
}

/// Returns true when a variant holds at least one source field.
fn variant_has_source(variant: &syn::Variant) -> bool {
    variant.fields.iter().any(is_source)
}

/// Returns true when a field is the error source, marked with `#[source]` or
/// `#[from]`. An unannotated field named `source` is not treated as a source.
fn is_source(field: &Field) -> bool {
    has_attribute(field, "source") || has_attribute(field, "from")
}

/// Returns true when a field carries the named attribute.
fn has_attribute(field: &Field, name: &str) -> bool {
    field
        .attrs
        .iter()
        .any(|attribute| attribute.path().is_ident(name))
}
