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
use syn::{
    Data, DataEnum, DeriveInput, Field, Fields, GenericArgument, Index, PathArguments, Type,
    parse_macro_input,
};

/// Derives [`caution_error::ProviderError`] for a struct or enum.
///
/// A field is provided only when it carries `#[provide]`. Each marked field is
/// exposed with `provide_ref::<FieldType>`, so context is shared by reference
/// and never cloned; a consumer asks for it with
/// `request_ref::<FieldType>(error)`.
///
/// A `#[source]` (or `#[from]`, or a field named `source`) wires
/// `provider_source` automatically. The source's type is not required to
/// implement the trait: the generated code probes it at compile time, returning
/// `Some` for a [`caution_error::ProviderError`] and `None` otherwise, so a
/// typed source and a `Box<dyn Error + Send + Sync>` source both build.
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
/// #[derive(Debug, thiserror::Error, caution_error::ProviderError)]
/// #[error("upstream returned {status}")]
/// struct UpstreamError {
///     #[provide]
///     request_id: String,
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

/// Expands the derive for one item.
fn expand(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let (provide_body, provider_source) = match &input.data {
        Data::Struct(data) => (
            struct_provide_body(&data.fields),
            struct_provider_source(&data.fields),
        ),
        Data::Enum(data) => (enum_provide_body(data), enum_provider_source(data)),
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
fn struct_provide_body(fields: &Fields) -> TokenStream2 {
    let mut body = TokenStream2::new();
    for (position, field) in fields.iter().enumerate() {
        if !is_provided(field) {
            continue;
        }
        let ty = &field.ty;
        let access = field_access(field, position);
        body.extend(quote! { request.provide_ref::<#ty>(#access); });
    }
    body
}

/// Builds the `provider_source` body for a struct, when it has a source field.
fn struct_provider_source(fields: &Fields) -> Option<TokenStream2> {
    let (position, field) = fields
        .iter()
        .enumerate()
        .find(|(_, field)| is_source(field))?;
    let access = field_access(field, position);
    Some(source_probe(access, &field.ty))
}

/// Builds the `provide` body for an enum.
fn enum_provide_body(data: &DataEnum) -> TokenStream2 {
    if !data.variants.iter().any(variant_provides) {
        return TokenStream2::new();
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
                    if !is_provided(field) {
                        continue;
                    }
                    let ident = named_field_ident(field);
                    let ty = &field.ty;
                    stmts.extend(quote! { request.provide_ref::<#ty>(#ident); });
                    bindings.push(quote!(#ident));
                }
                quote! { Self::#variant_ident { #(#bindings,)* .. } => { #stmts } }
            }
            Fields::Unnamed(unnamed) => {
                let mut patterns = Vec::new();
                let mut stmts = TokenStream2::new();
                for (position, field) in unnamed.unnamed.iter().enumerate() {
                    if is_provided(field) {
                        let binding = format_ident!("__provide_{}", position);
                        let ty = &field.ty;
                        stmts.extend(quote! { request.provide_ref::<#ty>(#binding); });
                        patterns.push(quote!(#binding));
                    } else {
                        patterns.push(quote!(_));
                    }
                }
                quote! { Self::#variant_ident(#(#patterns),*) => { #stmts } }
            }
        };
        arms.extend(arm);
    }

    quote! { match self { #arms } }
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
        arms.extend(arm);
    }

    Some(quote! { match self { #arms } })
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
fn field_access(field: &Field, position: usize) -> TokenStream2 {
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

/// Returns true when a variant holds at least one `#[provide]` field.
fn variant_provides(variant: &syn::Variant) -> bool {
    variant.fields.iter().any(is_provided)
}

/// Returns true when a variant holds at least one source field.
fn variant_has_source(variant: &syn::Variant) -> bool {
    variant.fields.iter().any(is_source)
}

/// Returns true when a field carries `#[provide]`.
fn is_provided(field: &Field) -> bool {
    has_attribute(field, "provide")
}

/// Returns true when a field is the error source: `#[source]`, `#[from]`, or a
/// field that `thiserror` treats as the source because it is named `source`.
fn is_source(field: &Field) -> bool {
    has_attribute(field, "source")
        || has_attribute(field, "from")
        || field.ident.as_ref().is_some_and(|ident| ident == "source")
}

/// Returns true when a field carries the named attribute.
fn has_attribute(field: &Field, name: &str) -> bool {
    field
        .attrs
        .iter()
        .any(|attribute| attribute.path().is_ident(name))
}
