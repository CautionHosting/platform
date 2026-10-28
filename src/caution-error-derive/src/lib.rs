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
use syn::{Data, DataEnum, DeriveInput, Field, Fields, Index, parse_macro_input};

/// Derives [`caution_error::ProviderError`] for a struct or enum.
///
/// A field is provided only when it carries `#[provide]`. Each marked field is
/// exposed with `provide_ref::<FieldType>`, so context is shared by reference
/// and never cloned; a consumer asks for it with
/// `request_ref::<FieldType>(error)`.
///
/// The derive does not implement `std::error::Error`; the type must get that
/// from `thiserror` (or an equivalent), which is how `dterror` errors are
/// built. It also does not implement `provider_source`; wire that by hand when
/// a typed source's context should be reachable through the chain helpers.
///
/// ```ignore
/// #[derive(Debug, thiserror::Error, caution_error::ProviderError)]
/// #[error("upstream returned {status}")]
/// struct UpstreamError {
///     #[provide]
///     request_id: String,
///     status: u16,
/// }
/// ```
#[proc_macro_derive(ProviderError, attributes(provide))]
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

    let body = match &input.data {
        Data::Struct(data) => struct_body(&data.fields),
        Data::Enum(data) => enum_body(data)?,
        Data::Union(_) => {
            return Err(syn::Error::new_spanned(
                name,
                "ProviderError cannot be derived for unions",
            ));
        }
    };

    Ok(quote! {
        impl #impl_generics caution_error::ProviderError for #name #ty_generics #where_clause {
            fn provide<'a>(&'a self, request: &mut caution_error::Request<'a>) {
                #body
            }
        }
    })
}

/// Builds the `provide` body for a struct.
fn struct_body(fields: &Fields) -> TokenStream2 {
    let mut body = TokenStream2::new();
    for (position, field) in fields.iter().enumerate() {
        if !is_provided(field) {
            continue;
        }
        let ty = &field.ty;
        let access = match &field.ident {
            Some(ident) => quote!(&self.#ident),
            None => {
                let index = Index::from(position);
                quote!(&self.#index)
            }
        };
        body.extend(quote! { request.provide_ref::<#ty>(#access); });
    }
    body
}

/// Builds the `provide` body for an enum.
fn enum_body(data: &DataEnum) -> syn::Result<TokenStream2> {
    if !data.variants.iter().any(variant_provides) {
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
                    if !is_provided(field) {
                        continue;
                    }
                    let ident = field
                        .ident
                        .as_ref()
                        .expect("named field always has an identifier");
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

    Ok(quote! { match self { #arms } })
}

/// Returns true when a variant holds at least one `#[provide]` field.
fn variant_provides(variant: &syn::Variant) -> bool {
    variant.fields.iter().any(is_provided)
}

/// Returns true when a field carries `#[provide]`.
fn is_provided(field: &Field) -> bool {
    field
        .attrs
        .iter()
        .any(|attribute| attribute.path().is_ident("provide"))
}
