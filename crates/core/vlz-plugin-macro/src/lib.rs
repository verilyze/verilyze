// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use proc_macro::TokenStream;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::{Ident, Token};

struct RegisterCall {
    variant: Ident,
    concrete_type: Ident,
}

impl Parse for RegisterCall {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let variant: Ident = input.parse()?;
        input.parse::<Token![,]>()?;
        let concrete_type: Ident = input.parse()?;
        Ok(RegisterCall {
            variant,
            concrete_type,
        })
    }
}

/// Expand `vlz_register!(Variant, Type)` into a `registry::register` call.
///
/// Uses `proc_macro2` so the expansion logic can be unit-tested. The
/// `#[proc_macro]` entry point is a thin TokenStream bridge (proc-macro
/// APIs cannot be invoked from ordinary `#[test]` functions).
fn vlz_register_impl(
    input: proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    let RegisterCall {
        variant,
        concrete_type,
    } = match syn::parse2(input) {
        Ok(call) => call,
        Err(err) => return err.to_compile_error(),
    };

    quote! {
        crate::registry::register(crate::registry::Plugin::#variant(Box::new(#concrete_type::new())));
    }
}

#[proc_macro]
pub fn vlz_register(input: TokenStream) -> TokenStream {
    vlz_register_impl(input.into()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::quote;

    #[test]
    fn vlz_register_expands_variant_and_concrete_type() {
        let output = vlz_register_impl(quote! { Reporter, DefaultReporter })
            .to_string();
        assert!(
            output.contains("registry :: register"),
            "expected register call, got: {output}"
        );
        assert!(
            output.contains("Plugin :: Reporter"),
            "expected Plugin variant, got: {output}"
        );
        assert!(
            output.contains("DefaultReporter :: new"),
            "expected concrete::new(), got: {output}"
        );
    }

    #[test]
    fn vlz_register_rejects_missing_comma() {
        let output =
            vlz_register_impl(quote! { Reporter DefaultReporter }).to_string();
        assert!(
            output.contains("compile_error"),
            "expected compile_error, got: {output}"
        );
    }

    #[test]
    fn vlz_register_rejects_empty_input() {
        let output =
            vlz_register_impl(proc_macro2::TokenStream::new()).to_string();
        assert!(
            output.contains("compile_error"),
            "expected compile_error, got: {output}"
        );
    }

    #[test]
    fn vlz_register_rejects_missing_concrete_type() {
        let output = vlz_register_impl(quote! { Reporter, }).to_string();
        assert!(
            output.contains("compile_error"),
            "expected compile_error, got: {output}"
        );
    }

    #[test]
    fn register_call_parse_round_trip() {
        let tokens = quote! { ManifestFinder, MyFinder };
        let parsed: RegisterCall =
            syn::parse2(tokens).expect("parse RegisterCall");
        assert_eq!(parsed.variant.to_string(), "ManifestFinder");
        assert_eq!(parsed.concrete_type.to_string(), "MyFinder");
    }
}
