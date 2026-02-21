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

#[proc_macro]
pub fn vlz_register(input: TokenStream) -> TokenStream {
    let RegisterCall {
        variant,
        concrete_type,
    } = syn::parse_macro_input!(input as RegisterCall);

    let expanded = quote! {
        crate::registry::register(crate::registry::Plugin::#variant(Box::new(#concrete_type::new())));
    };

    TokenStream::from(expanded)
}
