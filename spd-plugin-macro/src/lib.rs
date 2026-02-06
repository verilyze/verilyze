// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later

// This file is part of super-duper. Copyright © 2026 Travis Post
//
// super-duper is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// super-duper is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.

// You should have received a copy of the GNU General Public License along with
// super-duper. If not, see <https://www.gnu.org/licenses/>.

//! Helper macro used by the binary to register default plugins.
//!
//! Expands `spd_register!(PluginKind, ConcreteType)` to a call to
//! `crate::registry::register(Plugin::PluginKind(Box::new(ConcreteType::new())))`.
//! Used in the spd binary so plugin registration is driven by the binary
//! (avoids circular dependency with a separate spd-registry crate).

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
pub fn spd_register(input: TokenStream) -> TokenStream {
    let RegisterCall {
        variant,
        concrete_type,
    } = syn::parse_macro_input!(input as RegisterCall);

    let expanded = quote! {
        crate::registry::register(crate::registry::Plugin::#variant(Box::new(#concrete_type::new())));
    };

    TokenStream::from(expanded)
}
