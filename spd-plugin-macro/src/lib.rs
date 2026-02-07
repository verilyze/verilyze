// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
//
// This file is part of super-duper.
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
//
// You should have received a copy of the GNU General Public License along with
// super-duper (see the COPYING file in the project root for the full text). If
// not, see <https://www.gnu.org/licenses/>.

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
