//! Helper macro used by the binary to register default plugins.
//!
//! Expands `spd_register!(PluginKind, ConcreteType)` to a call to
//! `crate::registry::register(Plugin::PluginKind(Box::new(ConcreteType::new())))`.
//! Used in the spd binary so plugin registration is driven by the binary (avoids
//! circular dependency with a separate spd-registry crate).

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
