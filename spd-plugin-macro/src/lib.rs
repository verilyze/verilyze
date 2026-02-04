//! Helper macro used by plug‑in crates to register themselves.

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Ident};

#[proc_macro]
pub fn spd_register(input: TokenStream) -> TokenStream {
    // Expected syntax: spd_register!(MyFinder, MyParser, MyProvider);
    let ids = parse_macro_input!(input as syn::punctuated::Punctuated<Ident, syn::Token![,]>);

    let mut pushers = Vec::new();
    for id in ids.iter() {
        let var = syn::Ident::new(
            &format!("REGISTRY_{}", id.to_string().to_uppercase()),
            id.span(),
        );
        pushers.push(quote! {
            lazy_static::lazy_static! {
                static ref #var: () = {
                    spd::registry::register(Box::new(#id));
                };
            }
        });
    }

    TokenStream::from(quote! {
        #(#pushers)*
    })
}
