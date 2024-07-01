use quote::quote;
use syn::{Data, DeriveInput, Result};

use crate::common::{ensure, is_repr_c};

/// Implements `Deref` and `DerefMut`.
pub(crate) fn try_derive(ast: DeriveInput) -> Result<proc_macro2::TokenStream> {
    let is_struct = matches!(ast.data, Data::Struct(_));
    ensure!(is_struct, &ast, "expected `struct`");

    // Check that the struct is `#[repr(C)]`.
    let repr_c = is_repr_c(&ast.attrs);
    ensure!(repr_c, &ast, "column struct must be `#[repr(C)]`");

    // The name of the struct.
    let name = &ast.ident;

    // SAFETY: `u8` is guaranteed to have a `size_of` of 1.
    // https://doc.rust-lang.org/reference/type-layout.html#primitive-data-layout
    let num_columns = quote!(::core::mem::size_of::<#name<u8>>());

    // SAFETY: A struct generic over T has the same layout as an array [T; N] if:
    // - The struct is `#[repr(C)]`.
    // - Every field is one of T, [T; M], or a type with the same layout as [T; M],
    // - The total number of elements of type T is N.
    // https://doc.rust-lang.org/reference/type-layout.html#reprc-structs
    // https://doc.rust-lang.org/reference/type-layout.html#array-layout
    Ok(quote! {
        impl<T: ::core::marker::Copy> ::core::ops::Deref for #name<T> {
            type Target = [T; #num_columns];

            fn deref(&self) -> &<Self as ::core::ops::Deref>::Target {
                unsafe { ::core::mem::transmute(self) }
            }
        }

        impl<T: ::core::marker::Copy> ::core::ops::DerefMut for #name<T> {
            fn deref_mut(&mut self) -> &mut <Self as ::core::ops::Deref>::Target {
                unsafe { ::core::mem::transmute(self) }
            }
        }
    })
}
