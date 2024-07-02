use quote::quote;
use syn::{Data, DeriveInput, Result};

use crate::common::{ensure, is_repr_c};

/// Implements `Borrow`, `BorrowMut`, `From`, `Index`, `IndexMut`, and
/// `Default`.
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
        impl<T> ::core::borrow::Borrow<#name<T>> for [T; #num_columns]
        where
            T: ::core::marker::Copy,
        {
            fn borrow(&self) -> &#name<T> {
                unsafe { ::core::mem::transmute(self) }
            }
        }

        impl<T> ::core::borrow::BorrowMut<#name<T>> for [T; #num_columns]
        where
            T: ::core::marker::Copy,
        {
            fn borrow_mut(&mut self) -> &mut #name<T> {
                unsafe { ::core::mem::transmute(self) }
            }
        }

        impl<T> ::core::borrow::Borrow<[T; #num_columns]> for #name<T>
        where
            T: ::core::marker::Copy,
        {
            fn borrow(&self) -> &[T; #num_columns] {
                unsafe { ::core::mem::transmute(self) }
            }
        }

        impl<T> ::core::borrow::BorrowMut<[T; #num_columns]> for #name<T>
        where
            T: ::core::marker::Copy,
        {
            fn borrow_mut(&mut self) -> &mut [T; #num_columns] {
                unsafe { ::core::mem::transmute(self) }
            }
        }

        impl<T> From<[T; #num_columns]> for #name<T>
        where
            T: ::core::marker::Copy,
        {
            fn from(value: [T; #num_columns]) -> Self {
                debug_assert_eq!(
                    ::core::mem::size_of::<#name<T>>(),
                    ::core::mem::size_of::<[T; #num_columns]>()
                );
                // Need ManuallyDrop so that `value` is not dropped by this function.
                let value = ::core::mem::ManuallyDrop::new(value);
                // Copy the bit pattern. The original value is no longer safe to use.
                unsafe { ::core::mem::transmute_copy(&value) }
            }
        }

        impl<T> From<#name<T>> for [T; #num_columns]
        where
            T: ::core::marker::Copy,
        {
            fn from(value: #name<T>) -> Self {
                debug_assert_eq!(
                    ::core::mem::size_of::<#name<T>>(),
                    ::core::mem::size_of::<[T; #num_columns]>()
                );
                // Need ManuallyDrop so that `value` is not dropped by this function.
                let value = ::core::mem::ManuallyDrop::new(value);
                // Copy the bit pattern. The original value is no longer safe to use.
                unsafe { ::core::mem::transmute_copy(&value) }
            }
        }

        impl<T, I> ::core::ops::Index<I> for #name<T>
        where
            T: ::core::marker::Copy,
            [T]: ::core::ops::Index<I>,
        {
            type Output = <[T] as ::core::ops::Index<I>>::Output;

            fn index(&self, index: I) -> &<Self as ::core::ops::Index<I>>::Output {
                let arr = ::core::borrow::Borrow::<[T; #num_columns]>::borrow(self);
                <[T] as ::core::ops::Index<I>>::index(arr, index)
            }
        }

        impl<T, I> ::core::ops::IndexMut<I> for #name<T>
        where
            T: ::core::marker::Copy,
            [T]: ::core::ops::IndexMut<I>,
        {
            fn index_mut(&mut self, index: I) -> &mut <Self as ::core::ops::Index<I>>::Output {
                let arr = ::core::borrow::BorrowMut::<[T; #num_columns]>::borrow_mut(self);
                <[T] as ::core::ops::IndexMut<I>>::index_mut(arr, index)
            }
        }

        impl<T> ::core::default::Default for #name<T>
        where
            T: ::core::marker::Copy + ::core::default::Default,
        {
            fn default() -> Self {
                ::core::convert::Into::<Self>::into(
                    [<T as ::core::default::Default>::default(); #num_columns]
                )
            }
        }
    })
}
