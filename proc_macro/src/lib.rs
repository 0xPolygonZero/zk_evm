//! This library provides two convenient derive macros for interpreting arrays
//! of field elements as structs representing an AIR.
//!
//! Deriving [`Columns`] on a struct `Struct<T>` implements the following
//! conversion traits between `Struct<T>` and arrays `[T; N]` where `N` is the
//! number of fields in the struct: [`Borrow`], [`BorrowMut`], and [`From`].
//! Additionally, the traits [`Index`], [`IndexMut`], and [`Default`] are
//! implemented for `Struct<T>`.
//!
//! Deriving [`DerefColumns`] for a struct generic over `T` implements [`Deref`]
//! and [`DerefMut`] with target `[T; N]` where `N` is the number of fields in
//! the struct.
//!
//! These implementations employ unsafe code and place a burden on the user to
//! ensure their safe usage. Please see the respective macro implementations to
//! understand the conditions that should be upheld by any struct deriving
//! [`Columns`] or [`DerefColumns`]. In short, the struct must be `#[repr(C)]`
//! and all fields must be one of `T`, `[T; M]`, or a type with the same layout
//! as `[T; M]`.
//!
//! [`Borrow`]: ::core::borrow::Borrow
//! [`BorrowMut`]: ::core::borrow::BorrowMut
//! [`Index`]: ::core::ops::Index
//! [`IndexMut`]: ::core::ops::IndexMut
//! [`Deref`]: ::core::ops::Deref
//! [`DerefMut`]: ::core::ops::DerefMut

pub(crate) mod common;
mod impls;

use impls::{columns, deref_columns};

#[proc_macro_derive(Columns)]
pub fn derive_columns(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let ast = syn::parse_macro_input!(input as syn::DeriveInput);
    columns::try_derive(ast)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

#[proc_macro_derive(DerefColumns)]
pub fn derive_deref_columns(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let ast = syn::parse_macro_input!(input as syn::DeriveInput);
    deref_columns::try_derive(ast)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
