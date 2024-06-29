use syn::punctuated::Punctuated;
use syn::{token, Attribute, Meta};

/// Prefixes an error message and generates a `syn::Error` from the message.
macro_rules! span_err {
    ($ast:expr, $msg:literal $(,)?) => {
        ::syn::Error::new_spanned($ast, ::core::concat!("zk_evm_proc_macro error: ", $msg))
    };
}
pub(crate) use span_err;

/// Checks the condition and returns early with a prefixed error message if
/// false.
macro_rules! ensure {
    ($cond:expr, $ast:expr, $msg:literal $(,)?) => {
        if !$cond {
            return Err($crate::common::span_err!($ast, $msg));
        }
    };
}
pub(crate) use ensure;

/// Parses the `Meta` of a `repr` attribute and returns true if one of the
/// elements is "C".
fn is_meta_c(outer: &Meta) -> bool {
    if let Meta::List(inner) = outer {
        let parsed: Punctuated<Meta, token::Comma> = inner
            .parse_args_with(Punctuated::parse_terminated)
            .unwrap_or_default();
        parsed.iter().any(|meta| meta.path().is_ident("C"))
    } else {
        false
    }
}

/// Returns true if `#[repr(C)]` is contained in the attributes.
pub(crate) fn is_repr_c<'a>(attrs: impl IntoIterator<Item = &'a Attribute>) -> bool {
    attrs
        .into_iter()
        .any(|attr| attr.path().is_ident("repr") && is_meta_c(&attr.meta))
}
