mod compile;

/// The `compile_fail` tests in `tests/compile_fail/` are inherently fragile,
/// as small changes in output from rustc or from the trybuild crate may cause
/// them to fail. To regenerate the `*.stderr` files, run:
/// `TRYBUILD=overwrite cargo test -p zk_evm_proc_macro -- test_compile_fail`.
/// Then, check the git diff to ensure that the new `*.stderr` files are what
/// you would expect (most importantly, make sure they actually contain errors).
#[cfg_attr(miri, ignore = "incompatible with miri")]
#[test]
fn test_compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile_fail/*.rs");
}
