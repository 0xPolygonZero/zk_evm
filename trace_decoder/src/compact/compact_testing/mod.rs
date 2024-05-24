use crate::cfg_if;

mod complex_test_payloads;

cfg_if! {
    if #[cfg(feature = "mpt")] {
        mod complex_test_payloads_mpt;
    } else if #[cfg(feature = "smt")] {
        mod complex_test_payloads_smt;
    }
}
