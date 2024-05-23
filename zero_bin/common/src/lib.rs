pub mod debug_utils;
pub mod parsing;
pub mod prover_state;

pub trait Compat<Out> {
    fn compat(self) -> Out;
}

impl Compat<__compat_primitive_types::H160> for alloy::primitives::Address {
    fn compat(self) -> __compat_primitive_types::H160 {
        todo!()
    }
}

impl Compat<__compat_primitive_types::H256> for alloy::primitives::B256 {
    fn compat(self) -> __compat_primitive_types::H256 {
        todo!()
    }
}

impl Compat<[__compat_primitive_types::U256; 8]> for alloy::primitives::Bloom {
    fn compat(self) -> [__compat_primitive_types::U256; 8] {
        todo!()
    }
}
