use std::array;

pub mod debug_utils;
pub mod parsing;
pub mod prover_state;

pub trait Compat<Out> {
    fn compat(self) -> Out;
}

impl Compat<__compat_primitive_types::H160> for alloy::primitives::Address {
    fn compat(self) -> __compat_primitive_types::H160 {
        let alloy::primitives::Address(alloy::primitives::FixedBytes(arr)) = self;
        __compat_primitive_types::H160(arr)
    }
}

impl Compat<__compat_primitive_types::H256> for alloy::primitives::B256 {
    fn compat(self) -> __compat_primitive_types::H256 {
        let alloy::primitives::FixedBytes(arr) = self;
        __compat_primitive_types::H256(arr)
    }
}

impl Compat<[__compat_primitive_types::U256; 8]> for alloy::primitives::Bloom {
    fn compat(self) -> [__compat_primitive_types::U256; 8] {
        let alloy::primitives::Bloom(alloy::primitives::FixedBytes(src)) = self;
        // have      u8 * 256
        // want    U256 * 8
        // (no unsafe, no unstable)
        let mut chunks = src.chunks_exact(32);
        let dst = array::from_fn(|_ix| {
            __compat_primitive_types::U256::from(
                <[u8; 32]>::try_from(chunks.next().unwrap()).unwrap(),
            )
        });
        assert_eq!(chunks.len(), 0);
        dst
    }
}

#[test]
fn bloom() {
    let _did_not_panic = alloy::primitives::Bloom::ZERO.compat();
}
