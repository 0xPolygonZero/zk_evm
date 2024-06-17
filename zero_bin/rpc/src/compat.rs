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
        let dst = core::array::from_fn(|_ix| {
            // This is a bit spicy because we're going from an uninterpeted array of bytes
            // to wide integers, but we trust this `From` impl to do the right thing
            __compat_primitive_types::U256::from(
                <[u8; 32]>::try_from(chunks.next().unwrap()).unwrap(),
            )
        });
        assert_eq!(chunks.len(), 0);
        dst
    }
}

impl Compat<__compat_primitive_types::U256> for alloy::primitives::U256 {
    fn compat(self) -> __compat_primitive_types::U256 {
        __compat_primitive_types::U256(self.into_limbs())
    }
}

impl Compat<Vec<Vec<u8>>> for Vec<alloy::primitives::Bytes> {
    fn compat(self) -> Vec<Vec<u8>> {
        self.into_iter().map(|x| x.to_vec()).collect()
    }
}

impl Compat<alloy::primitives::Address> for __compat_primitive_types::H160 {
    fn compat(self) -> alloy::primitives::Address {
        let __compat_primitive_types::H160(arr) = self;
        alloy::primitives::Address(alloy::primitives::FixedBytes(arr))
    }
}

impl Compat<alloy::primitives::StorageKey> for __compat_primitive_types::H256 {
    fn compat(self) -> alloy::primitives::StorageKey {
        let __compat_primitive_types::H256(arr) = self;
        alloy::primitives::FixedBytes(arr)
    }
}

#[test]
fn bloom() {
    let _did_not_panic = alloy::primitives::Bloom::ZERO.compat();
}
