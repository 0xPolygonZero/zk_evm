use ethereum_types::{H256, U256};

pub(crate) fn u2b(x: U256) -> [u8; 32] {
    let mut res = [0; 32];
    x.to_big_endian(&mut res);
    res
}

pub(crate) fn u2h(x: U256) -> H256 {
    H256(u2b(x))
}
