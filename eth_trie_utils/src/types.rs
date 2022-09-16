use ethereum_types::U256;

use crate::partial_trie::Nibbles;

pub(crate) type EthAddress = U256;

impl From<EthAddress> for Nibbles {
    fn from(addr: EthAddress) -> Self {
        Self {
            count: 64, /* Always 64, since we are assuming fixed sized keys and `0`s can make up
                        * a key. */
            packed: addr,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::EthAddress;
    use crate::partial_trie::Nibbles;

    #[test]
    fn eth_addr_to_nibbles() {
        let addr = EthAddress::from(0x12);
        let nib = Nibbles::from(addr);

        assert_eq!(nib.count, 64);
        assert_eq!(nib.packed, EthAddress::from(0x12));
    }
}
