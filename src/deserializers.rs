//! Custom deserializers for Serde.
use hex::FromHex;
use plonky2_evm::generation::mpt::LegacyReceiptRlp;
use rlp::DecoderError;
use serde::{
    de::{Error, Visitor},
    Deserialize, Deserializer,
};

#[derive(Clone, Debug, Default, Deserialize)]
pub(crate) struct ByteString(#[serde(with = "self")] pub(crate) Vec<u8>);

impl From<ByteString> for Vec<u8> {
    fn from(v: ByteString) -> Self {
        v.0
    }
}

impl TryFrom<ByteString> for LegacyReceiptRlp {
    type Error = DecoderError;

    fn try_from(value: ByteString) -> Result<Self, Self::Error> {
        rlp::decode(&value.0)
    }
}

fn remove_hex_prefix_if_present(data: &str) -> &str {
    let prefix = &data[..2];

    match matches!(prefix, "0x" | "0X") {
        false => data,
        true => &data[2..],
    }
}

// Gross, but there is no Serde crate that can both parse a hex string with a
// prefix and also deserialize from a `Vec<u8>`.
fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    struct PrefixHexStrVisitor();

    impl<'de> Visitor<'de> for PrefixHexStrVisitor {
        type Value = Vec<u8>;

        fn visit_str<E>(self, data: &str) -> Result<Self::Value, E>
        where
            E: Error,
        {
            FromHex::from_hex(remove_hex_prefix_if_present(data)).map_err(Error::custom)
        }

        fn visit_borrowed_str<E>(self, data: &'de str) -> Result<Self::Value, E>
        where
            E: Error,
        {
            FromHex::from_hex(remove_hex_prefix_if_present(data)).map_err(Error::custom)
        }

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "a hex encoded string with a prefix")
        }
    }

    deserializer.deserialize_string(PrefixHexStrVisitor())
}
