//! Custom deserializers / serializers for Serde.
use hex::{FromHex, ToHex};
use serde::{
    de::{Error, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ByteString(#[serde(with = "self")] pub Vec<u8>);

impl From<ByteString> for Vec<u8> {
    fn from(v: ByteString) -> Self {
        v.0
    }
}

impl std::ops::Deref for ByteString {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<u8>> for ByteString {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
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

impl Serialize for ByteString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_string = format!("0x{}", self.0.encode_hex::<String>());

        serializer.serialize_str(&hex_string)
    }
}
