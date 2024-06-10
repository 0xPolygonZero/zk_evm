use std::collections::HashMap;

use ethereum_types::{H256, U256};
use hex_literal::hex;

use crate::cpu::kernel::constants::context_metadata::ContextMetadata;
use crate::cpu::kernel::constants::global_metadata::GlobalMetadata;
use crate::cpu::kernel::constants::journal_entry::JournalEntry;
use crate::cpu::kernel::constants::trie_type::PartialTrieType;
use crate::cpu::kernel::constants::txn_fields::NormalizedTxnField;
use crate::generation::mpt::AccountRlp;
use crate::memory::segments::Segment;

pub(crate) mod context_metadata;
mod exc_bitfields;
pub(crate) mod global_metadata;
pub(crate) mod journal_entry;
pub(crate) mod trie_type;
pub(crate) mod txn_fields;

/// Constants that are accessible to our kernel assembly code.
pub(crate) fn evm_constants() -> HashMap<String, U256> {
    let mut c = HashMap::new();

    let hex_constants = MISC_CONSTANTS
        .iter()
        .chain(EC_CONSTANTS.iter())
        .chain(HASH_CONSTANTS.iter())
        .cloned();
    for (name, value) in hex_constants {
        c.insert(name.into(), U256::from_big_endian(&value));
    }

    for (name, value) in GAS_CONSTANTS {
        c.insert(name.into(), U256::from(value));
    }

    for (name, value) in REFUND_CONSTANTS {
        c.insert(name.into(), U256::from(value));
    }

    for (name, value) in PRECOMPILES {
        c.insert(name.into(), U256::from(value));
    }

    for (name, value) in PRECOMPILES_GAS {
        c.insert(name.into(), U256::from(value));
    }

    for (name, value) in CODE_SIZE_LIMIT {
        c.insert(name.into(), U256::from(value));
    }

    for (name, value) in SNARKV_POINTERS {
        c.insert(name.into(), U256::from(value));
    }

    c.insert(MAX_NONCE.0.into(), U256::from(MAX_NONCE.1));
    c.insert(CALL_STACK_LIMIT.0.into(), U256::from(CALL_STACK_LIMIT.1));
    c.insert(
        cancun_constants::BEACON_ROOTS_CONTRACT_STATE_KEY.0.into(),
        U256::from_big_endian(&cancun_constants::BEACON_ROOTS_CONTRACT_STATE_KEY.1),
    );
    c.insert(
        cancun_constants::HISTORY_BUFFER_LENGTH.0.into(),
        cancun_constants::HISTORY_BUFFER_LENGTH.1.into(),
    );

    c.insert(
        global_exit_root::GLOBAL_EXIT_ROOT_MANAGER_L2_STATE_KEY
            .0
            .into(),
        U256::from_big_endian(&global_exit_root::GLOBAL_EXIT_ROOT_MANAGER_L2_STATE_KEY.1),
    );
    c.insert(
        global_exit_root::GLOBAL_EXIT_ROOT_STORAGE_POS.0.into(),
        U256::from(global_exit_root::GLOBAL_EXIT_ROOT_STORAGE_POS.1),
    );

    for segment in Segment::all() {
        c.insert(segment.var_name().into(), (segment as usize).into());
    }
    for txn_field in NormalizedTxnField::all() {
        // These offsets are already scaled by their respective segment.
        c.insert(txn_field.var_name().into(), (txn_field as usize).into());
    }
    for txn_field in GlobalMetadata::all() {
        // These offsets are already scaled by their respective segment.
        c.insert(txn_field.var_name().into(), (txn_field as usize).into());
    }
    for txn_field in ContextMetadata::all() {
        // These offsets are already scaled by their respective segment.
        c.insert(txn_field.var_name().into(), (txn_field as usize).into());
    }
    for trie_type in PartialTrieType::all() {
        c.insert(trie_type.var_name().into(), (trie_type as u32).into());
    }
    for entry in JournalEntry::all() {
        c.insert(entry.var_name().into(), (entry as u32).into());
    }
    c.insert(
        "INVALID_OPCODES_USER".into(),
        exc_bitfields::INVALID_OPCODES_USER,
    );
    c.insert(
        "STACK_LENGTH_INCREASING_OPCODES_USER".into(),
        exc_bitfields::STACK_LENGTH_INCREASING_OPCODES_USER,
    );
    c
}

const MISC_CONSTANTS: [(&str, [u8; 32]); 5] = [
    // Base for limbs used in bignum arithmetic.
    (
        "BIGNUM_LIMB_BASE",
        hex!("0000000000000000000000000000000100000000000000000000000000000000"),
    ),
    // Address where the empty node encoding is stored.
    // It is at the offset 0 within SEGMENT_RLP_RAW.
    // *Note*: Changing this will break some tests.
    (
        "ENCODED_EMPTY_NODE_ADDR",
        hex!("0000000000000000000000000000000000000000000000000000000b00000000"),
    ),
    // 0x10000 = 2^16 bytes, much larger than any RLP blob the EVM could possibly create.
    (
        "MAX_RLP_BLOB_SIZE",
        hex!("0000000000000000000000000000000000000000000000000000000000010000"),
    ),
    // Address where the txn RLP encoding starts.
    // It is the offset 1 within SEGMENT_RLP_RAW.
    // *Note*: Changing this will break some tests.
    (
        "INITIAL_TXN_RLP_ADDR",
        hex!("0000000000000000000000000000000000000000000000000000000b00000001"),
    ),
    // Scaled boolean value indicating that we are in kernel mode, to be used within `kexit_info`.
    // It is equal to 2^32.
    (
        "IS_KERNEL",
        hex!("0000000000000000000000000000000000000000000000000000000100000000"),
    ),
];

const HASH_CONSTANTS: [(&str, [u8; 32]); 2] = [
    // Hash of an empty string: keccak(b'').hex()
    (
        "EMPTY_STRING_HASH",
        hex!("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
    ),
    // Hash of an empty node: keccak(rlp.encode(b'')).hex()
    (
        "EMPTY_NODE_HASH",
        hex!("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
    ),
];

const EC_CONSTANTS: [(&str, [u8; 32]); 24] = [
    (
        "U256_MAX",
        hex!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    ),
    (
        "BN_BASE",
        hex!("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47"),
    ),
    (
        "BN_TWISTED_RE",
        hex!("2b149d40ceb8aaae81be18991be06ac3b5b4c5e559dbefa33267e6dc24a138e5"),
    ),
    (
        "BN_TWISTED_IM",
        hex!("009713b03af0fed4cd2cafadeed8fdf4a74fa084e52d1852e4a2bd0685c315d2"),
    ),
    (
        "BN_ENDO_X_COORD_RE",
        hex!("2fb347984f7911f74c0bec3cf559b143b78cc310c2c3330c99e39557176f553d"),
    ),
    (
        "BN_ENDO_X_COORD_IM",
        hex!("16c9e55061ebae204ba4cc8bd75a079432ae2a1d0b7c9dce1665d51c640fcba2"),
    ),
    (
        "BN_ENDO_Y_COORD_RE",
        hex!("063cf305489af5dcdc5ec698b6e2f9b9dbaae0eda9c95998dc54014671a0135a"),
    ),
    (
        "BN_ENDO_Y_COORD_IM",
        hex!("07c03cbcac41049a0704b5a7ec796f2b21807dc98fa25bd282d37f632623b0e3"),
    ),
    (
        "BN_SCALAR",
        hex!("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"),
    ),
    (
        "BN_GLV_BETA",
        hex!("000000000000000059e26bcea0d48bacd4f263f1acdb5c4f5763473177fffffe"),
    ),
    (
        "BN_GLV_S",
        hex!("0000000000000000b3c4d79d41a917585bfc41088d8daaa78b17ea66b99c90dd"),
    ),
    (
        "BN_GLV_MINUS_G1",
        hex!("000000000000000000000000000000024ccef014a773d2cf7a7bd9d4391eb18d"),
    ),
    (
        "BN_GLV_G2",
        hex!("000000000000000000000000000000000000000000000002d91d232ec7e0b3d7"),
    ),
    (
        "BN_GLV_B1",
        hex!("30644e72e131a029b85045b68181585cb8e665ff8b011694c1d039a872b0eed9"),
    ),
    (
        "BN_GLV_B2",
        hex!("00000000000000000000000000000000000000000000000089d3256894d213e3"),
    ),
    (
        "BN_BNEG_LOC",
        // This just needs to be large enough to not interfere with anything else in
        // SEGMENT_BN_TABLE_Q.
        hex!("0000000000000000000000000000000000000000000000000000000000001337"),
    ),
    (
        "SECP_BASE",
        hex!("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"),
    ),
    (
        "SECP_SCALAR",
        hex!("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
    ),
    (
        "SECP_GLV_BETA",
        hex!("7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee"),
    ),
    (
        "SECP_GLV_S",
        hex!("5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72"),
    ),
    (
        "SECP_GLV_MINUS_G1",
        hex!("00000000000000000000000000000000e4437ed6010e88286f547fa90abfe4c4"),
    ),
    (
        "SECP_GLV_G2",
        hex!("000000000000000000000000000000003086d221a7d46bcde86c90e49284eb15"),
    ),
    (
        "SECP_GLV_B1",
        hex!("fffffffffffffffffffffffffffffffdd66b5e10ae3a1813507ddee3c5765c7e"),
    ),
    (
        "SECP_GLV_B2",
        hex!("000000000000000000000000000000003086d221a7d46bcde86c90e49284eb15"),
    ),
];

const GAS_CONSTANTS: [(&str, u32); 38] = [
    ("GAS_ZERO", 0),
    ("GAS_JUMPDEST", 1),
    ("GAS_BASE", 2),
    ("GAS_VERYLOW", 3),
    ("GAS_LOW", 5),
    ("GAS_MID", 8),
    ("GAS_HIGH", 10),
    ("GAS_WARMACCESS", 100),
    ("GAS_ACCESSLISTADDRESS", 2_400),
    ("GAS_ACCESSLISTSTORAGE", 1_900),
    ("GAS_COLDACCOUNTACCESS", 2_600),
    ("GAS_COLDACCOUNTACCESS_MINUS_WARMACCESS", 2_500),
    ("GAS_COLDSLOAD", 2_100),
    ("GAS_COLDSLOAD_MINUS_WARMACCESS", 2_000),
    ("GAS_SSET", 20_000),
    ("GAS_SRESET", 2_900),
    ("GAS_SELFDESTRUCT", 5_000),
    ("GAS_CREATE", 32_000),
    ("GAS_CODEDEPOSIT", 200),
    ("GAS_CALLVALUE", 9_000),
    ("GAS_CALLSTIPEND", 2_300),
    ("GAS_NEWACCOUNT", 25_000),
    ("GAS_EXP", 10),
    ("GAS_EXPBYTE", 50),
    ("GAS_MEMORY", 3),
    ("GAS_TXCREATE", 32_000),
    ("GAS_TXDATAZERO", 4),
    ("GAS_TXDATANONZERO", 16),
    ("GAS_TRANSACTION", 21_000),
    ("GAS_LOG", 375),
    ("GAS_LOGDATA", 8),
    ("GAS_LOGTOPIC", 375),
    ("GAS_KECCAK256", 30),
    ("GAS_KECCAK256WORD", 6),
    ("GAS_COPY", 3),
    ("GAS_BLOCKHASH", 20),
    ("GAS_HASH_OPCODE", 3),
    ("GAS_PER_BLOB", 131_072),
];

const REFUND_CONSTANTS: [(&str, u16); 2] = [("REFUND_SCLEAR", 4_800), ("MAX_REFUND_QUOTIENT", 5)];

const PRECOMPILES: [(&str, u16); 10] = [
    ("ECREC", 1),
    ("SHA256", 2),
    ("RIP160", 3),
    ("ID", 4),
    ("EXPMOD", 5),
    ("BN_ADD", 6),
    ("BN_MUL", 7),
    ("SNARKV", 8),
    ("BLAKE2_F", 9),
    ("KZG_PEVAL", 10),
];

const PRECOMPILES_GAS: [(&str, u16); 14] = [
    ("ECREC_GAS", 3_000),
    ("SHA256_STATIC_GAS", 60),
    ("SHA256_DYNAMIC_GAS", 12),
    ("RIP160_STATIC_GAS", 600),
    ("RIP160_DYNAMIC_GAS", 120),
    ("ID_STATIC_GAS", 15),
    ("ID_DYNAMIC_GAS", 3),
    ("EXPMOD_MIN_GAS", 200),
    ("BN_ADD_GAS", 150),
    ("BN_MUL_GAS", 6_000),
    ("SNARKV_STATIC_GAS", 45_000),
    ("SNARKV_DYNAMIC_GAS", 34_000),
    ("BLAKE2_F__GAS", 1),
    ("KZG_PEVAL_GAS", 50_000),
];

const SNARKV_POINTERS: [(&str, u64); 2] = [("SNARKV_INP", 112), ("SNARKV_OUT", 100)];

const CODE_SIZE_LIMIT: [(&str, u64); 3] = [
    ("MAX_CODE_SIZE", 0x6000),
    ("MAX_INITCODE_SIZE", 0xc000),
    ("INITCODE_WORD_COST", 2),
];

const MAX_NONCE: (&str, u64) = ("MAX_NONCE", 0xffffffffffffffff);
const CALL_STACK_LIMIT: (&str, u64) = ("CALL_STACK_LIMIT", 1024);

/// Cancun-related constants
/// See <https://eips.ethereum.org/EIPS/eip-4788> and
/// <https://eips.ethereum.org/EIPS/eip-4844>.
pub mod cancun_constants {
    use super::*;

    pub const BLOB_BASE_FEE_UPDATE_FRACTION: U256 = U256([0x32f0ed, 0, 0, 0]);

    pub const MIN_BASE_FEE_PER_BLOB_GAS: U256 = U256::one();

    pub const KZG_VERSIONED_HASH: u8 = 0x01;

    pub const POINT_EVALUATION_PRECOMPILE_RETURN_VALUE: [[u8; 32]; 2] = [
        // U256(FIELD_ELEMENTS_PER_BLOB).to_be_bytes()
        hex!("0000000000000000000000000000000000000000000000000000000000001000"),
        // BLS_MODULUS.to_bytes32()
        hex!("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"),
    ];

    // Taken from <https://github.com/ethereum/c-kzg-4844/blob/main/src/trusted_setup.txt>.
    pub const G2_TRUSTED_SETUP_POINT: [[u8; 64]; 4] = [
        hex!("00000000000000000000000000000000185cbfee53492714734429b7b38608e23926c911cceceac9a36851477ba4c60b087041de621000edc98edada20c1def2"), // x_re
        hex!("0000000000000000000000000000000015bfd7dd8cdeb128843bc287230af38926187075cbfbefa81009a2ce615ac53d2914e5870cb452d2afaaab24f3499f72"), // x_im
        hex!("00000000000000000000000000000000014353bdb96b626dd7d5ee8599d1fca2131569490e28de18e82451a496a9c9794ce26d105941f383ee689bfbbb832a99"), // y_re
        hex!("000000000000000000000000000000001666c54b0a32529503432fcae0181b4bef79de09fc63671fda5ed1ba9bfa07899495346f3d7ac9cd23048ef30d0a154f"), // y_im
    ];

    pub const BEACON_ROOTS_CONTRACT_STATE_KEY: (&str, [u8; 20]) = (
        "BEACON_ROOTS_CONTRACT_STATE_KEY",
        hex!("000F3df6D732807Ef1319fB7B8bB8522d0Beac02"),
    );

    pub const HISTORY_BUFFER_LENGTH: (&str, u64) = ("HISTORY_BUFFER_LENGTH", 8191);

    pub const BEACON_ROOTS_CONTRACT_CODE: [u8; 97] = hex!("3373fffffffffffffffffffffffffffffffffffffffe14604d57602036146024575f5ffd5b5f35801560495762001fff810690815414603c575f5ffd5b62001fff01545f5260205ff35b5f5ffd5b62001fff42064281555f359062001fff015500");
    pub const BEACON_ROOTS_CONTRACT_CODE_HASH: [u8; 32] =
        hex!("f57acd40259872606d76197ef052f3d35588dadf919ee1f0e3cb9b62d3f4b02c");

    pub const BEACON_ROOTS_CONTRACT_ADDRESS_HASHED: [u8; 32] =
        hex!("37d65eaa92c6bc4c13a5ec45527f0c18ea8932588728769ec7aecfe6d9f32e42");

    pub const BEACON_ROOTS_ACCOUNT: AccountRlp = AccountRlp {
        nonce: U256::zero(),
        balance: U256::zero(),
        // Storage root for this account at genesis.
        storage_root: H256(hex!(
            "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
        )),
        code_hash: H256(BEACON_ROOTS_CONTRACT_CODE_HASH),
    };
}

pub mod global_exit_root {
    use super::*;

    /// Taken from https://github.com/0xPolygonHermez/cdk-erigon/blob/61f0b6912055c73f6879ea7e9b5bac22ea5fc85c/zk/utils/global_exit_root.go#L16.
    pub const GLOBAL_EXIT_ROOT_MANAGER_L2_STATE_KEY: (&str, [u8; 20]) = (
        "GLOBAL_EXIT_ROOT_MANAGER_L2_STATE_KEY",
        hex!("a40D5f56745a118D0906a34E69aeC8C0Db1cB8fA"),
    );
    /// Taken from https://github.com/0xPolygonHermez/cdk-erigon/blob/61f0b6912055c73f6879ea7e9b5bac22ea5fc85c/zk/utils/global_exit_root.go#L17.
    pub const GLOBAL_EXIT_ROOT_STORAGE_POS: (&str, u64) = ("GLOBAL_EXIT_ROOT_STORAGE_POS", 0);

    /// Taken from https://zkevm.polygonscan.com/address/0xa40D5f56745a118D0906a34E69aeC8C0Db1cB8fA#code.
    pub const GLOBAL_EXIT_ROOT_CONTRACT_CODE: [u8; 2112] = hex!("60806040526004361061004e5760003560e01c80633659cfe6146100655780634f1ef286146100855780635c60da1b146100985780638f283970146100c9578063f851a440146100e95761005d565b3661005d5761005b6100fe565b005b61005b6100fe565b34801561007157600080fd5b5061005b6100803660046106ca565b610118565b61005b6100933660046106e5565b61015f565b3480156100a457600080fd5b506100ad6101d0565b6040516001600160a01b03909116815260200160405180910390f35b3480156100d557600080fd5b5061005b6100e43660046106ca565b61020b565b3480156100f557600080fd5b506100ad610235565b610106610292565b610116610111610331565b61033b565b565b61012061035f565b6001600160a01b0316336001600160a01b031614156101575761015481604051806020016040528060008152506000610392565b50565b6101546100fe565b61016761035f565b6001600160a01b0316336001600160a01b031614156101c8576101c38383838080601f01602080910402602001604051908101604052809392919081815260200183838082843760009201919091525060019250610392915050565b505050565b6101c36100fe565b60006101da61035f565b6001600160a01b0316336001600160a01b03161415610200576101fb610331565b905090565b6102086100fe565b90565b61021361035f565b6001600160a01b0316336001600160a01b0316141561015757610154816103f1565b600061023f61035f565b6001600160a01b0316336001600160a01b03161415610200576101fb61035f565b606061028583836040518060600160405280602781526020016107e460279139610445565b9392505050565b3b151590565b61029a61035f565b6001600160a01b0316336001600160a01b031614156101165760405162461bcd60e51b815260206004820152604260248201527f5472616e73706172656e745570677261646561626c6550726f78793a2061646d60448201527f696e2063616e6e6f742066616c6c6261636b20746f2070726f78792074617267606482015261195d60f21b608482015260a4015b60405180910390fd5b60006101fb610519565b3660008037600080366000845af43d6000803e80801561035a573d6000f35b3d6000fd5b60007fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d61035b546001600160a01b0316919050565b61039b83610541565b6040516001600160a01b038416907fbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b90600090a26000825111806103dc5750805b156101c3576103eb8383610260565b50505050565b7f7e644d79422f17c01e4894b5f4f588d331ebfa28653d42ae832dc59e38c9798f61041a61035f565b604080516001600160a01b03928316815291841660208301520160405180910390a1610154816105e9565b6060833b6104a45760405162461bcd60e51b815260206004820152602660248201527f416464726573733a2064656c65676174652063616c6c20746f206e6f6e2d636f6044820152651b9d1c9858dd60d21b6064820152608401610328565b600080856001600160a01b0316856040516104bf9190610794565b600060405180830381855af49150503d80600081146104fa576040519150601f19603f3d011682016040523d82523d6000602084013e6104ff565b606091505b509150915061050f828286610675565b9695505050505050565b60007f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc610383565b803b6105a55760405162461bcd60e51b815260206004820152602d60248201527f455243313936373a206e657720696d706c656d656e746174696f6e206973206e60448201526c1bdd08184818dbdb9d1c9858dd609a1b6064820152608401610328565b807f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc5b80546001600160a01b0319166001600160a01b039290921691909117905550565b6001600160a01b03811661064e5760405162461bcd60e51b815260206004820152602660248201527f455243313936373a206e65772061646d696e20697320746865207a65726f206160448201526564647265737360d01b6064820152608401610328565b807fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d61036105c8565b60608315610684575081610285565b8251156106945782518084602001fd5b8160405162461bcd60e51b815260040161032891906107b0565b80356001600160a01b03811681146106c557600080fd5b919050565b6000602082840312156106dc57600080fd5b610285826106ae565b6000806000604084860312156106fa57600080fd5b610703846106ae565b9250602084013567ffffffffffffffff8082111561072057600080fd5b818601915086601f83011261073457600080fd5b81358181111561074357600080fd5b87602082850101111561075557600080fd5b6020830194508093505050509250925092565b60005b8381101561078357818101518382015260200161076b565b838111156103eb5750506000910152565b600082516107a6818460208701610768565b9190910192915050565b60208152600082518060208401526107cf816040850160208701610768565b601f01601f1916919091016040019291505056fe416464726573733a206c6f772d6c6576656c2064656c65676174652063616c6c206661696c6564a26469706673582212204675187caf3a43285d9a2c1844a981e977bd52a85ff073e7fc649f73847d70a464736f6c63430008090033");
    pub const GLOBAL_EXIT_ROOT_CONTRACT_CODE_HASH: [u8; 32] =
        hex!("6bec2bf64f7e824109f6ed55f77dd7665801d6195e461666ad6a5342a9f6daf5");
    pub const GLOBAL_EXIT_ROOT_ADDRESS_HASHED: [u8; 32] =
        hex!("1d5e9c22b4b1a781d0ef63e9c1293c2a45fee966809019aa9804b5e7148b0ca9");

    pub const GLOBAL_EXIT_ROOT_ACCOUNT: AccountRlp = AccountRlp {
        nonce: U256::zero(),
        balance: U256::zero(),
        // Empty storage root
        storage_root: H256(hex!(
            "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
        )),
        code_hash: H256(GLOBAL_EXIT_ROOT_CONTRACT_CODE_HASH),
    };
}
