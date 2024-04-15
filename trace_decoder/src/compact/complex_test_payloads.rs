use mpt_trie::partial_trie::PartialTrie;
use plonky2::plonk::config::GenericHashOut;

use super::{
    compact_mpt_processing::{
        process_compact_mpt_prestate, process_compact_mpt_prestate_debug, ProcessedCompactOutput,
    },
    compact_processing_common::{CompactParsingResult, Header},
    compact_smt_processing::process_compact_smt_prestate_debug,
    compact_to_mpt_trie::StateTrieExtractionOutput,
    compact_to_smt_trie::SmtStateTrieExtractionOutput,
};
use crate::{
    aliased_crate_types::MptAccountRlp,
    trace_protocol::{MptTrieCompact, SingleSmtPreImage},
    types::{HashedAccountAddr, TrieRootHash, EMPTY_TRIE_HASH},
    utils::{print_value_and_hash_nodes_of_storage_trie, print_value_and_hash_nodes_of_trie},
};

pub(crate) const TEST_PAYLOAD_1: TestProtocolInputAndRoot = TestProtocolInputAndRoot { byte_str: "01055821033601462093b5945d1676df093446790fd31b20e7b12a2e8e5e09d068109616b0084a021e19e0c9bab240000005582103468288056310c82aa4c01a7e12a10f8111a0560e72b700555479031b86c357d0084101031a697e814758281972fcd13bc9707dbcd2f195986b05463d7b78426508445a0405582103b70e80538acdabd6137353b0f9d8d149f4dba91e8be2e7946e409bfdbe685b900841010558210389802d6ed1a28b049e9d4fe5334c5902fd9bc00c42821c82f82ee2da10be90800841010558200256274a27dd7524955417c11ecd917251cc7c4c8310f4c7e4bd3c304d3d9a79084a021e19e0c9bab2400000055820023ab0970b73895b8c9959bae685c3a19f45eb5ad89d42b52a340ec4ac204d190841010219102005582103876da518a393dbd067dc72abfa08d475ed6447fca96d92ec3f9e7eba503ca6100841010558210352688a8f926c816ca1e079067caba944f158e764817b83fc43594370ca9cf62008410105582103690b239ba3aaf993e443ae14aeffc44cf8d9931a79baed9fa141d0e4506e131008410102196573", root_str: "6a0673c691edfa4c4528323986bb43c579316f436ff6f8b4ac70854bbd95340b" };

pub(crate) const TEST_PAYLOAD_2: TestProtocolInputAndRoot = TestProtocolInputAndRoot { byte_str: "01055821033601462093b5945d1676df093446790fd31b20e7b12a2e8e5e09d068109616b0084a021e19e0c9bab240000005582103468288056310c82aa4c01a7e12a10f8111a0560e72b700555479031b86c357d0084101031a697e814758281972fcd13bc9707dbcd2f195986b05463d7b78426508445a0405582103b70e80538acdabd6137353b0f9d8d149f4dba91e8be2e7946e409bfdbe685b900841010558210389802d6ed1a28b049e9d4fe5334c5902fd9bc00c42821c82f82ee2da10be90800841010558200256274a27dd7524955417c11ecd917251cc7c4c8310f4c7e4bd3c304d3d9a790c014a021e0c000250c782fa00055820023ab0970b73895b8c9959bae685c3a19f45eb5ad89d42b52a340ec4ac204d1908410102191020055820021eec2b84f0ba344fd4b4d2f022469febe7a772c4789acfc119eb558ab1da3d08480de0b6b3a76400000558200276da518a393dbd067dc72abfa08d475ed6447fca96d92ec3f9e7eba503ca61084101021901200558210352688a8f926c816ca1e079067caba944f158e764817b83fc43594370ca9cf62008410105582103690b239ba3aaf993e443ae14aeffc44cf8d9931a79baed9fa141d0e4506e131008410102196573", root_str: "e779761e7f0cf4bb2b5e5a2ebac65406d3a7516d46798040803488825a01c19c" };

pub(crate) const TEST_PAYLOAD_3: TestProtocolInputAndRoot = TestProtocolInputAndRoot { byte_str: "01055821033601462093b5945d1676df093446790fd31b20e7b12a2e8e5e09d068109616b0084a021e19e0c9bab240000005582103468288056310c82aa4c01a7e12a10f8111a0560e72b700555479031b86c357d0084101031a697e814758281972fcd13bc9707dbcd2f195986b05463d7b78426508445a0405582103b70e80538acdabd6137353b0f9d8d149f4dba91e8be2e7946e409bfdbe685b900841010558210389802d6ed1a28b049e9d4fe5334c5902fd9bc00c42821c82f82ee2da10be90800841010558200256274a27dd7524955417c11ecd917251cc7c4c8310f4c7e4bd3c304d3d9a790c024a021e0a9cae36fa8e4788055820023ab0970b73895b8c9959bae685c3a19f45eb5ad89d42b52a340ec4ac204d1908410102191020055820021eec2b84f0ba344fd4b4d2f022469febe7a772c4789acfc119eb558ab1da3d08480f43fc2c04ee00000558200276da518a393dbd067dc72abfa08d475ed6447fca96d92ec3f9e7eba503ca61084101021901200558210352688a8f926c816ca1e079067caba944f158e764817b83fc43594370ca9cf62008410105582103690b239ba3aaf993e443ae14aeffc44cf8d9931a79baed9fa141d0e4506e131008410102196573", root_str: "6978d65a3f2fc887408cc28dbb796836ff991af73c21ea74d03a11f6cdeb119c" };

pub(crate) const TEST_PAYLOAD_4: TestProtocolInputAndRoot = TestProtocolInputAndRoot { byte_str: "0103a6885b3731702da62e8e4a8f584ac46a7f6822f4e2ba50fba902f67b1588d23b005821028015657e298d35290e69628be03d91f74d613caf3afdbe09138cfa415efe2f5044deadbeef0558210218b289936a0874cccee65712c88cdaa0a305b004d3fda2942b2b2dc54f14f6110b443b9aca0004", root_str: "69a5a7a8f99161a35e8b64975d8c6af10db4eee7bd956418839d8ff763aaf00c" };

pub(crate) const TEST_PAYLOAD_5: TestProtocolInputAndRoot = TestProtocolInputAndRoot {
    byte_str: include_str!("large_test_payloads/test_payload_5.txt"),
    root_str: "2b5a703bdec53099c42d7575f8cd6db85d6f2226a04e98e966fcaef87868869b",
};

pub(crate) const TEST_PAYLOAD_6: TestProtocolInputAndRoot = TestProtocolInputAndRoot {
    byte_str: include_str!("large_test_payloads/test_payload_6.txt"),
    root_str: "135a0c66146c60d7f78049b3a3486aae3e155015db041a4650966e001f9ba301",
};

pub(crate) const TEST_PAYLOAD_7: TestProtocolInputAndRoot = TestProtocolInputAndRoot { byte_str: "01020302030203020102030203070354dbc6981a11fc2b000c635bfa7c47676b25c87d395820dae2aa361dfd1ca020a396615627d436107c35eff9fe7738a3512819782d706a58205f58e3a2316349923ce3780f8d587db2d72378aed66a8261c916544fa6846ca5030fe25b763f0806d8d0c4207d7d75d6ffc29aa68d453a706b6e48170f973b97180201031f4a9968d4864c15adc3ed2e8e5f16c3c0e06b4ffce615d7625e67a6f83324d80202020302030203038ebb1bd567318fff875f6b3754e347e153752094ab0426cfeac776e7ec9a9366070154ff6250d0e86a2465b0c1bf8e36409503d6a269634108034696e31d313fedc21d6cdb888864e901c34b49d1058639ca8c9924ce3f14d86a0377d0a35ad9d26ef9d4f8f4d95c4329218a5ab2f5495f245f3e844346501a861b0203020203ff2d60ea64b3ddc8a790ad37a37fdf985f6fff41e7eee8ed5aa92c2ab6263a78038718e1addf547b6ca1f97ad53186d20fec6a9a278246fed00954ffd91d6511670203020302030203070354a40d5f56745a118d0906a34e69aec8c0db1cb8fa5820360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc54282a631d9f3ef04bf1a44b4c9e8bdc8eb278917f038c9b7ef30c8d90ec8dcafe64f276c94d623dc061b668452db8c7df3f7a136435039b48a712bdd5b6ec945aa92cf29799236a2dded1017ef86f7e155a5464b0652d0202020303f28082b83a8d011059131af54610e945d3e95f438a7cbf80eaf1598f146536af02030202020103967e00fc69f5806b6f08105360091bd37c3a9ecfbda8d3137b773cc2d31f468902010201032d9df4b0208bcd6c9719c3b30b24f60012dabf83f3b55919d5a6456dfe22af5a0203020307035485ceb41028b1a5ed2b88e395145344837308b2515820000000000000000000000000000000000000000000000000000000000000000054dbc6981a11fc2b000c635bfa7c47676b25c87d390203020303f1266fd841ff5f3c27b8886275487d980e22c0b71ec6db7640c89b1049a68157070054ff6250d0e86a2465b0c1bf8e36409503d6a269634a152d02c7e14af680000003c8754745358d02c995f88cb07c6a9658e3c26c9b0df8273413b01f55ce43a16f0203031205a50bb9fadfd3aa680628a016a4be02c8e9964aa71f42db945e63cd3ca9340203020302030388055d5c158bb8922d299b7dccc16f3e0997d00a72db069cb8aadf18d6f55d1c070354dbc6981a11fc2b000c635bfa7c47676b25c87d3958209b3efc411c5f69533db363941e091f6f3af8b7e306525413577a56d27e5dbe73410103fcf29668a8ef83e5113c29d62d7fd09b9712da1a77bcd6e493303baae3812da80358243a7f4eb19a404936634ffb321c7f6a5320d02cb17bc6839f97c412b170e9", root_str: "a9ea727d6e65f97e86125a1afdd11208091c81027b31740bdc6cc38f903fee49" };

// TODO - Wrong root_str
pub(crate) const TEST_PAYLOAD_8: TestProtocolInputAndRoot = TestProtocolInputAndRoot {
    byte_str: include_str!("large_test_payloads/test_payload_8.txt"),
    root_str: "e3183936f83466ac3a7c4a0c58bcc62eee4a0a9edb0cbb8bb2ecc3094940f389",
};

// TODO - Wrong root_str
pub(crate) const TEST_PAYLOAD_9: TestProtocolInputAndRoot = TestProtocolInputAndRoot {
    byte_str: include_str!("large_test_payloads/test_payload_9.txt"),
    root_str: "355baf018ce42aae0df4605ff6274da1c2cd650bee756412dd12e60667794049",
};

// TODO - Wrong root_str
pub(crate) const TEST_PAYLOAD_10: TestProtocolInputAndRoot = TestProtocolInputAndRoot {
    byte_str: include_str!("large_test_payloads/test_payload_10.txt"),
    root_str: "006c7f763bab6c91bbd785231a463460e3db3956b02f2c3a0277a37556cc98c2",
};

pub(crate) const TEST_PAYLOAD_11: TestProtocolInputAndRoot = TestProtocolInputAndRoot { byte_str: "01020302030203020102030203070354dbc6981a11fc2b000c635bfa7c47676b25c87d395820dae2aa361dfd1ca020a396615627d436107c35eff9fe7738a3512819782d706a58205f58e3a2316349923ce3780f8d587db2d72378aed66a8261c916544fa6846ca5030fe25b763f0806d8d0c4207d7d75d6ffc29aa68d453a706b6e48170f973b97180201031f4a9968d4864c15adc3ed2e8e5f16c3c0e06b4ffce615d7625e67a6f83324d80202020302030203038ebb1bd567318fff875f6b3754e347e153752094ab0426cfeac776e7ec9a9366070154ff6250d0e86a2465b0c1bf8e36409503d6a269634109034696e31d313fedc21d6cdb888864e901c34b49d1058639ca8c9924ce3f14d86a0377d0a35ad9d26ef9d4f8f4d95c4329218a5ab2f5495f245f3e844346501a861b02030203032828d6f59c9f459eec72c8f7c3ca2a917e6ae3988894349292d3bd2edafcfcae020307045436810012486fc134d0679c07f85fe5ba5a087d8c420b9b034c43414146a58f344fc6d9e3967a4ca5bfb730f34d307cf52da1461aa5d1788d03ad4fbb1d9fb1ec2583874550a15c51a02fd06b31baad4edb9639554bd292699e020302030203036b2039084ec9a330a81c830bf10f152b56f3c5f1ce348917c83a61e230eb850702020203036ee1753e8040533b3449030940a41808ed85eb1c748a8a02e45c7419abfb8fd907015485ceb41028b1a5ed2b88e395145344837308b25141010202020303f28082b83a8d011059131af54610e945d3e95f438a7cbf80eaf1598f146536af020303237e44ef2f2c8075464a8aabaa0cb261d193d35130bd16e3ee034603b0872af002010201032d9df4b0208bcd6c9719c3b30b24f60012dabf83f3b55919d5a6456dfe22af5a02030203020202010203070054761d53b47334bee6612c0bd1467fb881435375b24563bea13c0003bfcbe8a808ca48c9bae028fb29e84b8abd48d7bbad74af727177d3eb8543b76b0203020303f1266fd841ff5f3c27b8886275487d980e22c0b71ec6db7640c89b1049a68157070054ff6250d0e86a2465b0c1bf8e36409503d6a269634a152d02c63909635cef8003c8754745358d02c995f88cb07c6a9658e3c26c9b0df8273413b01f55ce43a16f020302030203032d6be6ae60ad356076d958b6f0fff54ff2b9505b28f894f0ab07cc50c22a0a38070354a40d5f56745a118d0906a34e69aec8c0db1cb8fa5820b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d61035485ceb41028b1a5ed2b88e395145344837308b25103b9fb55dd268ecf19e428082767b8c791e442468983b12e10f77408ad3b65687f0203020302030388055d5c158bb8922d299b7dccc16f3e0997d00a72db069cb8aadf18d6f55d1c070354dbc6981a11fc2b000c635bfa7c47676b25c87d3958209b3efc411c5f69533db363941e091f6f3af8b7e306525413577a56d27e5dbe73410103fcf29668a8ef83e5113c29d62d7fd09b9712da1a77bcd6e493303baae3812da80358243a7f4eb19a404936634ffb321c7f6a5320d02cb17bc6839f97c412b170e9", root_str: "407fdb0c2f6538ebd624eae9cdaeb5eaef439eee9b9bd1392f97548a5257bdf4" };

pub(crate) const TEST_PAYLOAD_12: TestProtocolInputAndRoot = TestProtocolInputAndRoot { byte_str: "01020302030203020102030203070354dbc6981a11fc2b000c635bfa7c47676b25c87d395820dae2aa361dfd1ca020a396615627d436107c35eff9fe7738a3512819782d706a58205f58e3a2316349923ce3780f8d587db2d72378aed66a8261c916544fa6846ca5030fe25b763f0806d8d0c4207d7d75d6ffc29aa68d453a706b6e48170f973b97180201031f4a9968d4864c15adc3ed2e8e5f16c3c0e06b4ffce615d7625e67a6f83324d80202020302030203038ebb1bd567318fff875f6b3754e347e153752094ab0426cfeac776e7ec9a9366070154ff6250d0e86a2465b0c1bf8e36409503d6a26963410a02020203070154282a631d9f3ef04bf1a44b4c9e8bdc8eb278917f410103882de6be02fcb48c7ffd30c088d4d2b807b1143a9808e2ad33cc95b8762eb6a70377d0a35ad9d26ef9d4f8f4d95c4329218a5ab2f5495f245f3e844346501a861b02030357406ddb685037d5396e303c8a2df992502d6f83178d37ca8034e8b6614aa7c302030203039641b456dd9f9ca66e61252f9b33317325b91388d09f02936501cecc5bb467e8020203e18a6a605563197aebf4c5e36eed59de41bd99fba067c32d481dff5ab08a9eb2036aa3f4c85ce515bce80d52c16aaa4d9618c9b04515c57fda60acb760a86d8d160203020303b528a10857ba78165dfd4e0313988a841cfd9963cfdb58a6849c496317217e350202020303f28082b83a8d011059131af54610e945d3e95f438a7cbf80eaf1598f146536af020303c2d1dc61ffb7c8a7c627a7a20e81e2f199d50d817e8c0235b90fdc7caf4cba0e02010201032d9df4b0208bcd6c9719c3b30b24f60012dabf83f3b55919d5a6456dfe22af5a02030203020202010203070054761d53b47334bee6612c0bd1467fb881435375b245c77d42780003bfcbe8a808ca48c9bae028fb29e84b8abd48d7bbad74af727177d3eb8543b76b0203020303e713c2f5338e75eb386263cf44ee116326790e2869196ae623a1befaa4907c9b070054ff6250d0e86a2465b0c1bf8e36409503d6a269634a152d02c490c7d039df0003c8754745358d02c995f88cb07c6a9658e3c26c9b0df8273413b01f55ce43a16f0203031205a50bb9fadfd3aa680628a016a4be02c8e9964aa71f42db945e63cd3ca9340203020302030388055d5c158bb8922d299b7dccc16f3e0997d00a72db069cb8aadf18d6f55d1c070354dbc6981a11fc2b000c635bfa7c47676b25c87d3958209b3efc411c5f69533db363941e091f6f3af8b7e306525413577a56d27e5dbe73410103fcf29668a8ef83e5113c29d62d7fd09b9712da1a77bcd6e493303baae3812da8070154528e26b25a34a4a5d0dbda1d57d318153d2ed5824101", root_str: "4aad1c5d427ffb13aa6a438c4013cb2cf0d6dcf9484977f631c021337983c5eb" };

type ProcessMptCompactPrestateFn =
    ProcessedCompactPrestateFn<MptTrieCompact, StateTrieExtractionOutput>;

type ProcessSmtCompactPrestateFn =
    ProcessedCompactPrestateFn<SingleSmtPreImage, SmtStateTrieExtractionOutput>;

type ProcessedCompactPrestateFn<T, U> = fn(T) -> CompactParsingResult<ProcessedCompactOutput<U>>;

pub(crate) struct TestProtocolInputAndRoot {
    pub(crate) byte_str: &'static str,
    pub(crate) root_str: &'static str,
}

impl TestProtocolInputAndRoot {
    pub(crate) fn parse_and_check_hash_matches(self) {
        self.parse_and_check_mpt_trie(process_compact_mpt_prestate);
    }

    pub(crate) fn parse_and_check_hash_matches_with_debug(self) {
        self.parse_and_check_mpt_trie(process_compact_mpt_prestate_debug);
    }

    pub(crate) fn parse_and_check_hash_matches_with_debug_smt(self) {
        self.parse_and_check_smt_trie(process_compact_smt_prestate_debug)
    }

    fn parse_and_check_mpt_trie(self, process_compact_prestate_f: ProcessMptCompactPrestateFn) {
        let protocol_bytes = hex::decode(self.byte_str).unwrap();

        let out = match process_compact_prestate_f(MptTrieCompact(protocol_bytes)) {
            Ok(x) => x,
            Err(err) => panic!("{}", err.to_string()),
        };

        print_value_and_hash_nodes_of_trie(&out.witness_out.state_trie);

        for (hashed_addr, s_trie) in out.witness_out.storage_tries.iter() {
            print_value_and_hash_nodes_of_storage_trie(hashed_addr, s_trie);
        }

        let hash = out.witness_out.state_trie.hash();
        self.header_and_hash_checks(hash, out.header);
        Self::assert_non_all_storage_roots_exist_in_storage_trie_map(&out.witness_out);
    }

    fn parse_and_check_smt_trie(self, process_compact_prestate_f: ProcessSmtCompactPrestateFn) {
        let protocol_bytes = hex::decode(self.byte_str).unwrap();

        let out = process_compact_prestate_f(SingleSmtPreImage(protocol_bytes))
            .unwrap_or_else(|err| panic!("{}", err));
        let hash = TrieRootHash::from_slice(&out.witness_out.state_smt_trie.root.to_bytes());

        self.header_and_hash_checks(hash, out.header);
    }

    fn header_and_hash_checks(self, calculated_hash: TrieRootHash, header: Header) {
        let expected_hash = TrieRootHash::from_slice(&hex::decode(self.root_str).unwrap());

        assert!(header.version_is_compatible(1));
        assert_eq!(calculated_hash, expected_hash);
    }

    fn assert_non_all_storage_roots_exist_in_storage_trie_map(out: &StateTrieExtractionOutput) {
        let non_empty_account_s_roots = out
            .state_trie
            .items()
            .filter_map(|(addr, data)| {
                data.as_val().map(|data| {
                    (
                        HashedAccountAddr::from_slice(&addr.bytes_be()),
                        rlp::decode::<MptAccountRlp>(data).unwrap().storage_root,
                    )
                })
            })
            .filter(|(_, s_root)| *s_root != EMPTY_TRIE_HASH)
            .map(|(addr, _)| addr);

        for account_with_non_empty_root in non_empty_account_s_roots {
            assert!(out.storage_tries.contains_key(&account_with_non_empty_root));
        }
    }
}
