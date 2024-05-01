use evm_arithmetization::generation::mpt::AccountRlp;
use mpt_trie::partial_trie::PartialTrie;

use super::{
    compact_prestate_processing::{
        process_compact_prestate, process_compact_prestate_debug, CompactParsingResult,
        ProcessedCompactOutput,
    },
    compact_to_partial_trie::StateTrieExtractionOutput,
};
use crate::{
    trace_protocol::TrieCompact,
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

type ProcessCompactPrestateFn = fn(TrieCompact) -> CompactParsingResult<ProcessedCompactOutput>;

pub(crate) struct TestProtocolInputAndRoot {
    pub(crate) byte_str: &'static str,
    pub(crate) root_str: &'static str,
}

impl TestProtocolInputAndRoot {
    #[allow(dead_code)]
    pub(crate) fn parse_and_check_hash_matches(self) {
        self.parse_and_check_hash_matches_common(process_compact_prestate);
    }

    pub(crate) fn parse_and_check_hash_matches_with_debug(self) {
        self.parse_and_check_hash_matches_common(process_compact_prestate_debug);
    }

    fn parse_and_check_hash_matches_common(
        self,
        process_compact_prestate_f: ProcessCompactPrestateFn,
    ) {
        let protocol_bytes = hex::decode(self.byte_str).unwrap();
        let expected_hash = TrieRootHash::from_slice(&hex::decode(self.root_str).unwrap());

        let out = match process_compact_prestate_f(TrieCompact(protocol_bytes)) {
            Ok(x) => x,
            Err(err) => panic!("{}", err.to_string()),
        };
        let trie_hash = out.witness_out.state_trie.hash();

        print_value_and_hash_nodes_of_trie(&out.witness_out.state_trie);

        for (hashed_addr, s_trie) in out.witness_out.storage_tries.iter() {
            print_value_and_hash_nodes_of_storage_trie(hashed_addr, s_trie);
        }

        assert!(out.header.version_is_compatible(1));
        assert_eq!(trie_hash, expected_hash);

        Self::assert_non_all_storage_roots_exist_in_storage_trie_map(&out.witness_out);
    }

    fn assert_non_all_storage_roots_exist_in_storage_trie_map(out: &StateTrieExtractionOutput) {
        let non_empty_account_s_roots = out
            .state_trie
            .items()
            .filter_map(|(addr, data)| {
                data.as_val().map(|data| {
                    (
                        HashedAccountAddr::from_slice(&addr.bytes_be()),
                        rlp::decode::<AccountRlp>(data).unwrap().storage_root,
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
