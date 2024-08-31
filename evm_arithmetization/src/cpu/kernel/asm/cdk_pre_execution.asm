/// CDK-Erigon pre-block execution logic.
/// Reference implementation: `cdk-erigon/core/state/intra_block_state_zkevm.go`.
/// This currently supports the Etrog upgrade.

// TODO(Robin): Remove code template
// func (sdb *IntraBlockState) SyncerPreExecuteStateSet(
// 	chainConfig *chain.Config,
// 	blockNumber uint64,
// 	blockTimestamp uint64,
// 	prevBlockHash, blockGer, l1BlockHash *libcommon.Hash,
// 	gerUpdates *[]dstypes.GerUpdate,
// 	reUsedL1InfoTreeIndex bool,
// ) {
// 	if !sdb.Exist(ADDRESS_SCALABLE_L2) {
// 		// create account if not exists
// 		sdb.CreateAccount(ADDRESS_SCALABLE_L2, true)
// 	}

// 	//save block number
// 	sdb.scalableSetBlockNum(blockNumber)
// 	emptyHash := libcommon.Hash{}

// 	//ETROG
// 	if chainConfig.IsForkID7Etrog(blockNumber) {
// 		currentTimestamp := sdb.ScalableGetTimestamp()
// 		if blockTimestamp > currentTimestamp {
// 			sdb.ScalableSetTimestamp(blockTimestamp)
// 		}

// 		//save prev block hash
// 		sdb.scalableSetBlockHash(blockNumber-1, prevBlockHash)

// 		//save ger with l1blockhash - but only in the case that the l1 info tree index hasn't been
// 		// re-used.  If it has been re-used we never write this to the contract storage
// 		if !reUsedL1InfoTreeIndex && blockGer != nil && *blockGer != emptyHash {
// 			sdb.WriteGerManagerL1BlockHash(*blockGer, *l1BlockHash)
// 		}
// 	}
// }


/// Pre-stack: (empty)
/// Post-stack: (empty)
global pre_block_execution:
    // stack: (empty)
    PUSH start_txn
    // stack: retdest
    PUSH @ADDRESS_SCALABLE_L2_STATE_KEY
    %is_non_existent
    %jumpi(create_scalable_l2_account)

global update_scalable_block_number:
    // stack: retdest
    %blocknumber
    PUSH @LAST_BLOCK_STORAGE_POS
    // stack: last_block_slot, block_number, retdest
    %write_scalable_storage
    // stack: retdest

    // Check timestamp
    PUSH @ADDRESS_SCALABLE_L2_STATE_KEY
    PUSH @TIMESTAMP_STORAGE_POS
    %read_storage_linked_list_w_state_key
    // stack: old_timestamp, retdest
    %timestamp
    GT %jumpi(update_scalable_timestamp)

global update_scalable_prev_block_root_hash:
    // stack: retdest
    %mload_global_metadata(@GLOBAL_METADATA_STATE_TRIE_DIGEST_BEFORE)
    // stack: prev_block_root, retdest
    PUSH 1 %block_number SUB
    // stack: block_number - 1, prev_block_root, retdest
    %write_scalable_storage
    // stack: retdest

global update_scalable_l1_blockhash:
    // stack: retdest
    // TODO(RObin): FINISH
    JUMP

global update_scalable_timestamp:
    %timestamp
    PUSH @TIMESTAMP_STORAGE_POS
    // stack: timestamp_slot, timestamp, retdest
    %write_scalable_storage
    %jump(update_scalable_prev_block_root_hash)

global create_scalable_l2_account:
    // stack: (empty)
    PUSH update_scalable_block_number
    // stack: retdest
    %get_trie_data_size // pointer to new account we're about to create
    // stack: new_account_ptr, retdest
    PUSH 0 %append_to_trie_data // nonce
    PUSH 0 %append_to_trie_data // balance
    PUSH 0 %append_to_trie_data // storage root pointer
    PUSH @EMPTY_STRING_HASH %append_to_trie_data // code hash
    // stack: new_account_ptr, retdest
    PUSH @L2ADDRESS_SCALABLE_L2_STATE_KEY
    // stack: key, new_account_ptr, retdest
    %jump(mpt_insert_state_trie)

%macro write_scalable_storage
    // stack: slot, value
    %slot_to_storage_key
    // stack: storage_key, value
    PUSH @ADDRESS_SCALABLE_L2_STATE_KEY
    // stack: state_key, storage_key, value
    %insert_slot_with_value_from_keys
    // stack: (empty)
%endmacro
