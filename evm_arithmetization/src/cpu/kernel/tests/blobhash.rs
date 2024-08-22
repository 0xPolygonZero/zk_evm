use anyhow::Result;
use ethereum_types::{H256, U256};
use plonky2::field::goldilocks_field::GoldilocksField as F;
use rand::{thread_rng, Rng};

use crate::cpu::kernel::aggregator::KERNEL;
use crate::cpu::kernel::constants::context_metadata::ContextMetadata::GasLimit;
use crate::cpu::kernel::constants::global_metadata::GlobalMetadata;
use crate::cpu::kernel::interpreter::Interpreter;
use crate::memory::segments::Segment;
use crate::witness::memory::MemoryContextState;

#[test]
fn test_valid_blobhash() -> Result<()> {
    let blobhash_label = KERNEL.global_labels["sys_blobhash"];
    let retdest = (0xDEADBEEFu64 + (1 << 32)).into(); // kexit_info

    let versioned_hashes: Vec<U256> = vec![U256::from_big_endian(&thread_rng().gen::<H256>().0); 5];
    let index = 3;
    let target_hash = versioned_hashes[index];

    let mut interpreter: Interpreter<F> = Interpreter::new(blobhash_label, vec![], None);
    interpreter
        .generation_state
        .memory
        .contexts
        .push(MemoryContextState::default());
    interpreter.set_context(1);
    interpreter.set_memory_segment(Segment::TxnBlobVersionedHashes, versioned_hashes);
    interpreter.set_global_metadata_field(GlobalMetadata::BlobVersionedHashesLen, 5.into());

    interpreter.set_context_metadata_field(1, GasLimit, U256::from(1000000000000u64));

    interpreter
        .push(index.into())
        .expect("The stack should not overflow"); // target hash index
    interpreter
        .push(retdest)
        .expect("The stack should not overflow"); // kexit_info

    interpreter.run()?;

    let result = interpreter.stack();
    assert_eq!(interpreter.stack_len(), 1);
    assert_eq!(
        result[0], target_hash,
        "Resulting blobhash {:?} different from expected hash {:?}",
        result[0], target_hash
    );

    Ok(())
}

#[test]
fn test_invalid_blobhash() -> Result<()> {
    let blobhash_label = KERNEL.global_labels["sys_blobhash"];
    let retdest = (0xDEADBEEFu64 + (1 << 32)).into(); // kexit_info

    let versioned_hashes: Vec<U256> = vec![U256::from_big_endian(&thread_rng().gen::<H256>().0); 5];
    let index = 7;
    let target_hash = U256::zero(); // out of bound indexing yields 0.

    let mut interpreter: Interpreter<F> = Interpreter::new(blobhash_label, vec![], None);
    interpreter
        .generation_state
        .memory
        .contexts
        .push(MemoryContextState::default());
    interpreter.set_context(1);
    interpreter.set_memory_segment(Segment::TxnBlobVersionedHashes, versioned_hashes);
    interpreter.set_global_metadata_field(GlobalMetadata::BlobVersionedHashesLen, 5.into());

    interpreter.set_context_metadata_field(1, GasLimit, U256::from(1000000000000u64));

    interpreter
        .push(index.into())
        .expect("The stack should not overflow"); // target hash index
    interpreter
        .push(retdest)
        .expect("The stack should not overflow"); // kexit_info

    interpreter.run()?;

    let result = interpreter.stack();
    assert_eq!(interpreter.stack_len(), 1);
    assert_eq!(
        result[0], target_hash,
        "Resulting blobhash {:?} different from expected hash {:?}",
        result[0], target_hash
    );

    Ok(())
}
