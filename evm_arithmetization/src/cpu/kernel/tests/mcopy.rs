use anyhow::Result;
use ethereum_types::U256;
use hex_literal::hex;
use itertools::Itertools;
use plonky2::field::goldilocks_field::GoldilocksField as F;

use crate::cpu::kernel::constants::context_metadata::ContextMetadata;
use crate::cpu::kernel::interpreter::Interpreter;
use crate::memory::segments::Segment;
use crate::testing_utils::init_logger;

fn test_mcopy(
    dest_offset: usize,
    offset: usize,
    size: usize,
    pre_memory: &[u8],
    post_memory: &[u8],
) -> Result<()> {
    init_logger();

    let sys_mcopy = crate::cpu::kernel::aggregator::KERNEL.global_labels["sys_mcopy"];
    let kexit_info = U256::from(0xdeadbeefu32) + (U256::from(u64::from(true)) << 32);
    let initial_stack = vec![size.into(), offset.into(), dest_offset.into(), kexit_info];

    let mut interpreter: Interpreter<F> = Interpreter::new(sys_mcopy, initial_stack);
    interpreter.set_context_metadata_field(
        0,
        ContextMetadata::GasLimit,
        U256::from(1000000000000u64),
    );

    let pre_memory: Vec<U256> = pre_memory.iter().map(|&b| b.into()).collect_vec();
    let post_memory: Vec<U256> = post_memory.iter().map(|&b| b.into()).collect_vec();

    interpreter.set_memory_segment(Segment::MainMemory, pre_memory);
    interpreter.run()?;

    let main_memory_data = interpreter.get_memory_segment(Segment::MainMemory);
    assert_eq!(&main_memory_data, &post_memory);

    Ok(())
}

#[test]
fn test_mcopy_0_32_32() {
    let dest_offset = 0;
    let offset = 32;
    let size = 32;
    let pre_memory = hex!("0000000000000000000000000000000000000000000000000000000000000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let post_memory = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    assert!(test_mcopy(dest_offset, offset, size, &pre_memory, &post_memory).is_ok())
}

#[test]
fn test_mcopy_0_0_32() {
    let dest_offset = 0;
    let offset = 0;
    let size = 32;
    let pre_memory = hex!("0101010101010101010101010101010101010101010101010101010101010101");
    let post_memory = hex!("0101010101010101010101010101010101010101010101010101010101010101");

    assert!(test_mcopy(dest_offset, offset, size, &pre_memory, &post_memory).is_ok())
}

#[test]
fn test_mcopy_0_1_8() {
    let dest_offset = 0;
    let offset = 1;
    let size = 8;
    let pre_memory = hex!("0001020304050607080000000000000000000000000000000000000000000000");
    let post_memory = hex!("0102030405060708080000000000000000000000000000000000000000000000");

    assert!(test_mcopy(dest_offset, offset, size, &pre_memory, &post_memory).is_ok())
}

#[test]
fn test_mcopy_1_0_8() {
    let dest_offset = 1;
    let offset = 0;
    let size = 8;
    let pre_memory = hex!("0001020304050607080000000000000000000000000000000000000000000000");
    let post_memory = hex!("0000010203040506070000000000000000000000000000000000000000000000");

    assert!(test_mcopy(dest_offset, offset, size, &pre_memory, &post_memory).is_ok())
}

#[test]
fn test_mcopy_1_0_33() {
    init_logger();
    let dest_offset = 1;
    let offset = 0;
    let size = 33;
    let pre_memory =
        hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627");
    let post_memory =
        hex!("00000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20222324252627");

    assert!(test_mcopy(dest_offset, offset, size, &pre_memory, &post_memory).is_ok())
}

#[test]
fn test_mcopy_1_2_33() {
    init_logger();
    let dest_offset = 1;
    let offset = 2;
    let size = 33;
    let pre_memory =
        hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728");
    let post_memory =
        hex!("0002030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212222232425262728");

    assert!(test_mcopy(dest_offset, offset, size, &pre_memory, &post_memory).is_ok())
}
