use anyhow::Result;
use ethereum_types::U256;
use hex_literal::hex;
use keccak_hash::keccak;
use plonky2::field::goldilocks_field::GoldilocksField as F;
use rand::Rng;

use crate::cpu::kernel::aggregator::KERNEL;
use crate::cpu::kernel::constants::cancun_constants::KZG_VERSIONED_HASH;
use crate::cpu::kernel::constants::context_metadata::ContextMetadata;
use crate::cpu::kernel::interpreter::{
    self, run_interpreter_with_memory, Interpreter, InterpreterMemoryInitialization,
};
use crate::extension_tower::{Fp2, Stack, BLS381};
use crate::memory::segments::Segment::{self, KernelGeneral};

#[test]
fn test_bls_fp2_mul() -> Result<()> {
    let mut rng = rand::thread_rng();
    let x: Fp2<BLS381> = rng.gen::<Fp2<BLS381>>();
    let y: Fp2<BLS381> = rng.gen::<Fp2<BLS381>>();

    let mut stack = x.to_stack().to_vec();
    stack.extend(y.to_stack().to_vec());
    stack.push(U256::from(0xdeadbeefu32));
    let setup = InterpreterMemoryInitialization {
        label: "mul_fp381_2".to_string(),
        stack,
        segment: KernelGeneral,
        memory: vec![],
    };
    let interpreter = run_interpreter_with_memory::<F>(setup).unwrap();
    let stack: Vec<U256> = interpreter.stack().iter().rev().cloned().collect();
    let output = Fp2::<BLS381>::from_stack(&stack);

    assert_eq!(output, x * y);
    Ok(())
}

#[test]
fn test_kzg_peval_precompile() -> Result<()> {
    // Test case taken from <https://github.com/ethereum/c-kzg-4844/blob/main/tests/verify_kzg_proof/kzg-mainnet/verify_kzg_proof_case_correct_proof_31ebd010e6098750/data.yaml>.

    // input: {commitment:
    // '0x8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7'
    // , z: '0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000'
    // , y: '0x1522a4a7f34e1ea350ae07c29c96c7e79655aa926122e95fe69fcbd932ca49e9',
    // proof: '0xa62ad71d14c5719385c0686f1871430475bf3a00f0aa3f7b8dd99a9abc2160744faf0070725e00b60ad9a026a15b1a8c'}
    // output: true

    let commitment_bytes = hex!("8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7");
    let comm_hi = U256::from_big_endian(&commitment_bytes[0..16]);
    let comm_lo = U256::from_big_endian(&commitment_bytes[16..48]);
    let mut versioned_hash = keccak(&commitment_bytes).0;
    versioned_hash[0] = KZG_VERSIONED_HASH;
    let versioned_hash = U256::from_big_endian(&versioned_hash);
    let z = U256::from_big_endian(&hex!(
        "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000"
    ));
    let y = U256::from_big_endian(&hex!(
        "1522a4a7f34e1ea350ae07c29c96c7e79655aa926122e95fe69fcbd932ca49e9"
    ));
    let proof_bytes = hex!("a62ad71d14c5719385c0686f1871430475bf3a00f0aa3f7b8dd99a9abc2160744faf0070725e00b60ad9a026a15b1a8c");
    let proof_hi = U256::from_big_endian(&proof_bytes[0..16]);
    let proof_lo = U256::from_big_endian(&proof_bytes[16..48]);

    let mut stack = vec![
        versioned_hash,
        z,
        y,
        comm_hi,
        comm_lo,
        proof_hi,
        proof_lo,
        U256::from(0xdeadbeefu32),
    ];
    stack.reverse();

    let verify_kzg_proof = KERNEL.global_labels["verify_kzg_proof"];
    let mut interpreter: Interpreter<F> = Interpreter::new(verify_kzg_proof, stack);
    // interpreter.set_context(1);
    interpreter.halt_offsets = vec![KERNEL.global_labels["store_kzg_verification"]];
    interpreter.run().unwrap();

    println!("{:?}", interpreter.stack());

    panic!("TODO: debug test");
}
