use anyhow::Result;
use ethereum_types::U256;
use hex_literal::hex;
use plonky2::field::goldilocks_field::GoldilocksField as F;
use rand::Rng;

use super::{run_interpreter_with_memory, InterpreterMemoryInitialization};
use crate::cpu::kernel::aggregator::KERNEL;
use crate::cpu::kernel::cancun_constants::POINT_EVALUATION_PRECOMPILE_RETURN_VALUE;
use crate::cpu::kernel::constants::cancun_constants::KZG_VERSIONED_HASH;
use crate::cpu::kernel::interpreter::Interpreter;
use crate::extension_tower::{Fp2, Stack, BLS381};
use crate::memory::segments::Segment::KernelGeneral;
use crate::util::sha2;

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

/// A KZG point evaluation precompile payload consists in:
///     - a G1 compressed point commitment (48 bytes)
///     - a Scalar element z (32 bytes)
///     - a Scalar element y (32 bytes)
///     - a G1 compressed point proof (48 bytes)
type KzgPayload = ([u8; 48], [u8; 32], [u8; 32], [u8; 48]);
/// Contains a KZG payload and the expected result, i.e. success or failure.
type TestSequence = (KzgPayload, bool);

/// Test cases taken from <https://github.com/ethereum/c-kzg-4844/blob/main/tests/verify_kzg_proof/kzg-mainnet/>.
const KZG_PRECOMPILE_TEST_SEQUENCES: [TestSequence; 10] = [
    // verify_kzg_proof_case_correct_proof_02e696ada7d4631d/data.yaml
    ((hex!("c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
    hex!("0000000000000000000000000000000000000000000000000000000000000002"),
    hex!("0000000000000000000000000000000000000000000000000000000000000000"),
    hex!("c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")), true),

    // verify_kzg_proof_case_correct_proof_0cf79b17cb5f4ea2/data.yaml
    ((hex!("c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
    hex!("5eb7004fe57383e6c88b99d839937fddf3f99279353aaf8d5c9a75f91ce33c62"),
    hex!("0000000000000000000000000000000000000000000000000000000000000000"),
    hex!("c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")), true),

    // verify_kzg_proof_case_correct_proof_9b24f8997145435c/data.yaml
    ((hex!("93efc82d2017e9c57834a1246463e64774e56183bb247c8fc9dd98c56817e878d97b05f5c8d900acf1fbbbca6f146556"),
    hex!("0000000000000000000000000000000000000000000000000000000000000001"),
    hex!("0000000000000000000000000000000000000000000000000000000000000000"),
    hex!("b9241c6816af6388d1014cd4d7dd21662a6e3d47f96c0257bce642b70e8e375839a880864638669c6a709b414ab8bffc")), true),

    // verify_kzg_proof_case_correct_proof_31ebd010e6098750/data.yaml
    ((hex!("8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7"),
    hex!("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000"),
    hex!("1522a4a7f34e1ea350ae07c29c96c7e79655aa926122e95fe69fcbd932ca49e9"),
    hex!("a62ad71d14c5719385c0686f1871430475bf3a00f0aa3f7b8dd99a9abc2160744faf0070725e00b60ad9a026a15b1a8c")), true),



    // verify_kzg_proof_case_incorrect_proof_05c1f3685f3393f0/data.yaml
    ((hex!("a572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e"),
    hex!("564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d36306"),
    hex!("0000000000000000000000000000000000000000000000000000000000000002"),
    hex!("97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb")), false),

    // verify_kzg_proof_case_incorrect_proof_d736268229bd87ec/data.yaml
    ((hex!("93efc82d2017e9c57834a1246463e64774e56183bb247c8fc9dd98c56817e878d97b05f5c8d900acf1fbbbca6f146556"),
    hex!("5eb7004fe57383e6c88b99d839937fddf3f99279353aaf8d5c9a75f91ce33c62"),
    hex!("5fd58150b731b4facfcdd89c0e393ff842f5f2071303eff99b51e103161cd233"),
    hex!("84c349506215a2d55f9d06f475b8229c6dedc08fd467f41fabae6bb042c2d0dbdbcd5f7532c475e479588eec5820fd37")), false),

    // verify_kzg_proof_case_incorrect_proof_point_at_infinity_83e53423a2dd93fe/data.yaml
    ((hex!("a421e229565952cfff4ef3517100a97da1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06"),
    hex!("0000000000000000000000000000000000000000000000000000000000000001"),
    hex!("1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffe"),
    hex!("c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")), false),

    // verify_kzg_proof_case_invalid_commitment_e9d3e9ec16fbc15f/data.yaml
    ((hex!("8123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde0"),
    hex!("0000000000000000000000000000000000000000000000000000000000000001"),
    hex!("1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffe"),
    hex!("b0c829a8d2d3405304fecbea193e6c67f7c3912a6adc7c3737ad3f8a3b750425c1531a7426f03033a3994bc82a10609f")), false),

    // verify_kzg_proof_case_invalid_y_64b9ff2b8f7dddee/data.yaml
    ((hex!("8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7"),
    hex!("0000000000000000000000000000000000000000000000000000000000000001"),
    hex!("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000002"),
    hex!("b30b3d1e4faccc380557792c9a0374d58fa286f5f75fea48870585393f890909cd3c53cfe4897e799fb211b4be531e43")), false),

    // verify_kzg_proof_case_invalid_z_64b9ff2b8f7dddee/data.yaml
    ((hex!("8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7"),
    hex!("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000002"),
    hex!("60f840641ec0d0c0d2b77b2d5a393b329442721fad05ab78c7b98f2aa3c20ec9"),
    hex!("b30b3d1e4faccc380557792c9a0374d58fa286f5f75fea48870585393f890909cd3c53cfe4897e799fb211b4be531e43")), false),
];

#[test]
fn test_kzg_peval_precompile() -> Result<()> {
    for (bytes, is_correct) in KZG_PRECOMPILE_TEST_SEQUENCES.iter() {
        let commitment_bytes = bytes.0;
        let comm_hi = U256::from_big_endian(&commitment_bytes[0..32]);
        let comm_lo = U256::from_big_endian(&commitment_bytes[32..48]);
        let mut versioned_hash = sha2(commitment_bytes.to_vec());
        const KZG_HASH_MASK: U256 = U256([
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0x00ffffffffffffff,
        ]);
        versioned_hash &= KZG_HASH_MASK; // erase most significant byte
        versioned_hash |= U256::from(KZG_VERSIONED_HASH) << 248; // append 1
        let z = U256::from_big_endian(&bytes.1);
        let y = U256::from_big_endian(&bytes.2);
        let proof_bytes = bytes.3;
        let proof_hi = U256::from_big_endian(&proof_bytes[0..32]);
        let proof_lo = U256::from_big_endian(&proof_bytes[32..48]);

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
        interpreter.halt_offsets = vec![
            KERNEL.global_labels["store_kzg_verification"],
            KERNEL.global_labels["fault_exception"],
        ];
        if *is_correct {
            interpreter.run().unwrap();

            let mut post_stack = interpreter.stack();
            post_stack.reverse();

            assert_eq!(
                post_stack[0],
                U256::from_big_endian(&POINT_EVALUATION_PRECOMPILE_RETURN_VALUE[0])
            );
            assert_eq!(
                post_stack[1],
                U256::from_big_endian(&POINT_EVALUATION_PRECOMPILE_RETURN_VALUE[1])
            );
        } else {
            interpreter.run().unwrap();
            assert_eq!(
                interpreter.generation_state.registers.program_counter,
                KERNEL.global_labels["fault_exception"]
            );
        }
    }

    Ok(())
}
