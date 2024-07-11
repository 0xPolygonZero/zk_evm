use anyhow::Result;
use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
use ethereum_types::U256;
use hex_literal::hex;
use plonky2::field::goldilocks_field::GoldilocksField as F;
use rand::Rng;

use super::{run_interpreter_with_memory, InterpreterMemoryInitialization};
use crate::cpu::kernel::aggregator::KERNEL;
use crate::cpu::kernel::interpreter::{self, Interpreter};
use crate::curve_pairings::{
    bn_final_exponent, bn_miller_loop, gen_bn_fp12_sparse, Curve, CyclicGroup,
};
use crate::extension_tower::{FieldExt, Fp12, Fp2, Fp6, Stack, BN254};
use crate::memory::segments::Segment::{self, BnPairing};

fn run_bn_mul_fp6(f: Fp6<BN254>, g: Fp6<BN254>, label: &str) -> Fp6<BN254> {
    let mut stack = f.to_stack();
    if label == "mul_fp254_6" {
        stack.extend(g.to_stack().to_vec());
    }
    stack.push(U256::from(0xdeadbeefu32));
    let setup = InterpreterMemoryInitialization {
        label: label.to_string(),
        stack,
        segment: BnPairing,
        memory: vec![],
    };
    let interpreter = run_interpreter_with_memory::<F>(setup).unwrap();
    let output: Vec<U256> = interpreter.stack().iter().rev().cloned().collect();
    Fp6::<BN254>::from_stack(&output)
}

#[test]
fn test_bn_mul_fp6() -> Result<()> {
    let mut rng = rand::thread_rng();
    let f: Fp6<BN254> = rng.gen::<Fp6<BN254>>();
    let g: Fp6<BN254> = rng.gen::<Fp6<BN254>>();

    let output_normal: Fp6<BN254> = run_bn_mul_fp6(f, g, "mul_fp254_6");
    let output_square: Fp6<BN254> = run_bn_mul_fp6(f, f, "square_fp254_6");

    assert_eq!(output_normal, f * g);
    assert_eq!(output_square, f * f);

    Ok(())
}

fn run_bn_mul_fp12(f: Fp12<BN254>, g: Fp12<BN254>, label: &str) -> Fp12<BN254> {
    let in0: usize = 100;
    let in1: usize = 112;
    let out: usize = 124;

    let mut stack = vec![
        U256::from(in0),
        U256::from(in1),
        U256::from(out),
        U256::from(0xdeadbeefu32),
    ];
    if label == "square_fp254_12" {
        stack.remove(0);
    }
    let setup = InterpreterMemoryInitialization {
        label: label.to_string(),
        stack,
        segment: BnPairing,
        memory: vec![(in0, f.to_stack().to_vec()), (in1, g.to_stack().to_vec())],
    };
    let interpreter = run_interpreter_with_memory::<F>(setup).unwrap();
    let output = interpreter.extract_kernel_memory(BnPairing, out..out + 12);
    Fp12::<BN254>::from_stack(&output)
}

#[test]
fn test_bn_mul_fp12() -> Result<()> {
    let mut rng = rand::thread_rng();
    let f: Fp12<BN254> = rng.gen::<Fp12<BN254>>();
    let g: Fp12<BN254> = rng.gen::<Fp12<BN254>>();
    let h: Fp12<BN254> = gen_bn_fp12_sparse(&mut rng);

    let output_normal = run_bn_mul_fp12(f, g, "mul_fp254_12");
    let output_sparse = run_bn_mul_fp12(f, h, "mul_fp254_12_sparse");
    let output_square = run_bn_mul_fp12(f, f, "square_fp254_12");

    assert_eq!(output_normal, f * g);
    assert_eq!(output_sparse, f * h);
    assert_eq!(output_square, f * f);

    Ok(())
}

fn run_bn_frob_fp6(n: usize, f: Fp6<BN254>) -> Fp6<BN254> {
    let setup = InterpreterMemoryInitialization {
        label: format!("test_frob_fp254_6_{}", n),
        stack: f.to_stack().to_vec(),
        segment: BnPairing,
        memory: vec![],
    };
    let interpreter: Interpreter<F> = run_interpreter_with_memory(setup).unwrap();
    let output: Vec<U256> = interpreter.stack().iter().rev().cloned().collect();
    Fp6::<BN254>::from_stack(&output)
}

#[test]
fn test_bn_frob_fp6() -> Result<()> {
    let mut rng = rand::thread_rng();
    let f: Fp6<BN254> = rng.gen::<Fp6<BN254>>();
    for n in 1..4 {
        let output = run_bn_frob_fp6(n, f);
        assert_eq!(output, f.frob(n));
    }
    Ok(())
}

fn run_bn_frob_fp12(f: Fp12<BN254>, n: usize) -> Fp12<BN254> {
    let ptr: usize = 100;
    let setup = InterpreterMemoryInitialization {
        label: format!("test_frob_fp254_12_{}", n),
        stack: vec![U256::from(ptr)],
        segment: BnPairing,
        memory: vec![(ptr, f.to_stack().to_vec())],
    };
    let interpreter: Interpreter<F> = run_interpreter_with_memory(setup).unwrap();
    let output: Vec<U256> = interpreter.extract_kernel_memory(BnPairing, ptr..ptr + 12);
    Fp12::<BN254>::from_stack(&output)
}

#[test]
fn test_frob_fp12() -> Result<()> {
    let mut rng = rand::thread_rng();
    let f: Fp12<BN254> = rng.gen::<Fp12<BN254>>();

    for n in [1, 2, 3, 6] {
        let output = run_bn_frob_fp12(f, n);
        assert_eq!(output, f.frob(n));
    }
    Ok(())
}

#[test]
fn test_bn_inv_fp12() -> Result<()> {
    let ptr: usize = 100;
    let inv: usize = 112;
    let mut rng = rand::thread_rng();
    let f: Fp12<BN254> = rng.gen::<Fp12<BN254>>();

    let setup = InterpreterMemoryInitialization {
        label: "inv_fp254_12".to_string(),
        stack: vec![U256::from(ptr), U256::from(inv), U256::from(0xdeadbeefu32)],
        segment: BnPairing,
        memory: vec![(ptr, f.to_stack().to_vec())],
    };
    let interpreter: Interpreter<F> = run_interpreter_with_memory(setup).unwrap();
    let output: Vec<U256> = interpreter.extract_kernel_memory(BnPairing, inv..inv + 12);
    let output = Fp12::<BN254>::from_stack(&output);

    assert_eq!(output, f.inv());

    Ok(())
}

#[test]
fn test_bn_final_exponent() -> Result<()> {
    let ptr: usize = 100;

    let mut rng = rand::thread_rng();
    let f: Fp12<BN254> = rng.gen::<Fp12<BN254>>();

    let setup = InterpreterMemoryInitialization {
        label: "bn254_final_exponent".to_string(),
        stack: vec![
            U256::zero(),
            U256::zero(),
            U256::from(ptr),
            U256::from(0xdeadbeefu32),
        ],
        segment: BnPairing,
        memory: vec![(ptr, f.to_stack().to_vec())],
    };

    let interpreter: Interpreter<F> = run_interpreter_with_memory(setup).unwrap();
    let output: Vec<U256> = interpreter.extract_kernel_memory(BnPairing, ptr..ptr + 12);
    let expected: Vec<U256> = bn_final_exponent(f).to_stack();

    assert_eq!(output, expected);

    Ok(())
}

#[test]
fn test_bn_miller() -> Result<()> {
    let ptr: usize = 100;
    let out: usize = 106;

    let mut rng = rand::thread_rng();
    let p: Curve<BN254> = rng.gen::<Curve<BN254>>();
    let q: Curve<Fp2<BN254>> = rng.gen::<Curve<Fp2<BN254>>>();

    let mut input = p.to_stack();
    input.extend(q.to_stack());

    let setup = InterpreterMemoryInitialization {
        label: "bn254_miller".to_string(),
        stack: vec![U256::from(ptr), U256::from(out), U256::from(0xdeadbeefu32)],
        segment: BnPairing,
        memory: vec![(ptr, input)],
    };
    let interpreter = run_interpreter_with_memory::<F>(setup).unwrap();
    let output: Vec<U256> = interpreter.extract_kernel_memory(BnPairing, out..out + 12);
    let expected = bn_miller_loop(p, q).to_stack();

    assert_eq!(output, expected);

    Ok(())
}

#[test]
fn test_bn_pairing() -> Result<()> {
    let out: usize = 100;
    let ptr: usize = 112;

    let mut rng = rand::thread_rng();
    let k: usize = rng.gen_range(1..10);
    let mut acc: i32 = 0;
    let mut input: Vec<U256> = vec![];
    for _ in 1..k {
        let m: i32 = rng.gen_range(-8..8);
        let n: i32 = rng.gen_range(-8..8);
        acc -= m * n;

        let p: Curve<BN254> = Curve::<BN254>::int(m);
        let q: Curve<Fp2<BN254>> = Curve::<Fp2<BN254>>::int(n);
        input.extend(p.to_stack());
        input.extend(q.to_stack());
    }
    let p: Curve<BN254> = Curve::<BN254>::int(acc);
    let q: Curve<Fp2<BN254>> = Curve::<Fp2<BN254>>::GENERATOR;
    input.extend(p.to_stack());
    input.extend(q.to_stack());

    let setup = InterpreterMemoryInitialization {
        label: "bn254_pairing".to_string(),
        stack: vec![
            U256::from(k),
            U256::from(ptr),
            U256::from(out),
            U256::from(0xdeadbeefu32),
        ],
        segment: BnPairing,
        memory: vec![(ptr, input)],
    };
    let interpreter = run_interpreter_with_memory::<F>(setup).unwrap();
    assert_eq!(interpreter.stack()[0], U256::one());
    Ok(())
}

fn run_bn_g2_op(p: Curve<Fp2<BN254>>, q: Curve<Fp2<BN254>>, label: &str) -> Curve<Fp2<BN254>> {
    let mut stack = p.to_stack();
    if label == "bn_twisted_add" {
        stack.extend(&q.to_stack());
    }
    stack.push(U256::from(0xdeadbeefu32));
    let setup = InterpreterMemoryInitialization {
        label: label.to_string(),
        stack,
        segment: BnPairing,
        memory: vec![],
    };
    let interpreter = run_interpreter_with_memory::<F>(setup).unwrap();
    let output: Vec<U256> = interpreter.stack().iter().rev().cloned().collect();
    Curve::<Fp2<BN254>>::from_stack(&output)
}

#[test]
fn test_bn_g2_ops() -> Result<()> {
    let mut rng = rand::thread_rng();
    let p: Curve<Fp2<BN254>> = rng.gen::<Curve<Fp2<BN254>>>();
    let q: Curve<Fp2<BN254>> = rng.gen::<Curve<Fp2<BN254>>>();

    let output_add: Curve<Fp2<BN254>> = run_bn_g2_op(p, q, "bn_twisted_add");
    let output_double: Curve<Fp2<BN254>> = run_bn_g2_op(p, p, "bn_twisted_double");

    assert_eq!(output_add, p + q);
    assert_eq!(output_double, p + p);

    let unit = Curve::<Fp2<BN254>>::unit();
    let output_add_unit: Curve<Fp2<BN254>> = run_bn_g2_op(unit, unit, "bn_twisted_add");
    let output_double_unit: Curve<Fp2<BN254>> = run_bn_g2_op(unit, unit, "bn_twisted_double");

    assert_eq!(unit, output_add_unit);
    assert_eq!(unit, output_double_unit);

    let output_add_with_unit_left: Curve<Fp2<BN254>> = run_bn_g2_op(unit, p, "bn_twisted_add");
    let output_add_with_unit_right: Curve<Fp2<BN254>> = run_bn_g2_op(p, unit, "bn_twisted_add");

    assert_eq!(p, output_add_with_unit_left);
    assert_eq!(p, output_add_with_unit_right);

    Ok(())
}

/// Test cases taken from <https://github.com/ethereum/tests/blob/develop/src/GeneralStateTestsFiller/stZeroKnowledge/ecpairing_inputsFiller.yml>.
const ECPAIRING_PRECOMPILE_INVALID_INPUTS: [[u8; 192]; 4] = [
    // invalid_g1_point
    hex!("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f00000010000000000000000000000000000000000000000000000000000000000000000198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa"),
    // invalid_g2_point
    hex!("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffff0000000000000000ffffffffffffffffffff"),
    // invalid_g2_subgroup
    hex!("000000000000000000000000000000000000000000000000000000000000000130644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4530644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4500000000000000000000000000000000000000000000000000000000000000020833e47a2eaa8bbe12d33b2da1a4fa8d763f5c567fe0da6c5c9da2e246f2096f28dc125bf7443bc1826c69fe4c7bf30c26ec60882350e784c4848c822726eb43"),
    // invalid_g2_subgroup
    hex!("111f95e1632a3624dd29bbc012e6462b7836eb9c80e281b9381e103aebe632372b38b76d492b3af692eb99d03cd8dcfd8a8c3a6e4a161037c42f542af5564c41198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21a76dae6d3272396d0cbe61fced2bc532edac647851e3ac53ce1cc9c7e645a8305b993046905746641a19b500ebbbd30cf0068a845bfbee9de55b8fe57d1dee8243ef33537f73ef4ace4279d86344d93a5dc8c20c69045865c0fa3b924933879"),
];

#[test]
fn test_ecpairing_precompile_invalid_input() -> Result<()> {
    init_logger();

    let pairing_label = KERNEL.global_labels["bn254_pairing"];
    let mut stack = vec![1.into(), 0.into(), 100.into(), U256::from(0xdeadbeefu32)]; // k, inp, out, retdest
    stack.reverse();

    for bytes in ECPAIRING_PRECOMPILE_INVALID_INPUTS.iter() {
        let mut interpreter: Interpreter<F> = Interpreter::new(pairing_label, stack.clone(), None);
        let preloaded_memory = vec![
            U256::from_big_endian(&bytes[0..32]),    // Px
            U256::from_big_endian(&bytes[32..64]),   // Py
            U256::from_big_endian(&bytes[64..96]),   // Qx_re
            U256::from_big_endian(&bytes[96..128]),  // Qx_im
            U256::from_big_endian(&bytes[128..160]), // Qy_re
            U256::from_big_endian(&bytes[160..192]), // Qy_im
        ];
        interpreter.set_memory_segment(Segment::BnPairing, preloaded_memory);
        interpreter.run().unwrap();

        let mut post_stack = interpreter.stack();
        assert!(post_stack.len() == 1);

        assert_eq!(post_stack[0], U256::MAX); // invalid inputs
    }

    Ok(())
}

fn init_logger() {
    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "debug"));
}
