use std::str::FromStr;

use anyhow::Result;
use ethereum_types::U256;

use crate::bn254::{
    curve_generator, fp12_to_vec, frob_fp12, gen_fp12, gen_fp12_sparse, miller_loop, mul_fp12,
    power, tate, twisted_curve_generator, Curve, Fp12, TwistedCurve,
};
use crate::cpu::kernel::aggregator::KERNEL;
use crate::cpu::kernel::interpreter::run_interpreter;

fn get_address_from_label(lbl: &str) -> U256 {
    U256::from(KERNEL.global_labels[lbl])
}

fn get_output(lbl: &str, stack: Vec<U256>) -> Vec<U256> {
    let label = KERNEL.global_labels[lbl];
    let mut input = stack;
    input.reverse();
    let mut output = run_interpreter(label, input).unwrap().stack().to_vec();
    output.reverse();
    output
}

fn make_mul_stack(f: Fp12, g: Fp12, mul_label: &str) -> Vec<U256> {
    let in0 = U256::from(64);
    let in1 = U256::from(76);
    let out = U256::from(88);

    let mut stack = vec![in0];
    stack.extend(fp12_to_vec(f));
    stack.extend(vec![in1]);
    stack.extend(fp12_to_vec(g));
    stack.extend(vec![
        get_address_from_label(mul_label),
        in0,
        in1,
        out,
        get_address_from_label("return_fp12_on_stack"),
        out,
    ]);
    stack
}

#[test]
fn test_mul_fp12() -> Result<()> {
    let f: Fp12 = gen_fp12();
    let g: Fp12 = gen_fp12();
    let h: Fp12 = gen_fp12_sparse();

    let normal: Vec<U256> = make_mul_stack(f, g, "mul_fp12");
    let sparse: Vec<U256> = make_mul_stack(f, h, "mul_fp12_sparse");
    let square: Vec<U256> = make_mul_stack(f, f, "square_fp12_test");

    let out_normal: Vec<U256> = get_output("test_mul_fp12", normal);
    let out_sparse: Vec<U256> = get_output("test_mul_fp12", sparse);
    let out_square: Vec<U256> = get_output("test_mul_fp12", square);

    let exp_normal: Vec<U256> = fp12_to_vec(mul_fp12(f, g));
    let exp_sparse: Vec<U256> = fp12_to_vec(mul_fp12(f, h));
    let exp_square: Vec<U256> = fp12_to_vec(mul_fp12(f, f));

    assert_eq!(out_normal, exp_normal);
    assert_eq!(out_sparse, exp_sparse);
    assert_eq!(out_square, exp_square);

    Ok(())
}

#[test]
fn test_frob_fp12() -> Result<()> {
    let ptr = U256::from(100);

    let f: Fp12 = gen_fp12();

    let mut stack = vec![ptr];
    stack.extend(fp12_to_vec(f));
    stack.extend(vec![ptr]);

    let out_frob1: Vec<U256> = get_output("test_frob_fp12_1", stack.clone());
    let out_frob2: Vec<U256> = get_output("test_frob_fp12_2", stack.clone());
    let out_frob3: Vec<U256> = get_output("test_frob_fp12_3", stack.clone());
    let out_frob6: Vec<U256> = get_output("test_frob_fp12_6", stack);

    let exp_frob1: Vec<U256> = fp12_to_vec(frob_fp12(1, f));
    let exp_frob2: Vec<U256> = fp12_to_vec(frob_fp12(2, f));
    let exp_frob3: Vec<U256> = fp12_to_vec(frob_fp12(3, f));
    let exp_frob6: Vec<U256> = fp12_to_vec(frob_fp12(6, f));

    assert_eq!(out_frob1, exp_frob1);
    assert_eq!(out_frob2, exp_frob2);
    assert_eq!(out_frob3, exp_frob3);
    assert_eq!(out_frob6, exp_frob6);

    Ok(())
}

#[test]
fn test_inv_fp12() -> Result<()> {
    let ptr = U256::from(200);
    let inv = U256::from(300);

    let f: Fp12 = gen_fp12();
    let mut stack = vec![ptr];
    stack.extend(fp12_to_vec(f));
    stack.extend(vec![ptr, inv, U256::from_str("0xdeadbeef").unwrap()]);

    let output: Vec<U256> = get_output("test_inv_fp12", stack);

    assert_eq!(output, vec![]);

    Ok(())
}

#[test]
fn test_power() -> Result<()> {
    let ptr = U256::from(300);
    let out = U256::from(400);

    let f: Fp12 = gen_fp12();

    let mut stack = vec![ptr];
    stack.extend(fp12_to_vec(f));
    stack.extend(vec![
        ptr,
        out,
        get_address_from_label("return_fp12_on_stack"),
        out,
    ]);

    let output: Vec<U256> = get_output("test_pow", stack);
    let expected: Vec<U256> = fp12_to_vec(power(f));

    assert_eq!(output, expected);

    Ok(())
}

fn make_tate_stack(p: Curve, q: TwistedCurve) -> Vec<U256> {
    let ptr = U256::from(300);
    let out = U256::from(400);

    let p_: Vec<U256> = p.into_iter().collect();
    let q_: Vec<U256> = q.into_iter().flatten().collect();

    let mut stack = vec![ptr];
    stack.extend(p_);
    stack.extend(q_);
    stack.extend(vec![
        ptr,
        out,
        get_address_from_label("return_fp12_on_stack"),
        out,
    ]);
    stack
}

#[test]
fn test_miller() -> Result<()> {
    let p: Curve = curve_generator();
    let q: TwistedCurve = twisted_curve_generator();

    let stack = make_tate_stack(p, q);
    let output = get_output("test_miller", stack);
    let expected = fp12_to_vec(miller_loop(p, q));

    assert_eq!(output, expected);

    Ok(())
}

#[test]
fn test_tate() -> Result<()> {
    let p: Curve = curve_generator();
    let q: TwistedCurve = twisted_curve_generator();

    let stack = make_tate_stack(p, q);
    let output = get_output("test_tate", stack);
    let expected = fp12_to_vec(tate(p, q));

    assert_eq!(output, expected);

    Ok(())
}
