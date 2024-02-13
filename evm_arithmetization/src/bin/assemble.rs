use std::{env, fs};

use evm_arithmetization::cpu::kernel::assemble_to_bytes;
use hex::encode;

fn main() {
    let mut args = env::args();
    args.next();
    let file_contents: Vec<_> = args.map(|path| fs::read_to_string(path).unwrap()).collect();
    let assembled = assemble_to_bytes(&file_contents[..]);
    println!("{}", encode(assembled));
}
