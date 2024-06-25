use zk_evm_derive::Columns;

#[derive(Columns)]
struct Columns<T> {
    a: T,
    b: [T; 3],
}

fn main() {}
