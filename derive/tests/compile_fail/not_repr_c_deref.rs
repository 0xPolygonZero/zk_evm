use zk_evm_derive::DerefColumns;

#[derive(DerefColumns)]
struct Columns<T> {
    a: T,
    b: [T; 3],
}

fn main() {}
