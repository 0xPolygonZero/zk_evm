use zk_evm_proc_macro::DerefColumns;

#[derive(DerefColumns)]
struct Columns<T> {
    a: T,
    b: [T; 3],
}

fn main() {}
