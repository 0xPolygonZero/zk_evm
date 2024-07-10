use zk_evm_proc_macro::Columns;

#[derive(Columns)]
struct Columns<T> {
    a: T,
    b: [T; 3],
}

fn main() {}
