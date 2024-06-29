use zk_evm_proc_macro::Columns;

#[repr(C)]
#[derive(Columns)]
enum Maybe<T> {
    Nothing,
    Just(T),
}

fn main() {}
