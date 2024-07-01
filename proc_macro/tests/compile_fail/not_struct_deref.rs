use zk_evm_proc_macro::DerefColumns;

#[repr(C)]
#[derive(DerefColumns)]
enum Maybe<T> {
    Nothing,
    Just(T),
}

fn main() {}
