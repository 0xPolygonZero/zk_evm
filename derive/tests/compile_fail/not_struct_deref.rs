use zk_evm_derive::DerefColumns;

#[repr(C)]
#[derive(DerefColumns)]
enum Maybe<T> {
    Nothing,
    Just(T),
}

fn main() {}
