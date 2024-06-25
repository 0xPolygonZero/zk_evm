use zk_evm_derive::Columns;

#[repr(C)]
#[derive(Columns)]
enum Maybe<T> {
    Nothing,
    Just(T),
}

fn main() {}
