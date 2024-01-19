#![feature(linked_list_cursors)]
#![feature(trait_alias)]
#![feature(iter_array_chunks)]
// TODO: address these lints
#![allow(unused)]
#![allow(clippy::type_complexity)]
#![allow(private_interfaces)]

mod compact;
pub mod decoding;
mod deserializers;
pub mod processed_block_trace;
pub mod proof_gen_types;
pub mod trace_protocol;
pub mod types;
pub mod utils;
