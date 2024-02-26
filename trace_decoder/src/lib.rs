#![feature(linked_list_cursors)]
#![feature(trait_alias)]
#![feature(iter_array_chunks)]
// TODO: address these lints
#![allow(unused)]
#![allow(private_interfaces)]

pub mod compact;
pub mod decoding;
mod deserializers;
pub mod processed_block_trace;
pub mod trace_protocol;
pub mod types;
pub mod utils;
