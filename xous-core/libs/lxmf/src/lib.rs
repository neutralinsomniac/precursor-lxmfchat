//! `lxmf`: sans-IO implementation of the LXMF messaging format on top of
//! `reticulum-core`. (Implementation in progress.)

pub mod message;
pub mod stamp;
pub mod msgpack;

pub use message::{Fields, PackedMessage, ParsedMessage, pack, parse};
