//! # RTP parser
//! 
//! This crate contains a parser written in Rust (using nom) for the RTP protocol
//! 
//! See also:
//! - [RFC 3550](https://tools.ietf.org/html/rfc3550#page-13): RTP: A Transport Protocol for Real-Time Applications

mod rtp;
pub use rtp::*;

mod parser;
pub use parser::*;
