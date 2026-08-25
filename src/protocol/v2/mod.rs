//! Ironet V2 protocol primitives.
//!
//! V2 deliberately has no V1 decoder or negotiation fallback. QUIC owns
//! encryption, congestion control and packet protection; this module defines
//! the authenticated session preface and the application DATAGRAM payloads.

pub mod cell;
pub mod classifier;
pub mod cover;
pub mod dataplane;
pub mod fec;
pub mod feedback;
pub mod gso;
pub mod learner;
pub mod policy;
pub mod policy_tick;
pub mod policy_train;
pub mod presence;
pub mod promotion;
pub mod reassembly;
pub mod repair;
pub mod replay;
pub mod route_feedback;
pub mod routing;
pub mod scheduler;
pub mod session;
pub mod train;
pub mod tuning;
pub mod utility;

pub const MAJOR: u16 = 2;
