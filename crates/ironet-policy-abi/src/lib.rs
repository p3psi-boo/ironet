//! Policy ABI V1: the host/guest contract of the Ironet adaptive-control
//! policy module.
//!
//! This crate is the Rust mirror of the `ironet:policy/policy@1.0.0` WIT
//! world (`wit/ironet-policy.wit`). It is shared by the Ironet host,
//! `ironet-policy-core` and every policy guest, so it depends on nothing but
//! `serde` and compiles for `wasm32-unknown-unknown`: no `std::time`, no
//! randomness, no `usize`/`f64` in any ABI field.
//!
//! Conventions (one unit and one direction per field):
//!
//! - ratios are `per_mille` (1/1000) or `ppm` (1/1_000_000), gains are
//!   `milli` (1.000 == 1_000);
//! - durations are `micros` or `millis`;
//! - rates are `bytes_per_second`;
//! - `0` in a cap/rate field means "no cap / host default" unless the field
//!   documentation says otherwise;
//! - `local_tx_*` describes the direction the host transmits on, `local_rx_*`
//!   the direction it receives on, `remote_*` values are reported by the peer
//!   through feedback, and `host_*` values are not direction specific.
//!
//! Three action shapes exist:
//!
//! - [`CandidateActionV1`] is what a policy proposes; every field is optional
//!   and nothing in it is trusted;
//! - [`EffectiveActionV1`] is the host-authoritative, fully resolved action
//!   that the data plane executes;
//! - [`ClampReportV1`] records every candidate field the host changed,
//!   rejected or ignored while deriving the effective action.
//!
//! Conversions to and from the host runtime structs live in the host crate
//! (`ironet::protocol::v2::policy::api`), not here.

#![forbid(unsafe_code)]

mod backend;
mod candidate;
mod clamp;
mod effective;
mod enums;
mod input;
mod output;

pub use backend::*;
pub use candidate::*;
pub use clamp::*;
pub use effective::*;
pub use enums::*;
pub use input::*;
pub use output::*;

/// WIT world identifier this crate mirrors.
pub const POLICY_ABI_WORLD_V1: &str = "ironet:policy/policy@1.0.0";
/// ABI major version carried in [`HostCapabilitiesV1`].
pub const POLICY_ABI_MAJOR_V1: u16 = 1;
/// ABI minor version carried in [`HostCapabilitiesV1`].
pub const POLICY_ABI_MINOR_V1: u16 = 0;
/// Maximum encoded size of one [`PolicyInputV1`].
pub const POLICY_INPUT_BUDGET_BYTES: u32 = 64 * 1024;
/// Maximum encoded size of one [`PolicyOutputV1`].
pub const POLICY_OUTPUT_BUDGET_BYTES: u32 = 64 * 1024;
/// Maximum opaque per-peer policy state carried in `state`/`next_state`.
pub const POLICY_STATE_MAX_BYTES: u32 = 64 * 1024;
/// Maximum payload of one TLV extension entry.
pub const POLICY_EXTENSION_MAX_PAYLOAD_BYTES: u32 = 4 * 1024;
/// Maximum number of TLV extension entries per input or per candidate.
pub const POLICY_EXTENSION_MAX_COUNT: u16 = 32;
/// Byte length of the fixed-size diagnostics labels.
pub const POLICY_LABEL_BYTES: usize = 16;
/// Highest egress priority a candidate may request (0 = background).
pub const EGRESS_PRIORITY_MAX: u8 = 7;
/// Parity overhead guard: parity cells may not exceed the data-cell count.
/// The native policy reserves 100% overhead for severe correlated loss; the
/// ordinary geometries remain substantially below this host ceiling.
pub const FEC_PARITY_PER_MILLE_CAP: u16 = 1_000;
/// Largest FEC data cell count the V2 stripe encoder supports.
pub const FEC_DATA_CELLS_MAX: u8 = 16;
/// Largest FEC parity cell count the V2 stripe encoder supports.
pub const FEC_PARITY_CELLS_MAX: u8 = 8;

pub(crate) fn i64_saturating(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}
