use anyhow::{Result, ensure};
use bytes::{BufMut, Bytes, BytesMut};

use super::routing::RouteLabelV2;

const MAGIC: &[u8; 4] = b"RDV2";
const WIRE_LEN: usize = 36;

/// Destination-confirmed payload delivery for one compiled end-to-end route.
/// Transit nodes relay this record backwards without interpreting its sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteDeliveryFeedbackV2 {
    pub sequence: u64,
    pub route_epoch: u32,
    pub route_label: RouteLabelV2,
    pub delivered_payload_bytes: u64,
    pub interval_micros: u64,
}

impl RouteDeliveryFeedbackV2 {
    pub fn is_record(bytes: &[u8]) -> bool {
        bytes.starts_with(MAGIC)
    }

    pub fn encode(self) -> Result<Bytes> {
        ensure!(
            self.sequence != 0,
            "V2 route feedback sequence zero is reserved"
        );
        ensure!(
            self.route_epoch != 0,
            "V2 route feedback epoch zero is reserved"
        );
        RouteLabelV2::new(self.route_label.0)?;
        ensure!(
            self.interval_micros != 0,
            "V2 route feedback interval is zero"
        );
        let mut output = BytesMut::with_capacity(WIRE_LEN);
        output.extend_from_slice(MAGIC);
        output.put_u64(self.sequence);
        output.put_u32(self.route_epoch);
        output.put_u32(self.route_label.0);
        output.put_u64(self.delivered_payload_bytes);
        output.put_u64(self.interval_micros);
        Ok(output.freeze())
    }

    pub fn decode(bytes: Bytes) -> Result<Self> {
        ensure!(bytes.len() == WIRE_LEN, "invalid V2 route feedback length");
        ensure!(&bytes[..4] == MAGIC, "invalid V2 route feedback magic");
        let feedback = Self {
            sequence: u64::from_be_bytes(bytes[4..12].try_into().unwrap()),
            route_epoch: u32::from_be_bytes(bytes[12..16].try_into().unwrap()),
            route_label: RouteLabelV2::new(u32::from_be_bytes(bytes[16..20].try_into().unwrap()))?,
            delivered_payload_bytes: u64::from_be_bytes(bytes[20..28].try_into().unwrap()),
            interval_micros: u64::from_be_bytes(bytes[28..36].try_into().unwrap()),
        };
        ensure!(
            feedback.sequence != 0,
            "V2 route feedback sequence zero is reserved"
        );
        ensure!(
            feedback.route_epoch != 0,
            "V2 route feedback epoch zero is reserved"
        );
        ensure!(
            feedback.interval_micros != 0,
            "V2 route feedback interval is zero"
        );
        Ok(feedback)
    }

    pub fn delivery_rate_bps(self) -> u64 {
        (u128::from(self.delivered_payload_bytes)
            .saturating_mul(8_000_000)
            .checked_div(u128::from(self.interval_micros))
            .unwrap_or_default())
        .min(u128::from(u64::MAX)) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_delivery_feedback_round_trips_and_computes_rate() {
        let feedback = RouteDeliveryFeedbackV2 {
            sequence: 7,
            route_epoch: 9,
            route_label: RouteLabelV2::new(11).unwrap(),
            delivered_payload_bytes: 12_500_000,
            interval_micros: 1_000_000,
        };
        assert_eq!(
            RouteDeliveryFeedbackV2::decode(feedback.encode().unwrap()).unwrap(),
            feedback
        );
        assert_eq!(feedback.delivery_rate_bps(), 100_000_000);
    }
}
