//! Autotune execution, policy loading, and tuning telemetry for the V2 runtime.
//!
//! This module deliberately keeps the existing mechanical runtime lifecycle: the
//! outer runtime owns task spawning, while this module owns the complete
//! per-connection autotune loop and its policy/WASM/state helpers.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use iroh::{
    EndpointId, TransportAddr,
    endpoint::{Bbr3Tunables, Connection, ConnectionStats, ControllerSnapshot},
};
use tokio::sync::watch;
use tracing::{debug, info, warn};

use super::{
    V2RuntimeState,
    dataplane::{TX_ADMISSION_BATCH_BYTES, repair_minimum_age_for_rtt},
    status_projection::TuneStatusSampleV2,
    telemetry::{
        RemoteFeedbackSnapshot, RuntimeMetrics, SampleCounterSnapshot, StatusCounterSnapshot,
        TxByteSnapshotV2, counter_delta, histogram_percentile_micros, jain_fairness_ppm,
        path_endpoint_identity,
    },
};
use crate::{
    config::{AutotuneMode, AutotuneObjective},
    derp::DerpAddr,
    protocol::v2::{
        fec::FecGeometryV2,
        learner::{LearnerModeV2, LearnerTraceV2},
        policy::{
            api::{BbrEffectiveV1, PolicyBackend, PolicyFaultV1},
            runtime::WasmPolicyBackend,
            signature::{TrustStoreV1, encode_digest},
            state::PolicyStateStoreV1,
        },
        policy_tick::{
            PolicySlotV1, PolicyTickConfigV1, PolicyTickV1, ShadowEvaluationV2, ShadowEvaluatorV2,
            builtin_core_slot, peer_hash as policy_peer_hash,
        },
        tuning::{
            AutoTuneBoundsV2, AutoTunerV2, Bbr3PresetV2, CoverTrafficProfileV2, ForcedActionV2,
            PathReliability, PathTelemetryV2, TuneDecisionV2,
        },
        utility::{Objective, UtilitySample, WireCostV2},
    },
};

mod capacity_probe;
mod controller;
mod diagnostics;
mod loop_runtime;

use capacity_probe::*;
pub(super) use controller::LOW_RTT_CWND_FLOOR_BYTES;
use controller::*;
pub(super) use loop_runtime::tuner_loop;

#[derive(Debug, Clone, Copy)]
struct AutotuneTapSampleV2<'a> {
    sampled_unix_micros: u64,
    sample_elapsed: Duration,
    telemetry: PathTelemetryV2,
    decision: TuneDecisionV2,
    utility: UtilitySample,
    wire_cost: WireCostV2,
    force_applied: bool,
    learner: Option<LearnerTraceV2>,
    policy_id: &'a str,
    policy_source: &'a str,
    shadow_policy_id: Option<&'a str>,
    shadow: Option<ShadowEvaluationV2>,
    path_identity: &'a str,
    controller_cwnd_bytes: u64,
    adaptive_cwnd_floor_bytes: u64,
}

fn autotune_tap_record(
    peer: EndpointId,
    ticket_partition: &str,
    sample: AutotuneTapSampleV2<'_>,
) -> serde_json::Value {
    let AutotuneTapSampleV2 {
        sampled_unix_micros,
        sample_elapsed,
        telemetry,
        decision,
        utility,
        wire_cost,
        force_applied,
        learner,
        policy_id,
        policy_source,
        shadow_policy_id,
        shadow,
        path_identity,
        controller_cwnd_bytes,
        adaptive_cwnd_floor_bytes,
    } = sample;
    serde_json::json!({
        "schema_version": 5,
        "peer": peer.to_string(),
        "tls_ticket_partition": ticket_partition,
        "sampled_unix_micros": sampled_unix_micros,
        "sample_interval_micros": sample_elapsed.as_micros().min(u128::from(u64::MAX)) as u64,
        "force_applied": force_applied,
        "path_identity": path_identity,
        "controller": {
            "congestion_window_bytes": controller_cwnd_bytes,
            "adaptive_cwnd_floor_bytes": adaptive_cwnd_floor_bytes,
        },
        "policy": {
            "id": policy_id,
            "source": policy_source,
            "shadow_id": shadow_policy_id,
        },
        "telemetry": {
            "path_epoch": telemetry.path_epoch,
            "reliability": format!("{:?}", telemetry.reliability),
            "rtt_micros": telemetry.rtt.as_micros().min(u128::from(u64::MAX)) as u64,
            "min_rtt_micros": telemetry.min_rtt.as_micros().min(u128::from(u64::MAX)) as u64,
            "queue_delay_micros": telemetry.queue_delay.as_micros().min(u128::from(u64::MAX)) as u64,
            "loss_ppm": telemetry.loss_ppm,
            "burst_loss_cells": telemetry.burst_loss_cells,
            "reorder_ppm": telemetry.reorder_ppm,
            "receiver_goodput_bytes_per_second": telemetry.receiver_goodput_bytes_per_second,
            "residual_loss_ppm": telemetry.residual_loss_ppm,
            "latency_sojourn_p95_micros": telemetry.latency_sojourn_p95_micros,
            "latency_sojourn_p50_micros": telemetry.latency_sojourn_p50_micros,
            "latency_sojourn_p99_micros": telemetry.latency_sojourn_p99_micros,
            "latency_queue_recently_nonempty": telemetry.latency_queue_recently_nonempty,
            "delivery_rate_bytes_per_second": telemetry.delivery_rate_bytes_per_second,
            "controller_pacing_rate_bytes_per_second": telemetry.controller_pacing_rate_bytes_per_second,
            "controller_send_quantum_bytes": telemetry.controller_send_quantum_bytes,
            "controller_state": telemetry.controller_state,
            "controller_bw_bytes_per_second": telemetry.controller_bw_bytes_per_second,
            "controller_inflight_longterm_bytes": telemetry.controller_inflight_longterm_bytes,
            "controller_guard_transitions_delta": telemetry.controller_guard_transitions_delta,
            "controller_app_limited": telemetry.controller_app_limited,
            "controller_tunables_generation": telemetry.controller_tunables_generation,
            "controller_params_generation": telemetry.controller_params_generation,
            "controller_clamped_writes": telemetry.controller_clamped_writes,
            "receive_rate_bytes_per_second": telemetry.receive_rate_bytes_per_second,
            "packets_per_second": telemetry.packets_per_second,
            "tun_ingress_bytes_per_second": telemetry.tun_ingress_bytes_per_second,
            "average_record_bytes": telemetry.average_record_bytes,
            "gso_ingress_ratio_ppm": telemetry.gso_ingress_ratio_ppm,
            "packet_train_queue_bytes": telemetry.packet_train_queue_bytes,
            "latency_queue_bytes": telemetry.latency_queue_bytes,
            "reassembly_pressure_evictions": telemetry.reassembly_pressure_evictions,
            "remote_expired_stripes_delta": telemetry.remote_expired_stripes_delta,
            "train_build_bytes_per_second": telemetry.train_build_bytes_per_second,
            "bulk_preemption_delay_average_micros": telemetry.bulk_preemption_delay_average_micros,
            "cpu_utilization_per_mille": telemetry.cpu_utilization_per_mille,
            "wasted_parity_per_mille": telemetry.wasted_parity_per_mille,
            "fec_recovery_per_mille": telemetry.fec_recovery_per_mille,
            "repair_hit_per_mille": telemetry.repair_hit_per_mille,
            "repair_completed_requests": telemetry.repair_completed_requests,
            "repair_response_latency_micros": telemetry.repair_response_latency.as_micros().min(u128::from(u64::MAX)) as u64,
            "real_traffic_bytes_per_second": telemetry.real_traffic_bytes_per_second,
        },
        "decision": {
            "reason": format!("{:?}", decision.reason),
            "path_epoch": decision.path_epoch,
            "sample_count": decision.sample_count,
            "train_target_bytes": decision.train_target_bytes,
            "bulk_quantum_cells": decision.bulk_quantum_cells,
            "fec": decision.fec.map(|geometry| serde_json::json!({
                "data_cells": geometry.data_cells,
                "parity_cells": geometry.parity_cells,
            })),
            "repair_cache_bytes": decision.repair_cache_bytes,
            "send_buffer_bytes": decision.send_buffer_bytes,
            "receive_buffer_bytes": decision.receive_buffer_bytes,
            "receive_batch": decision.receive_batch,
            "cover_profile": format!("{:?}", decision.cover_profile),
            "cover_overhead_per_mille": decision.cover_overhead_per_mille,
            "cover_padding_bytes_per_second": decision.cover_padding_bytes_per_second,
            "bbr": {
                "preset": format!("{:?}", decision.bbr.preset),
                "up_gain_milli": decision.bbr.up_gain_milli,
                "headroom_milli": decision.bbr.headroom_milli,
                "cwnd_gain_milli": decision.bbr.cwnd_gain_milli,
                "pacing_cap_bytes_per_second": decision.bbr.pacing_cap_bytes_per_second,
                "loss_is_congestion": decision.bbr.loss_is_congestion,
            },
        },
        "utility": {
            "total": utility.total,
            "components": utility.components,
            "goodput_bytes_per_second": utility.goodput_bytes_per_second,
        },
        "wire_cost": {
            "payload_bytes": wire_cost.payload_bytes,
            "parity_bytes": wire_cost.parity_bytes,
            "repair_bytes": wire_cost.repair_bytes,
            "cover_bytes": wire_cost.cover_bytes,
            "cell_envelope_bytes": wire_cost.cell_envelope_bytes,
        },
        "learner": learner.map(|trace| serde_json::json!({
            "mode": format!("{:?}", trace.mode),
            "context": {
                "rtt_class": trace.context.rtt_class,
                "rate_class": trace.context.rate_class,
                "loss_class": trace.context.loss_class,
                "reliable": trace.context.reliable,
                "host_rtt": trace.context.host_rtt,
            },
            "baseline_preset": format!("{:?}", trace.baseline_preset),
            "proposed_preset": format!("{:?}", trace.proposed_preset),
            "applied_preset": format!("{:?}", trace.applied_preset),
            "predicted_advantage": trace.predicted_advantage,
            "exploring": trace.exploring,
            "rollback": trace.rollback,
            "rollbacks": trace.rollbacks,
            "fine_up_gain_delta_milli": trace.fine_up_gain_delta_milli,
            "fine_headroom_delta_milli": trace.fine_headroom_delta_milli,
            "fine_cwnd_gain_delta_milli": trace.fine_cwnd_gain_delta_milli,
        })),
        "shadow": shadow.map(|candidate| serde_json::json!({
            "policy_id": shadow_policy_id,
            "utility": {
                "total": candidate.utility.total,
                "components": candidate.utility.components,
                "goodput_bytes_per_second": candidate.utility.goodput_bytes_per_second,
            },
            "decision": {
                "train_target_bytes": candidate.decision.train_target_bytes,
                "bulk_quantum_cells": candidate.decision.bulk_quantum_cells,
                "fec": candidate.decision.fec.map(|geometry| serde_json::json!({
                    "data_cells": geometry.data_cells,
                    "parity_cells": geometry.parity_cells,
                })),
                "cover_profile": format!("{:?}", candidate.decision.cover_profile),
                "cover_overhead_per_mille": candidate.decision.cover_overhead_per_mille,
                "bbr": {
                    "preset": format!("{:?}", candidate.decision.bbr.preset),
                    "up_gain_milli": candidate.decision.bbr.up_gain_milli,
                    "headroom_milli": candidate.decision.bbr.headroom_milli,
                    "cwnd_gain_milli": candidate.decision.bbr.cwnd_gain_milli,
                    "pacing_cap_bytes_per_second": candidate.decision.bbr.pacing_cap_bytes_per_second,
                },
            },
            "trace": {
                "context": {
                    "rtt_class": candidate.trace.context.rtt_class,
                    "rate_class": candidate.trace.context.rate_class,
                    "loss_class": candidate.trace.context.loss_class,
                    "reliable": candidate.trace.context.reliable,
                    "host_rtt": candidate.trace.context.host_rtt,
                },
                "baseline_preset": format!("{:?}", candidate.trace.baseline_preset),
                "proposed_preset": format!("{:?}", candidate.trace.proposed_preset),
                "predicted_advantage": candidate.trace.predicted_advantage,
                "exploring": candidate.trace.exploring,
            },
        })),
    })
}

fn parse_forced_usize(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<Option<usize>> {
    object
        .get(field)
        .map(|value| {
            let number = value
                .as_u64()
                .with_context(|| format!("IRONET_AUTOTUNE_FORCE.{field} must be an integer"))?;
            usize::try_from(number)
                .with_context(|| format!("IRONET_AUTOTUNE_FORCE.{field} is too large"))
        })
        .transpose()
}

fn parse_forced_fec(value: &serde_json::Value) -> Result<Option<FecGeometryV2>> {
    if value.is_null() || value.as_str() == Some("off") {
        return Ok(None);
    }
    let geometry = if let Some(text) = value.as_str() {
        let (data, parity) = text
            .split_once('+')
            .context("IRONET_AUTOTUNE_FORCE.fec must be off or DATA+PARITY")?;
        FecGeometryV2 {
            data_cells: data
                .parse()
                .context("IRONET_AUTOTUNE_FORCE.fec data count is invalid")?,
            parity_cells: parity
                .parse()
                .context("IRONET_AUTOTUNE_FORCE.fec parity count is invalid")?,
        }
    } else {
        let object = value
            .as_object()
            .context("IRONET_AUTOTUNE_FORCE.fec must be null, a string, or an object")?;
        ensure!(
            object
                .keys()
                .all(|key| key == "data_cells" || key == "parity_cells"),
            "IRONET_AUTOTUNE_FORCE.fec has an unknown field"
        );
        FecGeometryV2 {
            data_cells: parse_forced_usize(object, "data_cells")?
                .context("IRONET_AUTOTUNE_FORCE.fec.data_cells is required")?,
            parity_cells: parse_forced_usize(object, "parity_cells")?
                .context("IRONET_AUTOTUNE_FORCE.fec.parity_cells is required")?,
        }
    };
    geometry
        .validate()
        .context("IRONET_AUTOTUNE_FORCE.fec is outside V2 geometry bounds")?;
    ensure!(
        geometry.parity_cells.saturating_mul(1_000) <= geometry.data_cells.saturating_mul(500),
        "IRONET_AUTOTUNE_FORCE.fec exceeds the 50% wire-overhead guard"
    );
    Ok(Some(geometry))
}

fn parse_autotune_force(input: &str) -> Result<ForcedActionV2> {
    let value: serde_json::Value =
        serde_json::from_str(input).context("parsing IRONET_AUTOTUNE_FORCE JSON")?;
    let object = value
        .as_object()
        .context("IRONET_AUTOTUNE_FORCE must be a JSON object")?;
    const FIELDS: [&str; 6] = [
        "bbr_preset",
        "fec",
        "train_target_bytes",
        "bulk_quantum_cells",
        "cover_profile",
        "cover_overhead_per_mille",
    ];
    ensure!(
        object.keys().all(|key| FIELDS.contains(&key.as_str())),
        "IRONET_AUTOTUNE_FORCE has an unknown field"
    );
    let cover_profile = object
        .get("cover_profile")
        .map(|value| {
            match value
                .as_str()
                .context("IRONET_AUTOTUNE_FORCE.cover_profile must be a string")?
            {
                "idle" => Ok(CoverTrafficProfileV2::Idle),
                "live-broadcast" => Ok(CoverTrafficProfileV2::LiveBroadcast),
                "interactive-video" => Ok(CoverTrafficProfileV2::InteractiveVideo),
                "generic-h3-bulk" => Ok(CoverTrafficProfileV2::GenericH3Bulk),
                _ => bail!("IRONET_AUTOTUNE_FORCE.cover_profile is unknown"),
            }
        })
        .transpose()?;
    let cover_overhead_per_mille = object
        .get("cover_overhead_per_mille")
        .map(|value| {
            let value = value
                .as_u64()
                .context("IRONET_AUTOTUNE_FORCE.cover_overhead_per_mille must be an integer")?;
            u16::try_from(value)
                .context("IRONET_AUTOTUNE_FORCE.cover_overhead_per_mille is too large")
        })
        .transpose()?;
    let bbr_preset = object
        .get("bbr_preset")
        .filter(|value| !value.is_null())
        .map(|value| {
            serde_json::from_value::<Bbr3PresetV2>(value.clone())
                .context("IRONET_AUTOTUNE_FORCE.bbr_preset is unknown")
        })
        .transpose()?;
    let forced = ForcedActionV2 {
        bbr_preset,
        fec: object.get("fec").map(parse_forced_fec).transpose()?,
        train_target_bytes: parse_forced_usize(object, "train_target_bytes")?,
        bulk_quantum_cells: parse_forced_usize(object, "bulk_quantum_cells")?,
        cover_profile,
        cover_overhead_per_mille,
    };
    ensure!(
        forced != ForcedActionV2::default(),
        "IRONET_AUTOTUNE_FORCE must override at least one action"
    );
    Ok(forced)
}

/// True only for an external component path.  The builtin policy is a
/// `PolicySpecV1` executed in-process; it never reaches `PolicyLoader`.
fn is_external_wasm_policy_path(path: &std::path::Path) -> bool {
    path.is_absolute()
        && path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("wasm"))
}

fn is_external_wasm_policy_selection(selection: &str) -> bool {
    is_external_wasm_policy_path(std::path::Path::new(selection))
}

/// Select a non-WASM live policy.  `builtin` is the default in-process core
/// learner; only an explicit `native` selection uses conservative rules.
fn non_wasm_live_slot(
    selection: &str,
    learner_mode: LearnerModeV2,
    policy_source: &mut String,
) -> PolicySlotV1 {
    match selection {
        crate::config::AUTOTUNE_POLICY_BUILTIN => builtin_core_slot(learner_mode),
        crate::config::AUTOTUNE_POLICY_NATIVE => PolicySlotV1::native_rules(),
        _ => {
            warn!(
                configured = %selection,
                "invalid non-WASM autotune policy reached the runtime; using the native conservative baseline"
            );
            *policy_source = crate::config::AUTOTUNE_POLICY_NATIVE.to_owned();
            PolicySlotV1::native_rules()
        }
    }
}

/// Plan section 8.3: a freshly loaded candidate component shadows the live
/// input for this many consecutive fault-free ticks before it is promoted at
/// a sample boundary. Any fault aborts the warmup and the last known-good
/// component stays live.
const WASM_WARMUP_TICKS: u64 = 5;

/// A verified candidate component running shadow warmup (plan section 8.3):
/// it observes the live input without influencing the wire until it has
/// survived [`WASM_WARMUP_TICKS`] fault-free ticks.
struct WasmWarmupV1 {
    evaluator: ShadowEvaluatorV2,
    /// The candidate's `state_schema_accepts` manifest list, applied when it
    /// is promoted (plan section 8.2).
    accepts: Vec<u32>,
    healthy_ticks: u64,
}

type WasmReloadResultV1 = Result<Option<(WasmPolicyBackend, [u8; 32])>>;
type WasmReloadTaskV1 = tokio::task::JoinHandle<WasmReloadResultV1>;

enum LiveReloadPhaseV1 {
    Idle,
    Loading(WasmReloadTaskV1),
    Warming(Box<WasmWarmupV1>),
}

enum ShadowReloadPhaseV1 {
    Idle,
    Loading(WasmReloadTaskV1),
}

struct PolicyReloadStateV1 {
    tick: u8,
    live_seen_hash: Option<[u8; 32]>,
    live_phase: LiveReloadPhaseV1,
    last_live_error: Option<String>,
    shadow_seen_hash: Option<[u8; 32]>,
    shadow_phase: ShadowReloadPhaseV1,
    last_shadow_error: Option<String>,
}

impl PolicyReloadStateV1 {
    fn new(
        live_seen_hash: Option<[u8; 32]>,
        shadow_seen_hash: Option<[u8; 32]>,
        last_shadow_error: Option<String>,
    ) -> Self {
        Self {
            tick: 0,
            live_seen_hash,
            live_phase: LiveReloadPhaseV1::Idle,
            last_live_error: None,
            shadow_seen_hash,
            shadow_phase: ShadowReloadPhaseV1::Idle,
            last_shadow_error,
        }
    }

    fn advance(&mut self) {
        self.tick = self.tick.wrapping_add(1);
    }

    fn scan_due(&self) -> bool {
        self.tick.is_multiple_of(5)
    }
}

/// Read and verified-load a `.wasm` policy component: read into a private
/// buffer, parse/verify against the sealed trust store, compile (cached by
/// package digest), instantiate and self-check. Also returns the whole-file
/// BLAKE3 for reload change detection. Runs synchronously; callers on a tick
/// path must offload it.
fn load_wasm_backend(
    runtime_state: &V2RuntimeState,
    path: &std::path::Path,
) -> Result<(WasmPolicyBackend, [u8; 32])> {
    ensure!(
        is_external_wasm_policy_path(path),
        "external WASM policy path must be absolute and end in .wasm: {}",
        path.display()
    );
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let file_hash = *blake3::hash(&bytes).as_bytes();
    Ok((
        load_wasm_backend_from_bytes(runtime_state, &bytes)?,
        file_hash,
    ))
}

fn load_changed_wasm_backend(
    runtime_state: &V2RuntimeState,
    path: &std::path::Path,
    seen_hash: Option<[u8; 32]>,
) -> Result<Option<(WasmPolicyBackend, [u8; 32])>> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let file_hash = *blake3::hash(&bytes).as_bytes();
    if seen_hash == Some(file_hash) {
        return Ok(None);
    }
    Ok(Some((
        load_wasm_backend_from_bytes(runtime_state, &bytes)?,
        file_hash,
    )))
}

fn load_wasm_backend_from_bytes(
    runtime_state: &V2RuntimeState,
    bytes: &[u8],
) -> Result<WasmPolicyBackend> {
    let trust = TrustStoreV1::from_config(&runtime_state.autotune.wasm)?;
    let loader = runtime_state
        .policy_loader()
        .context("policy WASM engine unavailable")?;
    let backend = loader.load_from_bytes(
        bytes,
        &runtime_state.autotune.wasm,
        &trust,
        chrono::Utc::now(),
    )?;
    Ok(backend)
}

/// Load a `.wasm` policy component into a live slot (see
/// [`load_wasm_backend`]).
fn load_wasm_live_slot(
    runtime_state: &V2RuntimeState,
    path: &std::path::Path,
) -> Result<(PolicySlotV1, [u8; 32])> {
    let (backend, file_hash) = load_wasm_backend(runtime_state, path)?;
    let digest = backend
        .identity()
        .digest
        .map(|digest| encode_digest(&digest))
        .unwrap_or_default();
    Ok((
        PolicySlotV1::new(Box::new(backend), None, digest),
        file_hash,
    ))
}

/// Shadow evaluator around a verified WASM backend: it observes the live
/// input without influencing the wire.
fn shadow_evaluator_for_backend(
    backend: WasmPolicyBackend,
    objective: Objective,
    peer_hash: [u8; 32],
) -> ShadowEvaluatorV2 {
    let identity = backend.identity().clone();
    let digest = identity
        .digest
        .map(|digest| encode_digest(&digest))
        .unwrap_or_default();
    let slot = PolicySlotV1::new(Box::new(backend), None, digest.clone());
    let mut shadow = ShadowEvaluatorV2::from_slot(
        slot,
        objective.weights(),
        objective,
        identity.policy_id,
        digest,
    );
    shadow.set_peer_hash(peer_hash);
    shadow
}

struct PolicyPersistenceV1 {
    store: Option<PolicyStateStoreV1>,
    peer: String,
    last_flush: Instant,
}

impl PolicyPersistenceV1 {
    fn new(store: Option<PolicyStateStoreV1>, peer: String, now: Instant) -> Self {
        Self {
            store,
            peer,
            last_flush: now,
        }
    }

    fn restore(&self, slot: &mut PolicySlotV1) {
        let Some(store) = &self.store else { return };
        let identity = slot.identity().clone();
        if let Some(state) = store.load(&identity.policy_id, identity.state_schema, &self.peer) {
            debug!(
                peer = %self.peer,
                policy_id = %identity.policy_id,
                state_schema = identity.state_schema,
                state_bytes = state.len(),
                "restored V2 policy state"
            );
            slot.set_state(state);
        }
    }

    fn flush(&mut self, slot: &mut PolicySlotV1, now: Instant) -> Result<()> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        if !slot.is_dirty() {
            return Ok(());
        }
        let identity = slot.identity();
        store.save(
            &identity.policy_id,
            identity.state_schema,
            &self.peer,
            slot.module_digest(),
            slot.state(),
        )?;
        slot.mark_flushed();
        self.last_flush = now;
        Ok(())
    }

    fn flush_if_due(&mut self, slot: &mut PolicySlotV1, now: Instant) -> Result<()> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        if slot.is_dirty()
            && now.saturating_duration_since(self.last_flush) >= store.flush_interval()
        {
            self.flush(slot, now)?;
        }
        Ok(())
    }
}

fn autotune_force_from_env() -> Result<Option<ForcedActionV2>> {
    match std::env::var("IRONET_AUTOTUNE_FORCE") {
        Ok(value) => parse_autotune_force(&value).map(Some),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            bail!("IRONET_AUTOTUNE_FORCE is not valid UTF-8")
        }
    }
}

/// Compatibility helper for the runtime unit test that exercises canonical
/// policy-action projection. Production ticks use `PolicyTickV1` and never
/// pass a `TuneDecisionV2` candidate directly to a data-plane applier.
#[cfg(test)]
fn constrain_learned_policy_action(
    tuner: &AutoTunerV2,
    policy: &ironet_policy_core::PolicySpecV1,
    telemetry: PathTelemetryV2,
    learned: TuneDecisionV2,
    trace: LearnerTraceV2,
) -> TuneDecisionV2 {
    if trace.mode != LearnerModeV2::On {
        return learned;
    }

    use crate::protocol::v2::policy::api::{
        CandidateActionV1, CandidateHostExt, EffectiveActionV1, EffectiveHostExt,
    };

    let mut candidate = CandidateActionV1::from_tune_decision(&learned);
    if let Some(action) =
        crate::protocol::v2::learner::forced_action_for_preset(policy, trace.applied_preset)
    {
        let application = action.to_candidate(telemetry.controller_bw_bytes_per_second);
        candidate.scheduler = application.scheduler;
        candidate.fec = application.fec;
        candidate.cover = application.cover;
    }
    let base = EffectiveActionV1::from_tune_decision(&learned);
    tuner
        .constrain_candidate(telemetry, &candidate, &base)
        .0
        .to_tune_decision()
}

const REMOTE_FEEDBACK_TTL: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Copy, Default)]
struct RemoteFeedbackRatesV2 {
    sequence: u64,
    wasted_parity_per_mille: u16,
    fec_recovery_per_mille: u16,
    repair_hit_per_mille: u16,
    repair_response_latency: Duration,
    receiver_goodput_bytes_per_second: u64,
    reorder_ppm: u32,
    residual_loss_ppm: u32,
    burst_loss_cells: u16,
    expired_stripes_delta: u64,
    repair_completed_requests: u64,
}

#[derive(Debug, Clone, Copy)]
struct RemoteFeedbackWindowV2 {
    previous: RemoteFeedbackSnapshot,
    rates: RemoteFeedbackRatesV2,
    expires_at: Instant,
}

impl RemoteFeedbackWindowV2 {
    fn capture(metrics: &RuntimeMetrics, now: Instant) -> Self {
        let sequence = metrics.remote_feedback_sequence.load(Ordering::Acquire);
        Self {
            previous: RemoteFeedbackSnapshot::capture(metrics, sequence, now),
            rates: RemoteFeedbackRatesV2 {
                sequence,
                ..RemoteFeedbackRatesV2::default()
            },
            expires_at: now,
        }
    }

    fn sample(&mut self, metrics: &RuntimeMetrics, now: Instant) -> RemoteFeedbackRatesV2 {
        let sequence = metrics.remote_feedback_sequence.load(Ordering::Acquire);
        if sequence == self.previous.sequence {
            self.rates.expired_stripes_delta = 0;
            if now >= self.expires_at {
                let sequence = self.rates.sequence;
                let repair_completed_requests = self.rates.repair_completed_requests;
                self.rates = RemoteFeedbackRatesV2 {
                    sequence,
                    repair_completed_requests,
                    ..RemoteFeedbackRatesV2::default()
                };
            }
            return self.rates;
        }

        let current = RemoteFeedbackSnapshot::capture(metrics, sequence, now);
        let delta = current.counter_delta(self.previous);
        let elapsed = now.saturating_duration_since(self.previous.at);
        let loss_runs = delta
            .loss_run_1
            .saturating_add(delta.loss_run_2)
            .saturating_add(delta.loss_run_3_4)
            .saturating_add(delta.loss_run_5_plus);
        let weighted_loss_cells = delta
            .loss_run_1
            .saturating_add(delta.loss_run_2.saturating_mul(2))
            .saturating_add(delta.loss_run_3_4.saturating_mul(4))
            .saturating_add(delta.loss_run_5_plus.saturating_mul(5));
        self.rates = RemoteFeedbackRatesV2 {
            sequence,
            wasted_parity_per_mille: ratio_per_thousand(delta.fec_wasted, delta.fec_parity),
            fec_recovery_per_mille: ratio_per_thousand(delta.fec_recovered, delta.fec_parity),
            repair_hit_per_mille: ratio_per_thousand(
                delta.repair_received,
                delta.repair_completed_requested,
            ),
            repair_response_latency: Duration::from_micros(
                delta
                    .repair_latency_micros
                    .checked_div(delta.repair_completed)
                    .unwrap_or_default(),
            ),
            receiver_goodput_bytes_per_second: rate_per_second(delta.delivered_payload, elapsed),
            reorder_ppm: ratio_per_million(delta.reorder_cells, delta.sent_data_cells),
            residual_loss_ppm: ratio_per_million(delta.missing_cells, delta.sent_data_cells),
            burst_loss_cells: weighted_loss_cells
                .checked_div(loss_runs)
                .unwrap_or_default()
                .min(u64::from(u16::MAX)) as u16,
            expired_stripes_delta: delta.expired_trains,
            repair_completed_requests: current.repair_completed,
        };
        self.previous = current;
        self.expires_at = now.checked_add(REMOTE_FEEDBACK_TTL).unwrap_or(now);
        self.rates
    }
}

struct PathTelemetryWindowV2 {
    previous: ConnectionStats,
    previous_sample_at: Instant,
    sample_counters: SampleCounterSnapshot,
    status_counters: StatusCounterSnapshot,
    identity: String,
    epoch: u64,
    previous_guard_transitions: u64,
    failures: u64,
}

impl PathTelemetryWindowV2 {
    fn capture(connection: &Connection, metrics: &RuntimeMetrics, now: Instant) -> Self {
        let previous = connection.stats();
        let tx_bytes = TxByteSnapshotV2::load(metrics, previous.udp_tx.bytes);
        let sample_counters = SampleCounterSnapshot::capture_with_tx(metrics, tx_bytes);
        Self {
            previous,
            previous_sample_at: now,
            sample_counters,
            status_counters: StatusCounterSnapshot::capture_with_tx(
                metrics,
                tx_bytes,
                sample_counters.real_bytes,
                now,
            ),
            identity: String::new(),
            epoch: 1,
            previous_guard_transitions: 0,
            failures: 0,
        }
    }
}

#[derive(Debug)]
struct SelectedPathSampleV2 {
    identity: String,
    reliability: PathReliability,
    rtt: Duration,
    congestion_window_bytes: u64,
    controller_pacing_rate_bytes_per_second: Option<u64>,
    controller_send_quantum_bytes: Option<u64>,
    controller_policer_pacing_transitions: u64,
    controller_snapshot: Option<ControllerSnapshot>,
    controller_tunables: Option<Arc<Bbr3Tunables>>,
}

fn selected_path_sample(connection: &Connection) -> Result<SelectedPathSampleV2> {
    let paths = connection.paths();
    let path = paths
        .iter()
        .find(|path| path.is_selected())
        .context("V2 connection has no selected path")?;
    let reliability = path_reliability(path.is_relay(), path.remote_addr());
    let stats = path.stats();
    let controller = connection
        .congestion_state(path.id())
        .map(|controller| controller.metrics());
    let controller_tunables = connection
        .congestion_tunables(path.id())
        .and_then(|handle| handle.downcast::<Bbr3Tunables>().ok());
    Ok(SelectedPathSampleV2 {
        identity: path_endpoint_identity(path.remote_addr()),
        reliability,
        rtt: stats.rtt,
        congestion_window_bytes: stats.cwnd,
        controller_pacing_rate_bytes_per_second: controller
            .as_ref()
            .and_then(|metrics| metrics.pacing_rate),
        controller_send_quantum_bytes: controller.as_ref().and_then(|metrics| metrics.send_quantum),
        controller_policer_pacing_transitions: controller
            .as_ref()
            .map_or(0, |metrics| metrics.policer_pacing_transitions),
        controller_snapshot: controller.as_ref().and_then(|metrics| metrics.snapshot),
        controller_tunables,
    })
}

pub(super) fn path_reliability(is_iroh_relay: bool, remote: &TransportAddr) -> PathReliability {
    if is_iroh_relay
        || matches!(
            remote,
            TransportAddr::Custom(address) if DerpAddr::from_custom(address).is_ok()
        )
    {
        PathReliability::ReliableRelay
    } else {
        PathReliability::Datagram
    }
}

fn ratio_per_million(numerator: u64, denominator: u64) -> u32 {
    if denominator == 0 {
        return 0;
    }
    numerator
        .saturating_mul(1_000_000)
        .checked_div(denominator)
        .unwrap_or(u64::MAX)
        .min(1_000_000) as u32
}

fn ratio_per_thousand(numerator: u64, denominator: u64) -> u16 {
    if denominator == 0 {
        return 0;
    }
    numerator
        .saturating_mul(1_000)
        .checked_div(denominator)
        .unwrap_or(u64::MAX)
        .min(1_000) as u16
}

#[cfg(test)]
fn ratio_scaled_u64(numerator: u64, denominator: u64, scale: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    (u128::from(numerator) * u128::from(scale) / u128::from(denominator)).min(u128::from(u64::MAX))
        as u64
}

fn rate_per_second(value: u64, elapsed: Duration) -> u64 {
    if elapsed.is_zero() {
        return 0;
    }
    (u128::from(value) * 1_000_000_000 / elapsed.as_nanos()).min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests;
