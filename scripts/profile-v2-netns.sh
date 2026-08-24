#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=${IRONETD_BIN:-$ROOT/target/profiling/ironetd}
CLI=${IRONET_BIN:-$ROOT/target/profiling/ironet}
OUT=${IRONET_V2_PROFILE_OUT:-$ROOT/target/v2-netns-profile-$(date -u +%Y%m%d-%H%M%S)}
DURATION=${IRONET_V2_PROFILE_SECONDS:-20}
PARALLEL=${IRONET_V2_PROFILE_STREAMS:-4}
PERF_FREQUENCY=${IRONET_V2_PROFILE_FREQUENCY:-99}
CALL_GRAPH=${IRONET_V2_PROFILE_CALL_GRAPH:-dwarf}
PERF=${PERF:-$(command -v perf || true)}
CPU_CORE_CPUS_FILE=${CPU_CORE_CPUS_FILE:-/sys/bus/event_source/devices/cpu_core/cpus}
CPU_ATOM_CPUS_FILE=${CPU_ATOM_CPUS_FILE:-/sys/bus/event_source/devices/cpu_atom/cpus}
IPERF3=${IPERF3:-$(command -v iperf3 || true)}
STACKCOLLAPSE=${STACKCOLLAPSE:-$(command -v stackcollapse-perf.pl || true)}
FLAMEGRAPH=${FLAMEGRAPH:-$(command -v flamegraph.pl || true)}
SHA256SUM=${SHA256SUM:-$(command -v sha256sum || true)}
DISABLE_TUN_OFFLOAD=${IRONET_V2_PROFILE_DISABLE_TUN_OFFLOAD:-0}
ETHTOOL=${ETHTOOL:-$(command -v ethtool || true)}
TC=${TC:-$(command -v tc || true)}
A_TO_B_DELAY_MS=${IRONET_V2_PROFILE_A_TO_B_DELAY_MS:-0}
A_TO_B_JITTER_MS=${IRONET_V2_PROFILE_A_TO_B_JITTER_MS:-0}
A_TO_B_DELAY_CORRELATION_PERCENT=${IRONET_V2_PROFILE_A_TO_B_DELAY_CORRELATION_PERCENT:-0}
A_TO_B_LOSS_PERCENT=${IRONET_V2_PROFILE_A_TO_B_LOSS_PERCENT:-0}
A_TO_B_LOSS_CORRELATION_PERCENT=${IRONET_V2_PROFILE_A_TO_B_LOSS_CORRELATION_PERCENT:-0}
B_TO_A_DELAY_MS=${IRONET_V2_PROFILE_B_TO_A_DELAY_MS:-0}
B_TO_A_JITTER_MS=${IRONET_V2_PROFILE_B_TO_A_JITTER_MS:-0}
B_TO_A_DELAY_CORRELATION_PERCENT=${IRONET_V2_PROFILE_B_TO_A_DELAY_CORRELATION_PERCENT:-0}
B_TO_A_LOSS_PERCENT=${IRONET_V2_PROFILE_B_TO_A_LOSS_PERCENT:-0}
B_TO_A_LOSS_CORRELATION_PERCENT=${IRONET_V2_PROFILE_B_TO_A_LOSS_CORRELATION_PERCENT:-0}
A_TO_B_RATE_MBIT=${IRONET_V2_PROFILE_A_TO_B_RATE_MBIT:-0}
B_TO_A_RATE_MBIT=${IRONET_V2_PROFILE_B_TO_A_RATE_MBIT:-0}
A_TO_B_QUEUE_PACKETS=${IRONET_V2_PROFILE_A_TO_B_QUEUE_PACKETS:-1000}
B_TO_A_QUEUE_PACKETS=${IRONET_V2_PROFILE_B_TO_A_QUEUE_PACKETS:-1000}
# netem's `limit` counts every skb retained by the qdisc, including packets
# held to emulate propagation delay and its random jitter. Reserve through the
# upper four-sigma tail of netem's normal delay distribution so declared queue
# packets remain available outside ordinary jitter variation. Underlay GSO/TSO
# is disabled below and the disposable veth MTU is 1500, so one limit slot
# models one wire packet.
NETEM_WIRE_PACKET_BYTES=1500
NETEM_NORMAL_JITTER_TAIL_SIGMAS=4
PROFILE_DIRECTION=${IRONET_V2_PROFILE_DIRECTION:-forward}
SCENARIO_NAME=${IRONET_V2_PROFILE_SCENARIO_NAME:-custom}
CONCURRENT_PING_INTERVAL_MS=${IRONET_V2_PROFILE_CONCURRENT_PING_INTERVAL_MS:-0}
FAIRNESS_SECONDS=${IRONET_V2_PROFILE_FAIRNESS_SECONDS:-0}
FAIRNESS_PER_STREAM_MBIT=${IRONET_V2_PROFILE_FAIRNESS_PER_STREAM_MBIT:-10}
COVER_SECONDS=${IRONET_V2_PROFILE_COVER_SECONDS:-0}
COVER_RATE_MBIT=${IRONET_V2_PROFILE_COVER_RATE_MBIT:-4}
PING=${PING:-$(command -v ping || true)}
TASKSET=${TASKSET:-$(command -v taskset || true)}
NICE=${NICE:-$(command -v nice || true)}
FLOCK=${FLOCK:-$(command -v flock || true)}
TIMEOUT=${TIMEOUT:-$(command -v timeout || true)}
PROFILE_NICE=${IRONET_V2_PROFILE_NICE:-10}
PROFILE_RUST_LOG=${IRONET_V2_PROFILE_RUST_LOG:-info,ironet::autotune=debug}
AUTOTUNE_FORCE=${IRONET_AUTOTUNE_FORCE:-}
AUTOTUNE_MODE=${IRONET_V2_PROFILE_AUTOTUNE_MODE:-shadow}
AUTOTUNE_OBJECTIVE=${IRONET_V2_PROFILE_AUTOTUNE_OBJECTIVE:-balanced}
AUTOTUNE_MEMORY=${IRONET_V2_PROFILE_AUTOTUNE_MEMORY:-0}
AUTOTUNE_POLICY=${IRONET_V2_PROFILE_AUTOTUNE_POLICY:-builtin}
AUTOTUNE_SHADOW_POLICY=${IRONET_V2_PROFILE_AUTOTUNE_SHADOW_POLICY:-}
PREFLIGHT_ONLY=${IRONET_V2_PROFILE_PREFLIGHT_ONLY:-0}
STARTUP_CANARY_ONLY=${IRONET_V2_PROFILE_STARTUP_CANARY_ONLY:-0}
QUEUE_DRAIN_TIMEOUT_SECONDS=${IRONET_V2_PROFILE_QUEUE_DRAIN_TIMEOUT_SECONDS:-15}
# perf/FlameGraph wrap the daemons by default. Tuner-behaviour runs (dynamic
# timelines, recordings) do not need CPU profiles; set 0 to skip perf entirely.
PERF_ENABLED=${IRONET_V2_PROFILE_PERF:-1}
# Dynamic scenario: path conditions change while the overlay saturation run is
# in progress. Format: "<offset_s>:<key>=<value>[,<key>=<value>...];<offset_s>:..."
# where offsets are whole seconds after the saturation phase starts, strictly
# increasing and smaller than IRONET_V2_PROFILE_SECONDS. Keys are
# a_delay a_jitter a_delay_corr a_loss a_loss_corr a_rate a_queue and the b_*
# equivalents, with the same units and ranges as the static variables. Every
# step re-applies the full netem state for every direction, resets that
# stage's deterministic PRNG seeds, brackets it with qdisc counters, captures
# peer status after the mutation, and is logged to timeline.tsv.
TIMELINE=${IRONET_V2_PROFILE_TIMELINE:-}
SECOND_PATH=${IRONET_V2_PROFILE_SECOND_PATH:-0}
SECOND_PATH_DELAY_MS=${IRONET_V2_PROFILE_SECOND_PATH_DELAY_MS:-30}
SECOND_PATH_LOSS_PERCENT=${IRONET_V2_PROFILE_SECOND_PATH_LOSS_PERCENT:-0}
SECOND_PATH_RATE_MBIT=${IRONET_V2_PROFILE_SECOND_PATH_RATE_MBIT:-0}
SECOND_PATH_QUEUE_PACKETS=${IRONET_V2_PROFILE_SECOND_PATH_QUEUE_PACKETS:-1000}
# A versioned base keeps netem's random loss/jitter repeatable across runs.
# Direction and timeline stage are mixed in below so the two wire directions
# and secondary path do not share one random stream.
NETEM_SEED_BASE=${IRONET_V2_PROFILE_NETEM_SEED:-20260822}
NETEM_SEED_DERIVATION_VERSION=ironet-netem-v1

expand_cpu_list() {
  local list=$1 part first last cpu
  local -a parts
  IFS=, read -r -a parts <<<"$list"
  for part in "${parts[@]}"; do
    if [[ $part == *-* ]]; then
      first=${part%-*}
      last=${part#*-}
      for ((cpu = first; cpu <= last; cpu++)); do
        printf '%s\n' "$cpu"
      done
    else
      printf '%s\n' "$part"
    fi
  done
}

ALLOWED_CPU_LIST=$(awk '/^Cpus_allowed_list:/ { print $2 }' /proc/self/status)
mapfile -t ALLOWED_CPUS < <(expand_cpu_list "$ALLOWED_CPU_LIST")
CPU_COUNT=${#ALLOWED_CPUS[@]}
((CPU_COUNT > 0)) || { echo "no CPUs available to the profiler" >&2; exit 1; }
DEFAULT_CPU_FIRST=$((CPU_COUNT / 2))
DEFAULT_CPUSET=$(IFS=,; echo "${ALLOWED_CPUS[*]:$DEFAULT_CPU_FIRST}")
PROFILE_CPUSET=${IRONET_V2_PROFILE_CPUSET:-$DEFAULT_CPUSET}

[[ -x $BIN ]] || { echo "missing profiling binary: $BIN" >&2; exit 1; }
[[ -x $CLI ]] || { echo "missing product CLI: $CLI" >&2; exit 1; }
[[ -x $SHA256SUM ]] || { echo "set SHA256SUM to sha256sum" >&2; exit 1; }
[[ -x $TASKSET ]] || { echo "set TASKSET to the taskset executable" >&2; exit 1; }
[[ -x $NICE ]] || { echo "set NICE to the nice executable" >&2; exit 1; }
[[ -x $FLOCK ]] || { echo "set FLOCK to the flock executable" >&2; exit 1; }
[[ -x $TIMEOUT ]] || { echo "set TIMEOUT to the timeout executable" >&2; exit 1; }
[[ -x $TC ]] || { echo "set TC to the tc executable" >&2; exit 1; }
[[ $PREFLIGHT_ONLY == 0 || $PREFLIGHT_ONLY == 1 ]] \
  || { echo "IRONET_V2_PROFILE_PREFLIGHT_ONLY must be 0 or 1" >&2; exit 1; }
[[ $STARTUP_CANARY_ONLY == 0 || $STARTUP_CANARY_ONLY == 1 ]] \
  || { echo "IRONET_V2_PROFILE_STARTUP_CANARY_ONLY must be 0 or 1" >&2; exit 1; }
[[ $DISABLE_TUN_OFFLOAD == 0 || $DISABLE_TUN_OFFLOAD == 1 ]] \
  || { echo "IRONET_V2_PROFILE_DISABLE_TUN_OFFLOAD must be 0 or 1" >&2; exit 1; }
[[ $SECOND_PATH == 0 || $SECOND_PATH == 1 ]] \
  || { echo "IRONET_V2_PROFILE_SECOND_PATH must be 0 or 1" >&2; exit 1; }
[[ $QUEUE_DRAIN_TIMEOUT_SECONDS =~ ^[1-9][0-9]*$ ]] \
  || { echo "invalid class queue drain timeout" >&2; exit 1; }
[[ $NETEM_SEED_BASE =~ ^[1-9][0-9]*$ ]] \
  && awk -v seed="$NETEM_SEED_BASE" 'BEGIN { exit !(seed <= 4294967295) }' \
  || { echo "IRONET_V2_PROFILE_NETEM_SEED must be an integer between 1 and 4294967295" >&2; exit 1; }
[[ $PREFLIGHT_ONLY == 0 || $STARTUP_CANARY_ONLY == 0 ]] \
  || { echo "preflight-only and startup-canary-only are mutually exclusive" >&2; exit 1; }
[[ $PERF_ENABLED == 0 || $PERF_ENABLED == 1 ]] \
  || { echo "IRONET_V2_PROFILE_PERF must be 0 or 1" >&2; exit 1; }
if [[ -n $AUTOTUNE_FORCE ]]; then
  python3 -c 'import json,sys; value=json.loads(sys.argv[1]); assert isinstance(value, dict)' \
    "$AUTOTUNE_FORCE" \
    || { echo "IRONET_AUTOTUNE_FORCE must be a JSON object" >&2; exit 1; }
fi
[[ $AUTOTUNE_MODE == off || $AUTOTUNE_MODE == shadow || $AUTOTUNE_MODE == on ]] \
  || { echo "IRONET_V2_PROFILE_AUTOTUNE_MODE must be off, shadow, or on" >&2; exit 1; }
[[ $AUTOTUNE_OBJECTIVE == balanced || $AUTOTUNE_OBJECTIVE == throughput \
  || $AUTOTUNE_OBJECTIVE == latency ]] \
  || { echo "IRONET_V2_PROFILE_AUTOTUNE_OBJECTIVE must be balanced, throughput, or latency" >&2; exit 1; }
[[ $AUTOTUNE_MEMORY == 0 || $AUTOTUNE_MEMORY == 1 ]] \
  || { echo "IRONET_V2_PROFILE_AUTOTUNE_MEMORY must be 0 or 1" >&2; exit 1; }
if [[ $AUTOTUNE_POLICY != builtin ]]; then
  [[ $AUTOTUNE_POLICY == /* && -f $AUTOTUNE_POLICY ]] \
    || { echo "IRONET_V2_PROFILE_AUTOTUNE_POLICY must be builtin or an existing absolute path" >&2; exit 1; }
fi
if [[ -n $AUTOTUNE_SHADOW_POLICY ]]; then
  [[ $AUTOTUNE_SHADOW_POLICY == /* && -f $AUTOTUNE_SHADOW_POLICY ]] \
    || { echo "IRONET_V2_PROFILE_AUTOTUNE_SHADOW_POLICY must be an existing absolute path" >&2; exit 1; }
fi
# The daemon is exec'd directly (no perf parent) in canary mode and when perf
# is disabled; PID verification and signalling must then target the daemon.
DAEMON_DIRECT=0
[[ $STARTUP_CANARY_ONLY == 1 || $PERF_ENABLED == 0 ]] && DAEMON_DIRECT=1
if [[ $PREFLIGHT_ONLY == 0 && $STARTUP_CANARY_ONLY == 0 ]]; then
  [[ -x $IPERF3 ]] || { echo "set IPERF3 to the iperf3 executable" >&2; exit 1; }
  if [[ $PERF_ENABLED == 1 ]]; then
    [[ -x $PERF ]] || { echo "set PERF to the perf executable" >&2; exit 1; }
    [[ -x $STACKCOLLAPSE ]] || { echo "set STACKCOLLAPSE to stackcollapse-perf.pl" >&2; exit 1; }
    [[ -x $FLAMEGRAPH ]] || { echo "set FLAMEGRAPH to flamegraph.pl" >&2; exit 1; }
  fi
fi
[[ $PERF_FREQUENCY =~ ^[1-9][0-9]*$ ]] || { echo "invalid perf sampling frequency" >&2; exit 1; }
[[ $CALL_GRAPH == dwarf || $CALL_GRAPH == fp || $CALL_GRAPH == lbr ]] \
  || { echo "invalid perf call graph mode: $CALL_GRAPH" >&2; exit 1; }

# netem parameter validators. The same rules apply to the static scenario and
# to every timeline step, so a dynamic scenario can never express a channel
# that a static one could not.
validate_netem_number() {
  [[ $2 =~ ^[0-9]+([.][0-9]+)?$ ]] \
    || { echo "invalid netem $1 value: $2" >&2; return 1; }
}
validate_netem_delay_correlation() {
  validate_netem_number "$1" "$2" || return 1
  awk -v value="$2" 'BEGIN { exit !(value >= 0 && value <= 100) }' \
    || { echo "netem correlation must be between 0 and 100: $2" >&2; return 1; }
}
validate_netem_loss_correlation() {
  validate_netem_number "$1" "$2" || return 1
  awk -v value="$2" 'BEGIN { exit !(value >= 0 && value < 100) }' \
    || { echo "loss burst correlation must be between 0 and 100: $2" >&2; return 1; }
}
validate_netem_loss() {
  validate_netem_number "$1" "$2" || return 1
  awk -v value="$2" 'BEGIN { exit !(value >= 0 && value < 100) }' \
    || { echo "netem loss must be between 0 and 100: $2" >&2; return 1; }
}
validate_netem_queue() {
  [[ $2 =~ ^[1-9][0-9]*$ ]] \
    || { echo "netem queue limit must be a positive packet count: $2" >&2; return 1; }
}

# Upper normal-delay envelope used to reserve netem slots. Four standard
# deviations cover ordinary jitter without granting unbounded capacity to the
# theoretical normal tail.
netem_propagation_envelope_ms() {
  awk -v delay_ms="$1" -v jitter_ms="$2" \
    -v tail_sigmas="$NETEM_NORMAL_JITTER_TAIL_SIGMAS" \
    'BEGIN { printf "%.9g\n", delay_ms + tail_sigmas * jitter_ms }'
}

# Packet slots consumed by the one-way propagation envelope BDP. A rate of
# zero means the harness has not declared a bottleneck capacity, so there is
# no finite modeled BDP to add. Round up: even a partial packet occupies one
# netem queue slot.
netem_propagation_packets() {
  awk -v delay_ms="$1" -v jitter_ms="$2" -v rate_mbit="$3" \
    -v tail_sigmas="$NETEM_NORMAL_JITTER_TAIL_SIGMAS" \
    -v packet_bytes="$NETEM_WIRE_PACKET_BYTES" '
    BEGIN {
      envelope_ms = delay_ms + tail_sigmas * jitter_ms
      if (envelope_ms == 0 || rate_mbit == 0) {
        print 0
        exit
      }
      packets = rate_mbit * 1000000 * envelope_ms / 1000 / 8 / packet_bytes
      whole = int(packets)
      print whole + (packets > whole ? 1 : 0)
    }
  '
}

netem_state_record() {
  local delay_ms=$1 jitter_ms=$2 delay_corr=$3 loss=$4 loss_corr=$5 rate_mbit=$6
  local queue_packets=$7 propagation_envelope_ms propagation_packets limit_packets
  propagation_envelope_ms=$(netem_propagation_envelope_ms "$delay_ms" "$jitter_ms")
  propagation_packets=$(netem_propagation_packets "$delay_ms" "$jitter_ms" "$rate_mbit")
  limit_packets=$((queue_packets + propagation_packets))
  printf 'delay=%s,jitter=%s,delay_corr=%s,loss=%s,loss_corr=%s,rate=%s,queue=%s,normal_jitter_tail_sigmas=%s,propagation_envelope_ms=%s,propagation_packets=%s,limit_packets=%s' \
    "$delay_ms" "$jitter_ms" "$delay_corr" "$loss" "$loss_corr" "$rate_mbit" \
    "$queue_packets" "$NETEM_NORMAL_JITTER_TAIL_SIGMAS" "$propagation_envelope_ms" \
    "$propagation_packets" "$limit_packets"
}
# Validate one timeline/static key. Keys use the short catalog names.
validate_netem_key() {
  local key=$1 value=$2
  case $key in
    a_delay | b_delay | a_jitter | b_jitter | a_rate | b_rate)
      validate_netem_number "$key" "$value" ;;
    a_delay_corr | b_delay_corr) validate_netem_delay_correlation "$key" "$value" ;;
    a_loss | b_loss) validate_netem_loss "$key" "$value" ;;
    a_loss_corr | b_loss_corr) validate_netem_loss_correlation "$key" "$value" ;;
    a_queue | b_queue) validate_netem_queue "$key" "$value" ;;
    primary | secondary)
      [[ $value == up || $value == down ]] \
        || { echo "$key path state must be up or down: $value" >&2; return 1; } ;;
    *) echo "unknown netem key: $key" >&2; return 1 ;;
  esac
}
validate_netem_key a_delay "$A_TO_B_DELAY_MS"
validate_netem_key a_jitter "$A_TO_B_JITTER_MS"
validate_netem_key a_delay_corr "$A_TO_B_DELAY_CORRELATION_PERCENT"
validate_netem_key a_loss "$A_TO_B_LOSS_PERCENT"
validate_netem_key a_loss_corr "$A_TO_B_LOSS_CORRELATION_PERCENT"
validate_netem_key a_rate "$A_TO_B_RATE_MBIT"
validate_netem_key a_queue "$A_TO_B_QUEUE_PACKETS"
validate_netem_key b_delay "$B_TO_A_DELAY_MS"
validate_netem_key b_jitter "$B_TO_A_JITTER_MS"
validate_netem_key b_delay_corr "$B_TO_A_DELAY_CORRELATION_PERCENT"
validate_netem_key b_loss "$B_TO_A_LOSS_PERCENT"
validate_netem_key b_loss_corr "$B_TO_A_LOSS_CORRELATION_PERCENT"
validate_netem_key b_rate "$B_TO_A_RATE_MBIT"
validate_netem_key b_queue "$B_TO_A_QUEUE_PACKETS"
validate_netem_number second_delay "$SECOND_PATH_DELAY_MS"
validate_netem_loss second_loss "$SECOND_PATH_LOSS_PERCENT"
validate_netem_number second_rate "$SECOND_PATH_RATE_MBIT"
validate_netem_queue second_queue "$SECOND_PATH_QUEUE_PACKETS"
A_TO_B_PROPAGATION_ENVELOPE_MS=$(netem_propagation_envelope_ms \
  "$A_TO_B_DELAY_MS" "$A_TO_B_JITTER_MS")
B_TO_A_PROPAGATION_ENVELOPE_MS=$(netem_propagation_envelope_ms \
  "$B_TO_A_DELAY_MS" "$B_TO_A_JITTER_MS")
SECOND_PATH_PROPAGATION_ENVELOPE_MS=$(netem_propagation_envelope_ms \
  "$SECOND_PATH_DELAY_MS" 0)
A_TO_B_PROPAGATION_PACKETS=$(netem_propagation_packets \
  "$A_TO_B_DELAY_MS" "$A_TO_B_JITTER_MS" "$A_TO_B_RATE_MBIT")
B_TO_A_PROPAGATION_PACKETS=$(netem_propagation_packets \
  "$B_TO_A_DELAY_MS" "$B_TO_A_JITTER_MS" "$B_TO_A_RATE_MBIT")
SECOND_PATH_PROPAGATION_PACKETS=$(netem_propagation_packets \
  "$SECOND_PATH_DELAY_MS" 0 "$SECOND_PATH_RATE_MBIT")
A_TO_B_NETEM_LIMIT_PACKETS=$((A_TO_B_QUEUE_PACKETS + A_TO_B_PROPAGATION_PACKETS))
B_TO_A_NETEM_LIMIT_PACKETS=$((B_TO_A_QUEUE_PACKETS + B_TO_A_PROPAGATION_PACKETS))
SECOND_PATH_NETEM_LIMIT_PACKETS=$((SECOND_PATH_QUEUE_PACKETS + SECOND_PATH_PROPAGATION_PACKETS))

# Parse and validate the dynamic timeline up front so a malformed step can
# never abort a run after the namespaces and daemons exist.
TIMELINE_OFFSETS=()
TIMELINE_CHANGES=()
TIMELINE_HAS_PATH_ACTION=0
if [[ -n $TIMELINE ]]; then
  [[ $DURATION =~ ^[1-9][0-9]*$ ]] || { echo "invalid profile duration" >&2; exit 1; }
  previous_offset=0
  IFS=';' read -r -a timeline_steps <<<"$TIMELINE"
  for step in "${timeline_steps[@]}"; do
    [[ -n $step ]] || continue
    [[ $step == *:* ]] || { echo "timeline step needs <offset>:<changes>: $step" >&2; exit 1; }
    offset=${step%%:*}
    changes=${step#*:}
    [[ $offset =~ ^[1-9][0-9]*$ ]] \
      || { echo "timeline offset must be a positive whole second: $offset" >&2; exit 1; }
    ((offset > previous_offset)) \
      || { echo "timeline offsets must strictly increase: $offset" >&2; exit 1; }
    ((offset < DURATION)) \
      || { echo "timeline offset $offset must be smaller than duration $DURATION" >&2; exit 1; }
    [[ -n $changes ]] || { echo "timeline step has no changes: $step" >&2; exit 1; }
    IFS=',' read -r -a change_list <<<"$changes"
    for change in "${change_list[@]}"; do
      [[ $change == *=* ]] || { echo "timeline change needs key=value: $change" >&2; exit 1; }
      validate_netem_key "${change%%=*}" "${change#*=}" || exit 1
      if [[ ${change%%=*} == primary || ${change%%=*} == secondary ]]; then
        TIMELINE_HAS_PATH_ACTION=1
        [[ $SECOND_PATH == 1 ]] \
          || { echo "path timeline actions require IRONET_V2_PROFILE_SECOND_PATH=1" >&2; exit 1; }
      fi
    done
    TIMELINE_OFFSETS+=("$offset")
    TIMELINE_CHANGES+=("$changes")
    previous_offset=$offset
  done
  ((${#TIMELINE_OFFSETS[@]} > 0)) || { echo "timeline is empty" >&2; exit 1; }
fi
[[ $PROFILE_DIRECTION == forward || $PROFILE_DIRECTION == reverse ]] \
  || { echo "profile direction must be forward or reverse" >&2; exit 1; }
[[ $SCENARIO_NAME =~ ^[a-zA-Z0-9._-]+$ ]] \
  || { echo "scenario name contains unsupported characters" >&2; exit 1; }
[[ $CONCURRENT_PING_INTERVAL_MS =~ ^[0-9]+$ ]] \
  || { echo "invalid concurrent ping interval" >&2; exit 1; }
[[ $FAIRNESS_SECONDS =~ ^[0-9]+$ ]] \
  || { echo "invalid fairness duration" >&2; exit 1; }
[[ $FAIRNESS_PER_STREAM_MBIT =~ ^[0-9]+([.][0-9]+)?$ ]] \
  || { echo "invalid fairness per-stream rate" >&2; exit 1; }
[[ $COVER_SECONDS =~ ^[0-9]+$ ]] \
  || { echo "invalid cover profile duration" >&2; exit 1; }
[[ $COVER_RATE_MBIT =~ ^[0-9]+([.][0-9]+)?$ ]] \
  || { echo "invalid cover profile rate" >&2; exit 1; }
[[ $PROFILE_NICE =~ ^(0|[1-9]|1[0-9])$ ]] \
  || { echo "profile nice level must be between 0 and 19" >&2; exit 1; }
"$TASKSET" -c "$PROFILE_CPUSET" true 2>/dev/null \
  || { echo "invalid or unavailable profile CPU set: $PROFILE_CPUSET" >&2; exit 1; }
if [[ $CONCURRENT_PING_INTERVAL_MS != 0 ]]; then
  [[ -x $PING ]] || { echo "set PING when enabling concurrent latency sampling" >&2; exit 1; }
fi
[[ -x $ETHTOOL ]] || { echo "set ETHTOOL to model wire packets after GSO segmentation" >&2; exit 1; }
sudo -n true

# Only one host-level profiler may run at a time. Contention between two
# otherwise isolated netns labs can still starve the management plane.
exec 9>"${TMPDIR:-/tmp}/ironet-v2-profile.lock"
"$FLOCK" -n 9 || { echo "another Ironet V2 profile is active" >&2; exit 1; }

mkdir -p "$OUT"
OUT=$(realpath "$OUT")
BINARY_SHA256=$($SHA256SUM "$BIN" | awk '{print $1}')
CLI_SHA256=$($SHA256SUM "$CLI" | awk '{print $1}')
printf '%s  %s\n' "$BINARY_SHA256" "$(realpath "$BIN")" >"$OUT/binary.sha256"
printf '%s  %s\n' "$CLI_SHA256" "$(realpath "$CLI")" >>"$OUT/binary.sha256"
printf 'cpuset=%s\nnice=%s\nperf_frequency_hz=%s\n' \
  "$PROFILE_CPUSET" "$PROFILE_NICE" "$PERF_FREQUENCY" >"$OUT/resource-isolation.txt"
printf 'scenario=%s\ndirection=%s\nrate_model=netem_serializing_shallow_shaper\n' \
  "$SCENARIO_NAME" "$PROFILE_DIRECTION" \
  >"$OUT/scenario.txt"
printf '{"derivation_version":"%s","base_seed":%s}\n' \
  "$NETEM_SEED_DERIVATION_VERSION" "$NETEM_SEED_BASE" >"$OUT/netem-seed-provenance.json"
printf 'stage\tdirection\tnamespace\tdevice\tseed\tmode\tqueue_packets\tdelay_ms\tjitter_ms\tnormal_jitter_tail_sigmas\tpropagation_envelope_ms\tpropagation_packets\tlimit_packets\n' \
  >"$OUT/netem-seeds.tsv"
printf '{"enabled":%s,"delay_ms":%s,"jitter_ms":0,"loss_percent":%s,"rate_mbit":%s,"rate_model":"netem_serializing_shallow_shaper","queue_packets":%s,"queue_packets_semantics":"excess_beyond_normal_delay_tail_envelope","normal_jitter_tail_sigmas":%s,"propagation_envelope_ms":%s,"propagation_packets":%s,"limit_packets":%s,"wire_packet_bytes":%s}\n' \
  "$( [[ $SECOND_PATH == 1 ]] && echo true || echo false )" \
  "$SECOND_PATH_DELAY_MS" "$SECOND_PATH_LOSS_PERCENT" "$SECOND_PATH_RATE_MBIT" \
  "$SECOND_PATH_QUEUE_PACKETS" "$NETEM_NORMAL_JITTER_TAIL_SIGMAS" \
  "$SECOND_PATH_PROPAGATION_ENVELOPE_MS" "$SECOND_PATH_PROPAGATION_PACKETS" \
  "$SECOND_PATH_NETEM_LIMIT_PACKETS" "$NETEM_WIRE_PACKET_BYTES" \
  >"$OUT/second-path.json"
if [[ -n $AUTOTUNE_FORCE ]]; then
  printf '%s\n' "$AUTOTUNE_FORCE" >"$OUT/autotune-force.json"
fi
NS="v2-prof-$$"
NSA="$NS-a"
NSB="$NS-b"
LINK="v2p$(( $$ % 100000 ))"
LINK2="${LINK}x"
PORT=$((20000 + $$ % 20000))
printf -v UNDERLAY_A 'fd76::%x' "$((($$ % 30000) + 1))"
printf -v UNDERLAY_B 'fd76::%x' "$((($$ % 30000) + 2))"
printf -v UNDERLAY_A2 'fd77::%x' "$((($$ % 30000) + 1))"
printf -v UNDERLAY_B2 'fd77::%x' "$((($$ % 30000) + 2))"
A_PID=
B_PID=
A_LAUNCH=
B_LAUNCH=
PING_PID=
UNDERLAY_PING_PID=
UNDERLAY_TIMELINE_PID=
UNDERLAY_TIMELINE_RAN=0
FAIRNESS_SERVER=
COVER_SERVER=
GUARD_BEFORE="$OUT/management-plane.before"
GUARD_AFTER="$OUT/management-plane.after"

capture_management_plane() {
  local output=$1
  {
    echo '[route-200]'
    ip -6 route show table all 200::/7 2>/dev/null || true
    echo '[tun-ygg-link]'
    ip -details link show dev tun-ygg 2>/dev/null || true
    echo '[tun-ygg-addresses]'
    ip -6 address show dev tun-ygg 2>/dev/null || true
    echo '[tun-ygg-qdisc]'
    "$TC" qdisc show dev tun-ygg 2>/dev/null || true
  } >"$output"
}

verify_management_plane() {
  capture_management_plane "$GUARD_AFTER"
  if ! cmp -s "$GUARD_BEFORE" "$GUARD_AFTER"; then
    diff -u "$GUARD_BEFORE" "$GUARD_AFTER" >"$OUT/management-plane.diff" || true
    echo "management-plane invariant changed; see $OUT/management-plane.diff" >&2
    return 1
  fi
}

capture_management_plane "$GUARD_BEFORE"

profile_pid_is_safe() {
  local pid=${1:-}
  [[ $pid =~ ^[0-9]+$ && $pid -gt 2 ]] || return 1
  [[ -r /proc/$pid/cmdline ]] || return 1
  # Require both the profiler and this exact benchmark binary in argv before
  # any privileged signal is sent to a host PID.
  if [[ $DAEMON_DIRECT == 1 ]]; then
    tr '\0' '\n' <"/proc/$pid/cmdline" | grep -Fqx -- "$BIN"
  else
    tr '\0' '\n' <"/proc/$pid/cmdline" | grep -Fqx -- "$PERF" \
      && tr '\0' '\n' <"/proc/$pid/cmdline" | grep -Fqx -- "$BIN"
  fi
}

stop_profiled() {
  local perf_pid=${1:-} launch_pid=${2:-}
  [[ -n $perf_pid ]] || return 0
  if ! sudo kill -0 "$perf_pid" 2>/dev/null; then
    [[ -n $launch_pid ]] && wait "$launch_pid" 2>/dev/null || true
    return 0
  fi
  if ! profile_pid_is_safe "$perf_pid"; then
    echo "refusing to signal unverified host PID: $perf_pid" >&2
    return 1
  fi
  local children
  children=$(pgrep -P "$perf_pid" 2>/dev/null || true)
  for _ in $(seq 1 100); do
    sudo kill -0 "$perf_pid" 2>/dev/null || break
    sleep 0.1
  done
  if sudo kill -0 "$perf_pid" 2>/dev/null; then
    sudo kill -TERM -- "$perf_pid" $children 2>/dev/null || true
    sleep 0.2
  fi
  if sudo kill -0 "$perf_pid" 2>/dev/null; then
    sudo kill -KILL -- "$perf_pid" $children 2>/dev/null || true
  fi
  [[ -n $launch_pid ]] && wait "$launch_pid" 2>/dev/null || true
}

stop_profiled_pair() {
  # Signal both endpoints before waiting for either one. A graceful close from
  # one side otherwise makes its peer report a dataplane failure at shutdown.
  local a_children= b_children= status=0
  # Never substitute PID 0 here: `pgrep -P 0` selects host init/kernel
  # processes and a following privileged kill would hit the management plane.
  if [[ -n ${A_PID:-} ]] && profile_pid_is_safe "$A_PID"; then
    if [[ $DAEMON_DIRECT == 1 ]]; then
      a_children=$A_PID
    else
      a_children=$(pgrep -P "$A_PID" 2>/dev/null || true)
    fi
  fi
  if [[ -n ${B_PID:-} ]] && profile_pid_is_safe "$B_PID"; then
    if [[ $DAEMON_DIRECT == 1 ]]; then
      b_children=$B_PID
    else
      b_children=$(pgrep -P "$B_PID" 2>/dev/null || true)
    fi
  fi
  if [[ -n $a_children || -n $b_children ]]; then
    # One kill(2) request makes the delivery window materially smaller than
    # two sequential sudo invocations.
    sudo kill -INT -- $a_children $b_children 2>/dev/null || true
  fi
  stop_profiled "$A_PID" "$A_LAUNCH" || status=1
  stop_profiled "$B_PID" "$B_LAUNCH" || status=1
  return "$status"
}

cleanup() {
  local status=0 restore_errexit=0 netns_list=
  [[ $- == *e* ]] && restore_errexit=1
  set +e
  [[ -z ${TIMELINE_PID:-} ]] || kill "$TIMELINE_PID" 2>/dev/null || true
  [[ -z ${UNDERLAY_TIMELINE_PID:-} ]] || kill "$UNDERLAY_TIMELINE_PID" 2>/dev/null || true
  [[ -z ${PING_PID:-} ]] || sudo kill "$PING_PID" 2>/dev/null || true
  [[ -z ${UNDERLAY_PING_PID:-} ]] || sudo kill "$UNDERLAY_PING_PID" 2>/dev/null || true
  [[ -z ${FAIRNESS_SERVER:-} ]] || kill "$FAIRNESS_SERVER" 2>/dev/null || true
  [[ -z ${COVER_SERVER:-} ]] || kill "$COVER_SERVER" 2>/dev/null || true
  stop_profiled_pair || status=1
  netns_list=$(sudo ip netns list 2>/dev/null) || status=1
  if awk '{print $1}' <<<"$netns_list" | grep -Fqx -- "$NSA"; then
    sudo ip netns del "$NSA" 2>/dev/null || status=1
  fi
  if awk '{print $1}' <<<"$netns_list" | grep -Fqx -- "$NSB"; then
    sudo ip netns del "$NSB" 2>/dev/null || status=1
  fi
  [[ -z ${A_SOCKET:-} || ! -e ${A_SOCKET:-} ]] \
    || sudo unlink "$A_SOCKET" 2>/dev/null || status=1
  [[ -z ${B_SOCKET:-} || ! -e ${B_SOCKET:-} ]] \
    || sudo unlink "$B_SOCKET" 2>/dev/null || status=1
  ((restore_errexit == 0)) || set -e
  return "$status"
}

on_exit() {
  local status=$? cleanup_status=0
  trap - EXIT INT TERM HUP
  cleanup || cleanup_status=$?
  if ((status == 0 && cleanup_status != 0)); then
    status=96
  fi
  if ! verify_management_plane; then
    ((status != 0)) || status=97
  fi
  exit "$status"
}
trap on_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

sudo ip netns add "$NSA"
sudo ip netns add "$NSB"
sudo ip link add "$LINK-a" type veth peer name "$LINK-b"
sudo ip link set "$LINK-a" netns "$NSA"
sudo ip link set "$LINK-b" netns "$NSB"
if [[ $SECOND_PATH == 1 ]]; then
  sudo ip link add "$LINK2-a" type veth peer name "$LINK2-b"
  sudo ip link set "$LINK2-a" netns "$NSA"
  sudo ip link set "$LINK2-b" netns "$NSB"
fi
sudo ip -n "$NSA" link set lo up
sudo ip -n "$NSB" link set lo up
# An administrative IPv6 link-down deletes global addresses by default on
# Linux. That models address withdrawal, not a temporary underlay outage, and
# makes failback impossible because the old four-tuple no longer exists. Keep
# the lab locators across the deliberate flap so `primary=down/up` exercises
# QUIC path recovery; address-renumbering is covered as a separate scenario.
sudo ip netns exec "$NSA" sysctl -qw "net.ipv6.conf.$LINK-a.keep_addr_on_down=1"
sudo ip netns exec "$NSB" sysctl -qw "net.ipv6.conf.$LINK-b.keep_addr_on_down=1"
sudo ip -n "$NSA" -6 addr add "$UNDERLAY_A/64" dev "$LINK-a" nodad
sudo ip -n "$NSB" -6 addr add "$UNDERLAY_B/64" dev "$LINK-b" nodad
if [[ $SECOND_PATH == 1 ]]; then
  sudo ip netns exec "$NSA" sysctl -qw "net.ipv6.conf.$LINK2-a.keep_addr_on_down=1"
  sudo ip netns exec "$NSB" sysctl -qw "net.ipv6.conf.$LINK2-b.keep_addr_on_down=1"
  sudo ip -n "$NSA" -6 addr add "$UNDERLAY_A2/64" dev "$LINK2-a" nodad
  sudo ip -n "$NSB" -6 addr add "$UNDERLAY_B2/64" dev "$LINK2-b" nodad
fi
sudo ip -n "$NSA" link set "$LINK-a" up
sudo ip -n "$NSB" link set "$LINK-b" up
if [[ $SECOND_PATH == 1 ]]; then
  sudo ip -n "$NSA" link set "$LINK2-a" up
  sudo ip -n "$NSB" link set "$LINK2-b" up
fi

# netem otherwise sees a UDP GSO super-packet as one loss unit. A nominal
# 0.2% WAN loss can then erase dozens of QUIC packets at once and manufacture
# a much harsher channel than a physical ISP/Wi-Fi link, where segmentation
# precedes wire loss. Disable offload only on the disposable underlay veths;
# ironet0 keeps product GSO/GRO so the daemon profile remains production-like.
sudo ip netns exec "$NSA" "$ETHTOOL" -K "$LINK-a" tso off gso off gro off
sudo ip netns exec "$NSB" "$ETHTOOL" -K "$LINK-b" tso off gso off gro off
sudo ip netns exec "$NSA" "$ETHTOOL" -k "$LINK-a" >"$OUT/a-underlay-features.txt"
sudo ip netns exec "$NSB" "$ETHTOOL" -k "$LINK-b" >"$OUT/b-underlay-features.txt"
if [[ $SECOND_PATH == 1 ]]; then
  sudo ip netns exec "$NSA" "$ETHTOOL" -K "$LINK2-a" tso off gso off gro off
  sudo ip netns exec "$NSB" "$ETHTOOL" -K "$LINK2-b" tso off gso off gro off
  sudo ip netns exec "$NSA" "$ETHTOOL" -k "$LINK2-a" >"$OUT/a-underlay2-features.txt"
  sudo ip netns exec "$NSB" "$ETHTOOL" -k "$LINK2-b" >"$OUT/b-underlay2-features.txt"
fi

netem_direction() {
  local namespace=$1 device=$2
  case "$namespace:$device" in
    "$NSA:$LINK-a") printf '%s\n' a-to-b ;;
    "$NSB:$LINK-b") printf '%s\n' b-to-a ;;
    "$NSA:$LINK2-a") printf '%s\n' secondary-a-to-b ;;
    "$NSB:$LINK2-b") printf '%s\n' secondary-b-to-a ;;
    *) echo "unknown profile netem direction: $namespace:$device" >&2; return 1 ;;
  esac
}

# Keep a stage's random sequence independent of process IDs/output paths.
# Underlay TCP and overlay runs intentionally receive the same direction/stage
# seed. This aligns their PRNG starting state; differing packetization means it
# does not claim identical packet-level loss or delay outcomes.
netem_seed() {
  local direction=$1 stage=$2 digest
  digest=$(printf '%s\0%s\0%s\0%s\n' \
    "$NETEM_SEED_DERIVATION_VERSION" "$NETEM_SEED_BASE" "$direction" "$stage" \
    | "$SHA256SUM" | awk '{print substr($1, 1, 8)}')
  printf '%u\n' "$(( (16#$digest % 4294967294) + 1 ))"
}

apply_netem() {
  local namespace=$1 device=$2 delay_ms=$3 jitter_ms=$4 delay_correlation=$5
  local loss_percent=$6 loss_correlation=$7 rate_mbit=$8 queue_packets=$9
  local mode=${10:-initial} stage=${11:-bootstrap-0}
  local direction seed qdisc propagation_envelope_ms propagation_packets limit_packets
  # The initial static scenario leaves a clean veth when nothing is requested.
  # A timeline step must always replace the root qdisc so that "back to
  # unimpaired" actually removes the previous delay/loss/rate; a netem with
  # only a packet limit is a pass-through queue.
  if [[ $mode == initial ]]; then
    [[ $delay_ms != 0 || $jitter_ms != 0 || $loss_percent != 0 || $rate_mbit != 0 ]] \
      || return 0
  fi
  [[ $namespace == "$NSA" || $namespace == "$NSB" ]] \
    || { echo "refusing netem outside the profile namespaces" >&2; return 1; }
  [[ $device == "$LINK-a" || $device == "$LINK-b" \
    || $device == "$LINK2-a" || $device == "$LINK2-b" ]] \
    || { echo "refusing netem on a non-profile interface" >&2; return 1; }
  direction=$(netem_direction "$namespace" "$device")
  seed=$(netem_seed "$direction" "$stage")
  local args=(netem)
  if [[ $delay_ms != 0 || $jitter_ms != 0 ]]; then
    args+=(delay "${delay_ms}ms")
    if [[ $jitter_ms != 0 ]]; then
      args+=("${jitter_ms}ms" "${delay_correlation}%" distribution normal)
    fi
  fi
  if [[ $loss_percent != 0 ]]; then
    if [[ $loss_correlation == 0 ]]; then
      args+=(loss random "${loss_percent}%")
    else
      # netem's `random P correlation` is an autoregressive random-number
      # correlation, not a packet-loss Markov chain; high values can produce
      # almost no drops for an entire short profile. Convert the requested
      # persistence into a Gilbert-Elliott chain whose stationary loss is P:
      # bad->good = 1-correlation, good->bad = P*r/(1-P). Bad packets are
      # dropped and good packets are kept, so both mean loss and burst length
      # are explicit and repeatable across scenario durations.
      local gemodel_exit gemodel_enter
      gemodel_exit=$(awk -v correlation="$loss_correlation" \
        'BEGIN { printf "%.6f", 100 - correlation }')
      gemodel_enter=$(awk -v loss="$loss_percent" -v leave="$gemodel_exit" \
        'BEGIN { printf "%.6f", loss * leave / (100 - loss) }')
      args+=(loss gemodel "${gemodel_enter}%" "${gemodel_exit}%" 100% 0%)
    fi
  fi
  if [[ $rate_mbit != 0 ]]; then
    args+=(rate "${rate_mbit}mbit")
  fi
  # netem's limit includes packets retained solely for delay emulation. Keep
  # the catalog value as actual queue capacity beyond the four-sigma normal
  # delay envelope; reserving only nominal delay lets positive jitter steal
  # queue slots and manufacture shallow-queue loss.
  propagation_envelope_ms=$(netem_propagation_envelope_ms "$delay_ms" "$jitter_ms")
  propagation_packets=$(netem_propagation_packets "$delay_ms" "$jitter_ms" "$rate_mbit")
  limit_packets=$((queue_packets + propagation_packets))
  args+=(limit "$limit_packets" seed "$seed")
  sudo ip netns exec "$namespace" "$TC" qdisc replace dev "$device" root "${args[@]}"
  qdisc=$(sudo ip netns exec "$namespace" "$TC" qdisc show dev "$device")
  grep -Eq "(^|[[:space:]])seed[[:space:]]$seed([[:space:]]|$)" <<<"$qdisc" \
    || { echo "netem seed assertion failed for $direction/$stage: expected $seed" >&2; return 1; }
  grep -Eq "(^|[[:space:]])limit[[:space:]]$limit_packets([[:space:]]|$)" <<<"$qdisc" \
    || { echo "netem limit assertion failed for $direction/$stage: expected $limit_packets" >&2; return 1; }
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$stage" "$direction" "$namespace" "$device" "$seed" "$mode" \
    "$queue_packets" "$delay_ms" "$jitter_ms" "$NETEM_NORMAL_JITTER_TAIL_SIGMAS" \
    "$propagation_envelope_ms" "$propagation_packets" "$limit_packets" \
    >>"$OUT/netem-seeds.tsv"
}

# netem is attached to each sender's egress. These names therefore describe
# actual direction rather than the receiving namespace, which is critical for
# reproducing asymmetric p2 -> wuwei-ws loss.
apply_netem "$NSA" "$LINK-a" "$A_TO_B_DELAY_MS" "$A_TO_B_JITTER_MS" \
  "$A_TO_B_DELAY_CORRELATION_PERCENT" "$A_TO_B_LOSS_PERCENT" \
  "$A_TO_B_LOSS_CORRELATION_PERCENT" "$A_TO_B_RATE_MBIT" "$A_TO_B_QUEUE_PACKETS"
apply_netem "$NSB" "$LINK-b" "$B_TO_A_DELAY_MS" "$B_TO_A_JITTER_MS" \
  "$B_TO_A_DELAY_CORRELATION_PERCENT" "$B_TO_A_LOSS_PERCENT" \
  "$B_TO_A_LOSS_CORRELATION_PERCENT" "$B_TO_A_RATE_MBIT" "$B_TO_A_QUEUE_PACKETS"
if [[ $SECOND_PATH == 1 ]]; then
  apply_netem "$NSA" "$LINK2-a" "$SECOND_PATH_DELAY_MS" 0 0 \
    "$SECOND_PATH_LOSS_PERCENT" 0 "$SECOND_PATH_RATE_MBIT" \
    "$SECOND_PATH_QUEUE_PACKETS"
  apply_netem "$NSB" "$LINK2-b" "$SECOND_PATH_DELAY_MS" 0 0 \
    "$SECOND_PATH_LOSS_PERCENT" 0 "$SECOND_PATH_RATE_MBIT" \
    "$SECOND_PATH_QUEUE_PACKETS"
fi

# Each direct-TCP or overlay saturation epoch begins from the same clean
# stage-zero netem state. Use timeline mode even for an all-zero initial
# state: initial mode intentionally leaves an interface alone, whereas an
# epoch reset must replace a previous dynamic qdisc with pass-through netem.
restore_initial_netem() {
  local stage=${1:-stage-0}
  apply_netem "$NSA" "$LINK-a" "$A_TO_B_DELAY_MS" "$A_TO_B_JITTER_MS" \
    "$A_TO_B_DELAY_CORRELATION_PERCENT" "$A_TO_B_LOSS_PERCENT" \
    "$A_TO_B_LOSS_CORRELATION_PERCENT" "$A_TO_B_RATE_MBIT" "$A_TO_B_QUEUE_PACKETS" timeline "$stage"
  apply_netem "$NSB" "$LINK-b" "$B_TO_A_DELAY_MS" "$B_TO_A_JITTER_MS" \
    "$B_TO_A_DELAY_CORRELATION_PERCENT" "$B_TO_A_LOSS_PERCENT" \
    "$B_TO_A_LOSS_CORRELATION_PERCENT" "$B_TO_A_RATE_MBIT" "$B_TO_A_QUEUE_PACKETS" timeline "$stage"
  if [[ $SECOND_PATH == 1 ]]; then
    apply_netem "$NSA" "$LINK2-a" "$SECOND_PATH_DELAY_MS" 0 0 \
      "$SECOND_PATH_LOSS_PERCENT" 0 "$SECOND_PATH_RATE_MBIT" \
      "$SECOND_PATH_QUEUE_PACKETS" timeline "$stage"
    apply_netem "$NSB" "$LINK2-b" "$SECOND_PATH_DELAY_MS" 0 0 \
      "$SECOND_PATH_LOSS_PERCENT" 0 "$SECOND_PATH_RATE_MBIT" \
      "$SECOND_PATH_QUEUE_PACKETS" timeline "$stage"
    set_underlay_path_state primary up
    set_underlay_path_state secondary up
  fi
}

capture_qdisc_pair() {
  local label=$1
  sudo ip netns exec "$NSA" "$TC" -s qdisc show dev "$LINK-a" \
    >"$OUT/$label-a-to-b-qdisc.txt"
  sudo ip netns exec "$NSB" "$TC" -s qdisc show dev "$LINK-b" \
    >"$OUT/$label-b-to-a-qdisc.txt"
  if [[ $SECOND_PATH == 1 ]]; then
    sudo ip netns exec "$NSA" "$TC" -s qdisc show dev "$LINK2-a" \
      >"$OUT/$label-second-a-to-b-qdisc.txt"
    sudo ip netns exec "$NSB" "$TC" -s qdisc show dev "$LINK2-b" \
      >"$OUT/$label-second-b-to-a-qdisc.txt"
  fi
}

capture_qdisc_pair netem-initial

if [[ $PREFLIGHT_ONLY == 1 ]]; then
  printf 'preflight_only=1\nstatus=namespace_scope_verified\n' \
    >>"$OUT/resource-isolation.txt"
  exit 0
fi

A_STATE="$OUT/a-state"
B_STATE="$OUT/b-state"
A_CONFIG="$A_STATE/config.toml"
B_CONFIG="$B_STATE/config.toml"
# AF_UNIX sockaddr paths are limited to roughly 108 bytes on Linux. Matrix
# scenario names and absolute artifact roots can legitimately exceed that, so
# keep only the disposable control sockets in a short host path while all
# durable state remains under the scenario artifact directory.
A_SOCKET="${TMPDIR:-/tmp}/$NS-a.sock"
B_SOCKET="${TMPDIR:-/tmp}/$NS-b.sock"
mkdir -p "$A_STATE" "$B_STATE"

run_product() {
  local namespace=$1 config=$2 state=$3 socket=$4
  shift 4
  sudo ip netns exec "$namespace" "$TASKSET" -c "$PROFILE_CPUSET" \
    "$NICE" -n "$PROFILE_NICE" "$CLI" \
    --config "$config" --state-dir "$state" --socket "$socket" "$@"
}

status_queues_are_drained() {
  python3 - "$@" <<'PY'
import json
import pathlib
import sys

def peer_traffic_value(peer, field):
    if field in peer:
        return int(peer[field] or 0)
    return int((peer.get("traffic") or {}).get(field, 0) or 0)

for name in sys.argv[1:]:
    status = json.loads(pathlib.Path(name).read_text())
    for peer in status.get("peers", []):
        if peer_traffic_value(peer, "packet_train_queue_bytes") != 0:
            raise SystemExit(1)
        if peer_traffic_value(peer, "latency_queue_bytes") != 0:
            raise SystemExit(1)
PY
}

wait_for_class_queues_to_drain() {
  local attempts=$((QUEUE_DRAIN_TIMEOUT_SECONDS * 10)) attempt
  local a_tmp="$OUT/a-final-status.json.tmp"
  local b_tmp="$OUT/b-final-status.json.tmp"
  for attempt in $(seq 1 "$attempts"); do
    if run_product "$NSA" "$A_CONFIG" "$A_STATE" "$A_SOCKET" \
        status --output json >"$a_tmp" \
      && run_product "$NSB" "$B_CONFIG" "$B_STATE" "$B_SOCKET" \
        status --output json >"$b_tmp" \
      && status_queues_are_drained "$a_tmp" "$b_tmp"; then
      mv "$a_tmp" "$OUT/a-final-status.json"
      mv "$b_tmp" "$OUT/b-final-status.json"
      printf 'drained=true\nattempts=%s\nelapsed_milliseconds=%s\n' \
        "$attempt" "$((attempt * 100))" >"$OUT/queue-drain.txt"
      return 0
    fi
    sleep 0.1
  done
  [[ -s $a_tmp ]] && mv "$a_tmp" "$OUT/a-final-status.json"
  [[ -s $b_tmp ]] && mv "$b_tmp" "$OUT/b-final-status.json"
  printf 'drained=false\nattempts=%s\nelapsed_milliseconds=%s\n' \
    "$attempts" "$((attempts * 100))" >"$OUT/queue-drain.txt"
  echo "V2 class queues did not drain within ${QUEUE_DRAIN_TIMEOUT_SECONDS}s" >&2
  return 1
}

capture_status_pair() {
  local label=$1
  run_product "$NSA" "$A_CONFIG" "$A_STATE" "$A_SOCKET" \
    status --output json >"$OUT/a-$label-status.json"
  run_product "$NSB" "$B_CONFIG" "$B_STATE" "$B_SOCKET" \
    status --output json >"$OUT/b-$label-status.json"
}

capture_underlay_paths() {
  local label=$1
  {
    echo "[$NSA primary]"
    sudo ip -n "$NSA" -s link show dev "$LINK-a"
    sudo ip -n "$NSA" -6 addr show dev "$LINK-a"
    sudo ip -n "$NSA" -6 neigh show dev "$LINK-a"
    echo "[$NSB primary]"
    sudo ip -n "$NSB" -s link show dev "$LINK-b"
    sudo ip -n "$NSB" -6 addr show dev "$LINK-b"
    sudo ip -n "$NSB" -6 neigh show dev "$LINK-b"
    if [[ $SECOND_PATH == 1 ]]; then
      echo "[$NSA secondary]"
      sudo ip -n "$NSA" -s link show dev "$LINK2-a"
      sudo ip -n "$NSA" -6 addr show dev "$LINK2-a"
      sudo ip -n "$NSA" -6 neigh show dev "$LINK2-a"
      echo "[$NSB secondary]"
      sudo ip -n "$NSB" -s link show dev "$LINK2-b"
      sudo ip -n "$NSB" -6 addr show dev "$LINK2-b"
      sudo ip -n "$NSB" -6 neigh show dev "$LINK2-b"
    fi
  } >"$OUT/$label-underlay-links.txt"
}

set_underlay_path_state() {
  local path=$1 state=$2 a_device b_device
  case $path in
    primary) a_device="$LINK-a"; b_device="$LINK-b" ;;
    secondary) a_device="$LINK2-a"; b_device="$LINK2-b" ;;
    *) echo "unknown underlay path: $path" >&2; return 1 ;;
  esac
  sudo ip -n "$NSA" link set dev "$a_device" "$state"
  sudo ip -n "$NSB" link set dev "$b_device" "$state"
}

# Dynamic timeline scheduler. Runs as a background subshell for the whole
# overlay saturation phase and re-applies netem at each scheduled offset. Each
# step is bracketed by qdisc captures so that per-segment netem drops/bytes can
# be derived without any change to the daemon. Peer status is captured after
# the mutation: querying a saturated daemon can take seconds and must not move
# the scheduled netem application away from its requested offset. All
# mutations go through apply_netem, which only accepts the two lab namespaces
# and veths.
run_timeline() {
  local started_ns=$1
  local a_delay=$A_TO_B_DELAY_MS a_jitter=$A_TO_B_JITTER_MS
  local a_delay_corr=$A_TO_B_DELAY_CORRELATION_PERCENT a_loss=$A_TO_B_LOSS_PERCENT
  local a_loss_corr=$A_TO_B_LOSS_CORRELATION_PERCENT a_rate=$A_TO_B_RATE_MBIT
  local a_queue=$A_TO_B_QUEUE_PACKETS
  local b_delay=$B_TO_A_DELAY_MS b_jitter=$B_TO_A_JITTER_MS
  local b_delay_corr=$B_TO_A_DELAY_CORRELATION_PERCENT b_loss=$B_TO_A_LOSS_PERCENT
  local b_loss_corr=$B_TO_A_LOSS_CORRELATION_PERCENT b_rate=$B_TO_A_RATE_MBIT
  local b_queue=$B_TO_A_QUEUE_PACKETS
  local index offset changes change key value label stage a_seed b_seed
  local primary_state=up secondary_state=up path_changed
  local now_ns remaining_ms applied_ms
  printf 'step\toffset_seconds\tapplied_offset_ms\tchanges\ta_to_b\tb_to_a\ta_seed\tb_seed\tprimary\tsecondary\n' \
    >"$OUT/timeline.tsv"
  for index in "${!TIMELINE_OFFSETS[@]}"; do
    offset=${TIMELINE_OFFSETS[$index]}
    changes=${TIMELINE_CHANGES[$index]}
    label=$(printf 'timeline-%02d' "$((index + 1))")
    now_ns=$(date +%s%N)
    remaining_ms=$(( (offset * 1000) - (now_ns - started_ns) / 1000000 ))
    if ((remaining_ms > 0)); then
      sleep "$(awk -v ms="$remaining_ms" 'BEGIN { printf "%.3f", ms / 1000 }')"
    fi
    capture_qdisc_pair "$label-before"
    capture_underlay_paths "$label-before"
    path_changed=0
    IFS=',' read -r -a change_list <<<"$changes"
    for change in "${change_list[@]}"; do
      key=${change%%=*}
      value=${change#*=}
      case $key in
        a_* | b_*) ;;
        primary | secondary)
          printf -v "${key}_state" '%s' "$value"
          path_changed=1
          continue ;;
      esac
      printf -v "$key" '%s' "$value"
    done
    # A stage replacement must reset both directional PRNGs, even if the
    # catalog change touched only one side. Otherwise the untouched direction
    # inherits a TCP-vs-overlay-dependent random history.
    stage="stage-$((index + 1))"
    a_seed=$(netem_seed a-to-b "$stage")
    b_seed=$(netem_seed b-to-a "$stage")
    apply_netem "$NSA" "$LINK-a" "$a_delay" "$a_jitter" "$a_delay_corr" \
      "$a_loss" "$a_loss_corr" "$a_rate" "$a_queue" timeline "$stage"
    apply_netem "$NSB" "$LINK-b" "$b_delay" "$b_jitter" "$b_delay_corr" \
      "$b_loss" "$b_loss_corr" "$b_rate" "$b_queue" timeline "$stage"
    if [[ $SECOND_PATH == 1 ]]; then
      apply_netem "$NSA" "$LINK2-a" "$SECOND_PATH_DELAY_MS" 0 0 \
        "$SECOND_PATH_LOSS_PERCENT" 0 "$SECOND_PATH_RATE_MBIT" \
        "$SECOND_PATH_QUEUE_PACKETS" timeline "$stage"
      apply_netem "$NSB" "$LINK2-b" "$SECOND_PATH_DELAY_MS" 0 0 \
        "$SECOND_PATH_LOSS_PERCENT" 0 "$SECOND_PATH_RATE_MBIT" \
        "$SECOND_PATH_QUEUE_PACKETS" timeline "$stage"
    fi
    if ((path_changed)); then
      set_underlay_path_state primary "$primary_state"
      set_underlay_path_state secondary "$secondary_state"
    fi
    applied_ms=$(( ($(date +%s%N) - started_ns) / 1000000 ))
    capture_qdisc_pair "$label-after"
    capture_underlay_paths "$label-after"
    capture_status_pair "$label-after"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$((index + 1))" "$offset" "$applied_ms" \
      "$changes" \
      "$(netem_state_record "$a_delay" "$a_jitter" "$a_delay_corr" "$a_loss" "$a_loss_corr" "$a_rate" "$a_queue")" \
      "$(netem_state_record "$b_delay" "$b_jitter" "$b_delay_corr" "$b_loss" "$b_loss_corr" "$b_rate" "$b_queue")" \
      "$a_seed" "$b_seed" \
      "$primary_state" "$secondary_state" \
      >>"$OUT/timeline.tsv"
  done
}

# Run the same scheduled impairment states while the direct TCP underlay
# control is measured. This deliberately has no daemon/status probes: its job
# is to align stage timing, configuration and PRNG seeds with the later
# overlay phase, not to claim identical packet-level outcomes.
run_underlay_timeline() {
  local started_ns=$1
  local a_delay=$A_TO_B_DELAY_MS a_jitter=$A_TO_B_JITTER_MS
  local a_delay_corr=$A_TO_B_DELAY_CORRELATION_PERCENT a_loss=$A_TO_B_LOSS_PERCENT
  local a_loss_corr=$A_TO_B_LOSS_CORRELATION_PERCENT a_rate=$A_TO_B_RATE_MBIT
  local a_queue=$A_TO_B_QUEUE_PACKETS
  local b_delay=$B_TO_A_DELAY_MS b_jitter=$B_TO_A_JITTER_MS
  local b_delay_corr=$B_TO_A_DELAY_CORRELATION_PERCENT b_loss=$B_TO_A_LOSS_PERCENT
  local b_loss_corr=$B_TO_A_LOSS_CORRELATION_PERCENT b_rate=$B_TO_A_RATE_MBIT
  local b_queue=$B_TO_A_QUEUE_PACKETS
  local index offset changes change key value stage a_seed b_seed now_ns remaining_ms applied_ms
  printf 'step\toffset_seconds\tapplied_offset_ms\tchanges\ta_to_b\tb_to_a\ta_seed\tb_seed\tprimary\tsecondary\n' \
    >"$OUT/underlay-timeline.tsv"
  for index in "${!TIMELINE_OFFSETS[@]}"; do
    offset=${TIMELINE_OFFSETS[$index]}
    changes=${TIMELINE_CHANGES[$index]}
    now_ns=$(date +%s%N)
    remaining_ms=$(( (offset * 1000) - (now_ns - started_ns) / 1000000 ))
    if ((remaining_ms > 0)); then
      sleep "$(awk -v ms="$remaining_ms" 'BEGIN { printf "%.3f", ms / 1000 }')"
    fi
    IFS=',' read -r -a change_list <<<"$changes"
    for change in "${change_list[@]}"; do
      key=${change%%=*}
      value=${change#*=}
      case $key in
        a_* | b_*) ;;
        # A single direct TCP flow has no equivalent for overlay path failover.
        # Such timelines retain the legacy baseline and are marked incomparable.
        primary | secondary) continue ;;
      esac
      printf -v "$key" '%s' "$value"
    done
    stage="stage-$((index + 1))"
    a_seed=$(netem_seed a-to-b "$stage")
    b_seed=$(netem_seed b-to-a "$stage")
    apply_netem "$NSA" "$LINK-a" "$a_delay" "$a_jitter" "$a_delay_corr" \
      "$a_loss" "$a_loss_corr" "$a_rate" "$a_queue" timeline "$stage"
    apply_netem "$NSB" "$LINK-b" "$b_delay" "$b_jitter" "$b_delay_corr" \
      "$b_loss" "$b_loss_corr" "$b_rate" "$b_queue" timeline "$stage"
    if [[ $SECOND_PATH == 1 ]]; then
      apply_netem "$NSA" "$LINK2-a" "$SECOND_PATH_DELAY_MS" 0 0 \
        "$SECOND_PATH_LOSS_PERCENT" 0 "$SECOND_PATH_RATE_MBIT" \
        "$SECOND_PATH_QUEUE_PACKETS" timeline "$stage"
      apply_netem "$NSB" "$LINK2-b" "$SECOND_PATH_DELAY_MS" 0 0 \
        "$SECOND_PATH_LOSS_PERCENT" 0 "$SECOND_PATH_RATE_MBIT" \
        "$SECOND_PATH_QUEUE_PACKETS" timeline "$stage"
    fi
    applied_ms=$(( ($(date +%s%N) - started_ns) / 1000000 ))
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\tup\tup\n' "$((index + 1))" "$offset" "$applied_ms" \
      "$changes" \
      "$(netem_state_record "$a_delay" "$a_jitter" "$a_delay_corr" "$a_loss" "$a_loss_corr" "$a_rate" "$a_queue")" \
      "$(netem_state_record "$b_delay" "$b_jitter" "$b_delay_corr" "$b_loss" "$b_loss_corr" "$b_rate" "$b_queue")" \
      "$a_seed" "$b_seed" \
      >>"$OUT/underlay-timeline.tsv"
  done
}

verify_synchronized_timeline() {
  python3 - "$OUT/underlay-timeline.tsv" "$OUT/timeline.tsv" \
    >"$OUT/timeline-synchronization.json" <<'PY'
import csv
import json
import pathlib
import sys

underlay_path, overlay_path = map(pathlib.Path, sys.argv[1:])
keys = (
    "step", "offset_seconds", "changes", "a_to_b", "b_to_a",
    "a_seed", "b_seed", "primary", "secondary",
)
maximum_applied_offset_delta_ms = 250
with underlay_path.open() as handle:
    underlay = list(csv.DictReader(handle, delimiter="\t"))
with overlay_path.open() as handle:
    overlay = list(csv.DictReader(handle, delimiter="\t"))
if len(underlay) != len(overlay):
    raise SystemExit("underlay/overlay timeline step count differs")
for index, (left, right) in enumerate(zip(underlay, overlay), start=1):
    for key in keys:
        if left.get(key) != right.get(key):
            raise SystemExit(f"timeline step {index} differs at {key}: {left.get(key)!r} != {right.get(key)!r}")
applied_offset_deltas_ms = [
    abs(int(left["applied_offset_ms"]) - int(right["applied_offset_ms"]))
    for left, right in zip(underlay, overlay)
]
underlay_requested_offset_errors_ms = [
    abs(int(row["applied_offset_ms"]) - int(row["offset_seconds"]) * 1000)
    for row in underlay
]
overlay_requested_offset_errors_ms = [
    abs(int(row["applied_offset_ms"]) - int(row["offset_seconds"]) * 1000)
    for row in overlay
]
if any(delta > maximum_applied_offset_delta_ms for delta in applied_offset_deltas_ms):
    raise SystemExit(
        "underlay/overlay timeline applied-offset delta exceeds "
        f"{maximum_applied_offset_delta_ms} ms: {applied_offset_deltas_ms}"
    )
if any(
    error > maximum_applied_offset_delta_ms
    for error in underlay_requested_offset_errors_ms
):
    raise SystemExit(
        "underlay timeline applied offset misses its requested offset by more than "
        f"{maximum_applied_offset_delta_ms} ms: {underlay_requested_offset_errors_ms}"
    )
if any(
    error > maximum_applied_offset_delta_ms
    for error in overlay_requested_offset_errors_ms
):
    raise SystemExit(
        "overlay timeline applied offset misses its requested offset by more than "
        f"{maximum_applied_offset_delta_ms} ms: {overlay_requested_offset_errors_ms}"
    )
print(json.dumps({
    "mode": "synchronized_dynamic_timeline",
    "comparable": True,
    "steps": len(overlay),
    "validated_fields": list(keys),
    "applied_offset_deltas_ms": applied_offset_deltas_ms,
    "maximum_applied_offset_delta_ms": max(applied_offset_deltas_ms, default=0),
    "underlay_requested_offset_errors_ms": underlay_requested_offset_errors_ms,
    "overlay_requested_offset_errors_ms": overlay_requested_offset_errors_ms,
    "maximum_underlay_requested_offset_error_ms": max(
        underlay_requested_offset_errors_ms, default=0
    ),
    "maximum_overlay_requested_offset_error_ms": max(
        overlay_requested_offset_errors_ms, default=0
    ),
    "allowed_applied_offset_delta_ms": maximum_applied_offset_delta_ms,
}, indent=2))
PY
}

capture_and_verify_route_isolation() {
  local label=$1 namespace=$2
  local family output
  for family in 4 6; do
    output="$OUT/$label-ipv$family-rules.txt"
    sudo ip netns exec "$namespace" ip "-$family" rule show >"$output"
    grep -Eq '^10000:.*lookup 211' "$output"
    output="$OUT/$label-ipv$family-table-211.txt"
    sudo ip netns exec "$namespace" ip "-$family" route show table 211 >"$output"
    grep -q 'dev ironet0' "$output"
    output="$OUT/$label-ipv$family-main-proto-100.txt"
    sudo ip netns exec "$namespace" ip "-$family" route show table main proto 100 >"$output"
    [[ ! -s $output ]]
  done
}

wait_for_route_convergence() {
  local a_tmp="$OUT/a-status.tmp.json" b_tmp="$OUT/b-status.tmp.json"
  local attempt
  for attempt in $(seq 1 200); do
    if run_product "$NSA" "$A_CONFIG" "$A_STATE" "$A_SOCKET" \
        status --output json >"$a_tmp" \
      && run_product "$NSB" "$B_CONFIG" "$B_STATE" "$B_SOCKET" \
        status --output json >"$b_tmp" \
      && python3 - "$a_tmp" "$b_tmp" <<'PY'
import json
import sys

for path in sys.argv[1:]:
    status = json.load(open(path))
    if status.get("mesh", {}).get("directory_entries", 0) < 2:
        raise SystemExit(1)
    routes = status.get("routes", [])
    if len(routes) < 2 or not all(route.get("present") for route in routes):
        raise SystemExit(1)
PY
    then
      mv "$a_tmp" "$OUT/a-status.json"
      mv "$b_tmp" "$OUT/b-status.json"
      return 0
    fi
    sleep 0.1
  done
  echo "V2 route inventory did not converge" >&2
  return 1
}

run_iperf() {
  local namespace=$1
  shift
  local maximum_duration=$DURATION
  ((FAIRNESS_SECONDS <= maximum_duration)) || maximum_duration=$FAIRNESS_SECONDS
  ((COVER_SECONDS <= maximum_duration)) || maximum_duration=$COVER_SECONDS
  sudo ip netns exec "$namespace" "$TASKSET" -c "$PROFILE_CPUSET" \
    "$NICE" -n "$PROFILE_NICE" "$TIMEOUT" --signal=INT --kill-after=5s \
    "$((maximum_duration + 30))s" "$IPERF3" "$@"
}

# Build the same sealed V2 product configuration used in production. Invite
# creation pins the generated member identity on B; A receives B's underlay
# locator and owns the bootstrap dial.
LISTEN_ADDR="[$UNDERLAY_B]:$PORT"
INVITE_ADDRESS_ARGS=(--address "[$UNDERLAY_B]:$PORT")
if [[ $SECOND_PATH == 1 ]]; then
  LISTEN_ADDR="[::]:$PORT"
  INVITE_ADDRESS_ARGS+=(--address "[$UNDERLAY_B2]:$PORT")
fi
run_product "$NSB" "$B_CONFIG" "$B_STATE" "$B_SOCKET" \
  network create profile-v2 --node-name b \
  --address-pool 198.18.0.0/16 --ipv6-address-pool fd42:6972:6f68::/64 \
  --listen "$LISTEN_ADDR" --no-dns --no-start --output json \
  >"$OUT/b-network.json"
run_product "$NSB" "$B_CONFIG" "$B_STATE" "$B_SOCKET" \
  invite create "${INVITE_ADDRESS_ARGS[@]}" --output json \
  >"$OUT/invite.json"
TOKEN=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["token"])' \
  "$OUT/invite.json")
run_product "$NSA" "$A_CONFIG" "$A_STATE" "$A_SOCKET" \
  join "$TOKEN" --node-name a --no-start --output json >"$OUT/a-network.json"

# Profile runs are disposable experiments. Make their policy inputs explicit
# and disable cross-run memory by default so two artifacts remain comparable.
# Both policies can still hot-reload while the daemons are running.
install_autotune_profile_config() {
  local namespace=$1 config=$2 state=$3 socket=$4 memory
  [[ $AUTOTUNE_MEMORY == 1 ]] && memory=true || memory=false
  if sudo grep -q '^\[autotune\]$' "$config"; then
    echo "generated profile config unexpectedly contains an autotune table: $config" >&2
    return 1
  fi
  {
    printf '\n[autotune]\n'
    printf 'mode = "%s"\n' "$AUTOTUNE_MODE"
    printf 'objective = "%s"\n' "$AUTOTUNE_OBJECTIVE"
    printf 'memory = %s\n' "$memory"
    printf 'policy = "%s"\n' "$AUTOTUNE_POLICY"
    if [[ -n $AUTOTUNE_SHADOW_POLICY ]]; then
      printf 'shadow_policy = "%s"\n' "$AUTOTUNE_SHADOW_POLICY"
    fi
  } | sudo tee -a "$config" >/dev/null
  run_product "$namespace" "$config" "$state" "$socket" seal-config >/dev/null
}

install_autotune_profile_config "$NSB" "$B_CONFIG" "$B_STATE" "$B_SOCKET"
install_autotune_profile_config "$NSA" "$A_CONFIG" "$A_STATE" "$A_SOCKET"
B_OVERLAY=$(python3 -c \
  'import json,sys; print(next(x.split("/")[0] for x in json.load(open(sys.argv[1]))["network"]["addresses"] if "." in x))' \
  "$OUT/b-network.json")

launch_profiled() {
  local output_variable=$1 namespace=$2 log=$3 data=$4 pidfile=$5
  local -a daemon_env=(env "RUST_LOG=$PROFILE_RUST_LOG")
  shift 5
  if [[ -n $AUTOTUNE_FORCE ]]; then
    daemon_env+=("IRONET_AUTOTUNE_FORCE=$AUTOTUNE_FORCE")
  fi
  if [[ $DAEMON_DIRECT == 1 ]]; then
    sudo ip netns exec "$namespace" sh -c \
      'echo $$ > "$1"; shift; exec "$@"' sh "$pidfile" \
      "$TASKSET" -c "$PROFILE_CPUSET" "$NICE" -n "$PROFILE_NICE" \
      "${daemon_env[@]}" "$BIN" "$@" >"$log" 2>&1 &
  else
    sudo ip netns exec "$namespace" sh -c \
      'echo $$ > "$1"; shift; exec "$@"' sh "$pidfile" \
      "$TASKSET" -c "$PROFILE_CPUSET" "$NICE" -n "$PROFILE_NICE" \
      "${daemon_env[@]}" "$PERF" record --sample-cpu \
      -F "$PERF_FREQUENCY" -g \
      --call-graph "$CALL_GRAPH" -o "$data" -- "$BIN" "$@" \
      >"$log" 2>&1 &
  fi
  printf -v "$output_variable" '%s' "$!"
}

launch_profiled B_LAUNCH "$NSB" "$OUT/b.log" "$OUT/b.perf.data" "$OUT/b.pid" \
  --config "$B_CONFIG" --socket "$B_SOCKET"
for _ in $(seq 1 100); do
  [[ -s $OUT/b.pid ]] && grep -q 'V2 endpoint ready' "$OUT/b.log" && break
  sleep 0.1
done
[[ -s $OUT/b.pid ]] && grep -q 'V2 endpoint ready' "$OUT/b.log"
B_PID=$(cat "$OUT/b.pid")
launch_profiled A_LAUNCH "$NSA" "$OUT/a.log" "$OUT/a.perf.data" "$OUT/a.pid" \
  --config "$A_CONFIG" --socket "$A_SOCKET"
for _ in $(seq 1 200); do
  [[ -s $OUT/a.pid ]] && grep -Eq 'V2 (mesh )?TUN configured' "$OUT/a.log" \
    && grep -Eq 'V2 (mesh )?TUN configured' "$OUT/b.log" && break
  sleep 0.1
done
[[ -s $OUT/a.pid ]] && grep -Eq 'V2 (mesh )?TUN configured' "$OUT/a.log"
grep -Eq 'V2 (mesh )?TUN configured' "$OUT/b.log"
A_PID=$(cat "$OUT/a.pid")

if [[ $STARTUP_CANARY_ONLY == 1 ]]; then
  wait_for_route_convergence
  capture_and_verify_route_isolation a "$NSA"
  capture_and_verify_route_isolation b "$NSB"
  printf 'startup_canary_only=1\nstatus=official_v2_pair_ready\n' \
    >>"$OUT/resource-isolation.txt"
  stop_profiled_pair
  A_PID=
  B_PID=
  A_LAUNCH=
  B_LAUNCH=
  sudo chown -R "$(id -u):$(id -g)" "$OUT"
  exit 0
fi

if [[ $DISABLE_TUN_OFFLOAD == 1 ]]; then
  # Exercise the ordinary near-MTU/two-Cell path separately from the default
  # end-to-end GSO profile. This is a benchmark switch, never a product knob.
  sudo ip netns exec "$NSA" "$ETHTOOL" -K ironet0 tso off gso off gro off
  sudo ip netns exec "$NSB" "$ETHTOOL" -K ironet0 tso off gso off gro off
fi

run_iperf "$NSB" -s -1 --json >"$OUT/underlay-server.json" &
UNDERLAY_SERVER=$!
sleep 0.2
# Reset only after the receiver is ready. Underlay and overlay now perform the
# same final sequence -- reset, concurrent ping, anchor, client -- so daemon
# setup/status work cannot consume a different prefix of the netem PRNG stream.
restore_initial_netem stage-0
# `tc qdisc replace` intentionally preserves the qdisc instance and its
# cumulative counters. Snapshot immediately after the epoch restore so the
# underlay delta excludes bootstrap/setup traffic and can be compared with an
# independently delimited overlay epoch.
capture_qdisc_pair netem-before-underlay
if [[ $PREFLIGHT_ONLY == 0 && $CONCURRENT_PING_INTERVAL_MS != 0 ]]; then
  PING_INTERVAL=$(awk -v value="$CONCURRENT_PING_INTERVAL_MS" 'BEGIN { printf "%.3f", value / 1000 }')
  # Both controls sample the same wall-clock window. A shorter underlay window
  # overweights TCP startup and makes both throughput and latency incomparable.
  UNDERLAY_PING_WINDOW_MS=$((DURATION * 1000))
  UNDERLAY_PING_COUNT=$((UNDERLAY_PING_WINDOW_MS / CONCURRENT_PING_INTERVAL_MS))
  ((UNDERLAY_PING_COUNT > 0)) || UNDERLAY_PING_COUNT=1
  sudo ip netns exec "$NSA" "$TASKSET" -c "$PROFILE_CPUSET" "$NICE" -n "$PROFILE_NICE" \
    "$PING" -6 -n -i "$PING_INTERVAL" -c "$UNDERLAY_PING_COUNT" \
    "$UNDERLAY_B" >"$OUT/underlay-concurrent-ping.txt" 2>&1 &
  UNDERLAY_PING_PID=$!
fi
IPERF_DIRECTION_ARGS=()
[[ $PROFILE_DIRECTION == forward ]] || IPERF_DIRECTION_ARGS=(-R)
if [[ $SECOND_PATH == 1 ]]; then
  # One direct TCP socket uses only the primary underlay address, while the
  # overlay is allowed to select or fail over to the secondary address. Until
  # the harness has path-specific byte evidence or a matched secondary TCP
  # control, an aggregate throughput ratio would compare different paths.
  if [[ $TIMELINE_HAS_PATH_ACTION == 1 ]]; then
    printf '%s\n' '{"mode":"unavailable_path_state_timeline","comparable":false,"reason":"direct TCP control cannot reproduce overlay path-state changes or secondary-path selection"}' \
      >"$OUT/timeline-comparison.json"
  else
    printf '%s\n' '{"mode":"unavailable_secondary_path","comparable":false,"reason":"direct TCP control measures only the primary path; overlay secondary-path usage is not proven absent"}' \
      >"$OUT/timeline-comparison.json"
  fi
elif ((${#TIMELINE_OFFSETS[@]} > 0)); then
  # The direct TCP control receives the same scheduled netem configurations,
  # stage seeds and duration as the overlay. Without this, a dynamic scenario
  # compared an initial-link control against a later, different link schedule.
  UNDERLAY_STARTED_NS=$(date +%s%N)
  date -u -d "@$((UNDERLAY_STARTED_NS / 1000000000))" +%Y-%m-%dT%H:%M:%SZ \
    >"$OUT/underlay-started-at.txt"
  printf '%s\n' "$UNDERLAY_STARTED_NS" >>"$OUT/underlay-started-at.txt"
  run_underlay_timeline "$UNDERLAY_STARTED_NS" &
  UNDERLAY_TIMELINE_PID=$!
  UNDERLAY_TIMELINE_RAN=1
  printf '%s\n' '{"mode":"synchronized_dynamic_timeline","comparable":true}' \
    >"$OUT/timeline-comparison.json"
else
  printf '%s\n' '{"mode":"static_initial","comparable":true}' \
    >"$OUT/timeline-comparison.json"
fi
run_iperf "$NSA" -6 -c "$UNDERLAY_B" -t "$DURATION" -P "$PARALLEL" \
  "${IPERF_DIRECTION_ARGS[@]}" --json \
  >"$OUT/underlay.json"
wait "$UNDERLAY_SERVER"
if [[ -n ${UNDERLAY_TIMELINE_PID:-} ]]; then
  wait "$UNDERLAY_TIMELINE_PID" || { echo "underlay dynamic timeline failed" >&2; exit 1; }
  UNDERLAY_TIMELINE_PID=
  # Preserve the final dynamic underlay counters before qdisc replace resets
  # them for cover traffic or the overlay epoch.
  capture_qdisc_pair netem-after-underlay
  restore_initial_netem stage-0
else
  capture_qdisc_pair netem-after-underlay
fi
if [[ -n ${UNDERLAY_PING_PID:-} ]]; then
  wait "$UNDERLAY_PING_PID"
  UNDERLAY_PING_PID=
fi

# Exercise the automatic LiveMedia shaper below path capacity before the
# saturation run. The following TCP/Bulk phases then prove that queue/loss
# evidence suppresses padding without an operator toggle.
if ((COVER_SECONDS > 0)); then
  capture_status_pair cover-before
  run_iperf "$NSB" -s -1 --json >"$OUT/overlay-cover-server.json" &
  COVER_SERVER=$!
  sleep 0.2
  run_iperf "$NSA" -4 -u -c "$B_OVERLAY" -t "$COVER_SECONDS" \
    -P 1 -b "${COVER_RATE_MBIT}M" -l 1200 --udp-counters-64bit --json \
    >"$OUT/overlay-cover.json"
  wait "$COVER_SERVER"
  COVER_SERVER=
  capture_status_pair cover-after
fi

capture_status_pair saturation-before
# Link counters are the ground truth below the QUIC socket. Keep snapshots at
# the saturation boundaries as well as around timeline mutations so recovery
# probes can be distinguished from packets merely queued by the protocol.
capture_underlay_paths saturation-before
run_iperf "$NSB" -s -1 --json >"$OUT/overlay-server.json" &
OVERLAY_SERVER=$!
sleep 0.2
# Cover traffic, status probes and the direct baseline may consume netem's
# PRNG. Match the underlay's final preparation order by resetting only after
# the receiver is ready and immediately before ping/timeline/client launch.
restore_initial_netem stage-0
# This is the overlay phase's counter origin. Do not use netem-initial here:
# that snapshot predates the direct underlay control and would fold its bytes
# and drops into the overlay shallow-shaper evidence.
capture_qdisc_pair netem-before-overlay
if [[ $PREFLIGHT_ONLY == 0 && $CONCURRENT_PING_INTERVAL_MS != 0 ]]; then
  PING_INTERVAL=$(awk -v value="$CONCURRENT_PING_INTERVAL_MS" 'BEGIN { printf "%.3f", value / 1000 }')
  PING_COUNT=$((DURATION * 1000 / CONCURRENT_PING_INTERVAL_MS))
  ((PING_COUNT > 0)) || PING_COUNT=1
  sudo ip netns exec "$NSA" "$TASKSET" -c "$PROFILE_CPUSET" "$NICE" -n "$PROFILE_NICE" \
    "$PING" -4 -n -i "$PING_INTERVAL" -c "$PING_COUNT" \
    "$B_OVERLAY" >"$OUT/overlay-concurrent-ping.txt" 2>&1 &
  PING_PID=$!
fi
# Wall-clock anchor for the saturation phase: timeline offsets, per-second
# iperf intervals, ping samples and daemon log timestamps are all aligned to
# this instant by the summary.
SATURATION_STARTED_NS=$(date +%s%N)
date -u -d "@$((SATURATION_STARTED_NS / 1000000000))" +%Y-%m-%dT%H:%M:%SZ \
  >"$OUT/saturation-started-at.txt"
printf '%s\n' "$SATURATION_STARTED_NS" >>"$OUT/saturation-started-at.txt"
if ((${#TIMELINE_OFFSETS[@]} > 0)); then
  run_timeline "$SATURATION_STARTED_NS" &
  TIMELINE_PID=$!
fi
run_iperf "$NSA" -4 -c "$B_OVERLAY" -t "$DURATION" -P "$PARALLEL" \
  "${IPERF_DIRECTION_ARGS[@]}" --json \
  >"$OUT/overlay.json"
wait "$OVERLAY_SERVER"
if [[ -n ${TIMELINE_PID:-} ]]; then
  # Every step is scheduled strictly before the saturation run ends; a failed
  # netem replacement must fail the scenario instead of silently producing a
  # static profile under a dynamic label.
  wait "$TIMELINE_PID" || { echo "dynamic timeline failed" >&2; exit 1; }
  TIMELINE_PID=
fi
if [[ $UNDERLAY_TIMELINE_RAN == 1 ]]; then
  # This is an executable harness assertion, not a name-based assumption:
  # every scheduled configuration, seed and directional state must align
  # before the ratio is accepted as a synchronized comparison.
  verify_synchronized_timeline || { echo "underlay/overlay timeline mismatch" >&2; exit 1; }
fi
capture_qdisc_pair netem-after-overlay
capture_underlay_paths saturation-after
if [[ -n ${PING_PID:-} ]]; then
  wait "$PING_PID"
  PING_PID=
fi
capture_status_pair saturation-after
if ((FAIRNESS_SECONDS > 0)); then
  run_iperf "$NSB" -s -1 --json >"$OUT/overlay-fairness-server.json" &
  FAIRNESS_SERVER=$!
  sleep 0.2
  run_iperf "$NSA" -4 -u -c "$B_OVERLAY" -t "$FAIRNESS_SECONDS" \
    -P "$PARALLEL" -b "${FAIRNESS_PER_STREAM_MBIT}M" -l 1200 \
    --udp-counters-64bit --json \
    >"$OUT/overlay-fairness.json"
  wait "$FAIRNESS_SERVER"
  FAIRNESS_SERVER=
fi
wait_for_class_queues_to_drain

stop_profiled_pair
A_PID=
B_PID=
A_LAUNCH=
B_LAUNCH=
sudo chown -R "$(id -u):$(id -g)" "$OUT"

for side in a b; do
  [[ $PERF_ENABLED == 1 ]] || break
  "$TASKSET" -c "$PROFILE_CPUSET" "$NICE" -n "$PROFILE_NICE" \
    "$PERF" report --stdio -i "$OUT/$side.perf.data" >"$OUT/$side.report.txt"
  "$TASKSET" -c "$PROFILE_CPUSET" "$NICE" -n "$PROFILE_NICE" \
    "$PERF" script -i "$OUT/$side.perf.data" >"$OUT/$side.perf.script"
  "$TASKSET" -c "$PROFILE_CPUSET" "$NICE" -n "$PROFILE_NICE" \
    "$STACKCOLLAPSE" "$OUT/$side.perf.script" >"$OUT/$side.folded"
  # A process-mode recording on an Intel hybrid host contains both PMUs, but
  # an unfiltered `perf script` renders only one of them. `--sample-cpu` above
  # records the actual CPU for every sample, which lets us produce complete,
  # symbolized P-core and Atom call stacks instead of reconstructing stacks
  # from the lossy folded text emitted by `perf report`.
  if "$PERF" evlist -i "$OUT/$side.perf.data" | grep -q '^cpu_core/cycles' \
      && [[ -r $CPU_CORE_CPUS_FILE && -r $CPU_ATOM_CPUS_FILE ]]; then
    CORE_CPUS=$(<"$CPU_CORE_CPUS_FILE")
    ATOM_CPUS=$(<"$CPU_ATOM_CPUS_FILE")
    "$TASKSET" -c "$PROFILE_CPUSET" "$NICE" -n "$PROFILE_NICE" \
      "$PERF" script -C "$CORE_CPUS" -i "$OUT/$side.perf.data" \
      >"$OUT/$side.core.perf.script"
    "$STACKCOLLAPSE" "$OUT/$side.core.perf.script" >"$OUT/$side.core.folded"
    "$TASKSET" -c "$PROFILE_CPUSET" "$NICE" -n "$PROFILE_NICE" \
      "$PERF" script -C "$ATOM_CPUS" -i "$OUT/$side.perf.data" \
      >"$OUT/$side.atom.perf.script"
    "$STACKCOLLAPSE" "$OUT/$side.atom.perf.script" >"$OUT/$side.atom.folded"
    if [[ -s $OUT/$side.core.folded ]]; then
      cp "$OUT/$side.core.folded" "$OUT/$side.folded"
    elif [[ -s $OUT/$side.atom.folded ]]; then
      cp "$OUT/$side.atom.folded" "$OUT/$side.folded"
    fi
  fi
  "$TASKSET" -c "$PROFILE_CPUSET" "$NICE" -n "$PROFILE_NICE" \
    "$FLAMEGRAPH" --title "Ironet V2 $side" "$OUT/$side.folded" >"$OUT/$side.svg"
done

python3 - "$OUT" "$PERF_FREQUENCY" \
  "$A_TO_B_DELAY_MS" "$A_TO_B_JITTER_MS" "$A_TO_B_DELAY_CORRELATION_PERCENT" \
  "$A_TO_B_LOSS_PERCENT" "$A_TO_B_LOSS_CORRELATION_PERCENT" \
  "$B_TO_A_DELAY_MS" "$B_TO_A_JITTER_MS" "$B_TO_A_DELAY_CORRELATION_PERCENT" \
  "$B_TO_A_LOSS_PERCENT" "$B_TO_A_LOSS_CORRELATION_PERCENT" \
  "$A_TO_B_RATE_MBIT" "$B_TO_A_RATE_MBIT" \
  "$A_TO_B_QUEUE_PACKETS" "$B_TO_A_QUEUE_PACKETS" "$CALL_GRAPH" \
  "$BINARY_SHA256" "$CONCURRENT_PING_INTERVAL_MS" "$PROFILE_DIRECTION" \
  "$SCENARIO_NAME" "$TIMELINE" "$PERF_ENABLED" "$DURATION" \
  "$AUTOTUNE_OBJECTIVE" "$A_TO_B_PROPAGATION_PACKETS" \
  "$A_TO_B_NETEM_LIMIT_PACKETS" "$B_TO_A_PROPAGATION_PACKETS" \
  "$B_TO_A_NETEM_LIMIT_PACKETS" "$NETEM_WIRE_PACKET_BYTES" \
  "$NETEM_NORMAL_JITTER_TAIL_SIGMAS" "$A_TO_B_PROPAGATION_ENVELOPE_MS" \
  "$B_TO_A_PROPAGATION_ENVELOPE_MS" <<'PY'
import csv, datetime, io, json, pathlib, re, statistics, sys
out = pathlib.Path(sys.argv[1])
# Older daemon builds coloured stderr even when redirected; parse both forms.
ANSI = re.compile(r"\x1b\[[0-9;]*m")
perf_enabled = sys.argv[23] == "1"
sampling_frequency_hz = int(sys.argv[2]) if perf_enabled else None
duration_seconds = int(sys.argv[24])
autotune_objective = sys.argv[25]
ping_interval_ms = int(sys.argv[19])
def rate(name):
    data = json.loads((out / name).read_text())
    return data["end"]["sum_received"]["bits_per_second"]
def lost_samples(side):
    path = out / f"{side}.report.txt"
    if not path.exists():
        return None
    report = path.read_text(errors="replace")
    values = [int(value) for value in re.findall(r"Total Lost Samples:\s*(\d+)", report)]
    return sum(values)
def saturation_started():
    path = out / "saturation-started-at.txt"
    if not path.exists():
        return None, None
    lines = path.read_text().split()
    return lines[0], int(lines[1])
saturation_started_iso, saturation_started_ns = saturation_started()
def iperf_intervals(name, expected_sender=None):
    # iperf3 reports one aggregate sample per second. Both dynamic runs take
    # their own anchor immediately before the client, so their offsets share
    # the same timeline grammar even though they run sequentially. Preserve
    # bytes and duration: averaging interval rates would overweight a short
    # final sample and cannot correctly apportion an interval across a
    # timeline boundary.
    data = json.loads((out / name).read_text())
    series = []
    for interval in data.get("intervals", []):
        total = interval.get("sum") or {}
        if "bits_per_second" not in total:
            continue
        sender = total.get("sender")
        if expected_sender is not None and sender is not expected_sender:
            raise SystemExit(
                f"{name} contains {'sender' if sender else 'receiver'} intervals; "
                f"expected {'sender' if expected_sender else 'receiver'} intervals"
            )
        series.append({
            "start_seconds": float(total.get("start", 0.0)),
            "end_seconds": float(total.get("end", 0.0)),
            "seconds": float(total.get("seconds", 0.0)),
            "bytes": int(total.get("bytes", 0)),
            "bits_per_second": float(total["bits_per_second"]),
            "retransmits": total.get("retransmits"),
            "sender": sender,
        })
    return series
def receiver_interval_name(prefix):
    return f"{prefix}-server.json" if sys.argv[20] == "forward" else f"{prefix}.json"
def overlay_intervals():
    # In forward mode the client intervals describe bytes accepted by the
    # sending TCP socket, not bytes delivered through the overlay. The server
    # JSON is the receiver record. In reverse mode the client is the receiver.
    name = receiver_interval_name("overlay")
    return iperf_intervals(name, expected_sender=False)
def underlay_intervals():
    name = receiver_interval_name("underlay")
    return iperf_intervals(name, expected_sender=False)
def ping_series():
    # Per-second latency buckets from the concurrent overlay ping; icmp_seq
    # starts at 1 and the interval is fixed, so arrival second is derived
    # without relying on ping's optional -D timestamps.
    path = out / "overlay-concurrent-ping.txt"
    if not path.exists() or ping_interval_ms == 0:
        return None
    buckets = {}
    for match in re.finditer(r"icmp_seq=(\d+) .*?time[=<]([0-9.]+) ms", path.read_text(errors="replace")):
        second = int((int(match.group(1)) - 1) * ping_interval_ms / 1000)
        buckets.setdefault(second, []).append(float(match.group(2)))
    series = []
    for second in sorted(buckets):
        samples = sorted(buckets[second])
        series.append({
            "second": second,
            "samples": len(samples),
            "p50_ms": samples[len(samples) // 2],
            "maximum_ms": samples[-1],
        })
    return series
def parse_kv(text):
    return {
        key: (float(value) if re.fullmatch(r"[0-9]+([.][0-9]+)?", value) else value)
        for key, value in (item.split("=", 1) for item in text.split(",") if item)
    }
def qdisc_counters(label, direction):
    path = out / f"{label}-{direction}-qdisc.txt"
    if not path.exists():
        return None
    text = path.read_text(errors="replace")
    sent = re.search(r"Sent (\d+) bytes (\d+) pkt \(dropped (\d+), overlimits (\d+) requeues (\d+)\)", text)
    if not sent:
        return None
    return {
        "bytes": int(sent.group(1)),
        "packets": int(sent.group(2)),
        "dropped": int(sent.group(3)),
        "overlimits": int(sent.group(4)),
    }
def qdisc_delta(before, after, direction):
    first = qdisc_counters(before, direction)
    last = qdisc_counters(after, direction)
    if first is None or last is None:
        return None
    delta = {key: last[key] - first[key] for key in first}
    if any(value < 0 for value in delta.values()):
        raise SystemExit(
            f"qdisc counters decreased across {before}->{after} ({direction}); "
            "the phase boundary no longer refers to one cumulative qdisc instance"
        )
    return delta
TIMELINE_FIELDS = (
    "step", "offset_seconds", "applied_offset_ms", "changes", "a_to_b", "b_to_a",
    "a_seed", "b_seed", "primary", "secondary",
)
def parse_timeline(handle):
    reader = csv.DictReader(handle, delimiter="\t")
    missing = [field for field in TIMELINE_FIELDS if field not in (reader.fieldnames or [])]
    if missing:
        raise SystemExit(f"timeline TSV is missing fields: {missing}")
    steps = []
    for row in reader:
        steps.append({
            "step": int(row["step"]),
            "offset_seconds": int(row["offset_seconds"]),
            "applied_offset_ms": int(row["applied_offset_ms"]),
            "changes": parse_kv(row["changes"]),
            "netem_after": {
                "a_to_b": parse_kv(row["a_to_b"]),
                "b_to_a": parse_kv(row["b_to_a"]),
            },
            "a_seed": int(row["a_seed"]),
            "b_seed": int(row["b_seed"]),
            "underlay_paths_after": {
                "primary": row["primary"],
                "secondary": row["secondary"],
            },
        })
    return steps
def verify_timeline_parser():
    fixture = io.StringIO(
        "\t".join(TIMELINE_FIELDS) + "\n"
        "1\t20\t20007\ta_loss=5\tdelay=42\tdelay=42\t123\t456\tdown\tup\n"
    )
    parsed = parse_timeline(fixture)
    if parsed != [{
        "step": 1,
        "offset_seconds": 20,
        "applied_offset_ms": 20007,
        "changes": {"a_loss": 5.0},
        "netem_after": {"a_to_b": {"delay": 42.0}, "b_to_a": {"delay": 42.0}},
        "a_seed": 123,
        "b_seed": 456,
        "underlay_paths_after": {"primary": "down", "secondary": "up"},
    }]:
        raise SystemExit(f"timeline TSV parser self-test failed: {parsed!r}")
verify_timeline_parser()
def timeline_steps():
    path = out / "timeline.tsv"
    if not path.exists():
        return []
    with path.open(newline="") as handle:
        return parse_timeline(handle)
def underlay_timeline_steps():
    path = out / "underlay-timeline.tsv"
    if not path.exists():
        return []
    with path.open(newline="") as handle:
        return parse_timeline(handle)
def settle_seconds(values, start_offset):
    # First second after which throughput stays within ±10% of the segment's
    # final level (median of its last five samples) for three consecutive
    # samples. None means the segment never settled or was too short.
    if len(values) < 5:
        return None
    target = statistics.median(value for _, value in values[-5:])
    if target <= 0:
        return None
    streak = 0
    for second, value in values:
        if abs(value - target) <= 0.10 * target:
            streak += 1
            if streak == 3:
                return second - 2 - start_offset
        else:
            streak = 0
    return None
def interval_window_rate(intervals, start, end):
    """Receiver bits delivered in [start, end), divided by wall-clock width."""
    if end <= start:
        return None
    delivered_bytes = 0.0
    has_overlap = False
    for interval in intervals or []:
        interval_start = interval["start_seconds"]
        interval_end = interval["end_seconds"]
        overlap = max(0.0, min(end, interval_end) - max(start, interval_start))
        if overlap <= 0.0:
            continue
        interval_seconds = interval["seconds"] or (interval_end - interval_start)
        if interval_seconds <= 0.0:
            continue
        delivered_bytes += interval["bytes"] * overlap / interval_seconds
        has_overlap = True
    return delivered_bytes * 8.0 / (end - start) if has_overlap else None
def verify_interval_window_rate():
    # Exercise both sides of a timeline boundary. A simple mean would return
    # 1,000 bps; overlap accounting yields 200 bytes in 1.5 seconds.
    synthetic = [
        {"start_seconds": 0.0, "end_seconds": 1.0, "seconds": 1.0, "bytes": 100},
        {"start_seconds": 1.0, "end_seconds": 3.0, "seconds": 2.0, "bytes": 300},
    ]
    measured = interval_window_rate(synthetic, 0.5, 2.0)
    if measured is None or abs(measured - (3_200.0 / 3.0)) > 1e-6:
        raise SystemExit(f"receiver interval overlap accounting self-test failed: {measured}")
verify_interval_window_rate()
def applied_boundaries(steps):
    return [0.0] + [step["applied_offset_ms"] / 1_000.0 for step in steps] + [float(duration_seconds)]
def verify_applied_boundaries():
    synthetic = [
        {"applied_offset_ms": 20_125},
        {"applied_offset_ms": 40_075},
    ]
    if applied_boundaries(synthetic) != [0.0, 20.125, 40.075, float(duration_seconds)]:
        raise SystemExit("actual timeline boundary self-test failed")
verify_applied_boundaries()
def segment_qdisc_labels(steps):
    return (
        ["netem-before-overlay"]
        + [f"timeline-{step['step']:02d}-after" for step in steps],
        [f"timeline-{step['step']:02d}-before" for step in steps]
        + ["netem-after-overlay"],
    )
def verify_segment_qdisc_labels():
    labels, next_labels = segment_qdisc_labels([{"step": 1}])
    if labels != ["netem-before-overlay", "timeline-01-after"] or next_labels != [
        "timeline-01-before", "netem-after-overlay"
    ]:
        raise SystemExit("overlay segment qdisc phase-boundary self-test failed")
verify_segment_qdisc_labels()
def segments(steps, intervals, pings, baseline_intervals=None, baseline_steps=None):
    requested_boundaries = [0] + [step["offset_seconds"] for step in steps] + [duration_seconds]
    overlay_boundaries = applied_boundaries(steps)
    underlay_boundaries = (
        applied_boundaries(baseline_steps)
        if baseline_steps else [float(value) for value in requested_boundaries]
    )
    if len(underlay_boundaries) != len(overlay_boundaries):
        raise SystemExit("underlay/overlay timeline boundary count differs")
    labels, next_labels = segment_qdisc_labels(steps)
    result = []
    for index in range(len(requested_boundaries) - 1):
        requested_start, requested_end = requested_boundaries[index:index + 2]
        overlay_start, overlay_end = overlay_boundaries[index:index + 2]
        underlay_start, underlay_end = underlay_boundaries[index:index + 2]
        values = [
            (int(interval["start_seconds"]), interval["bits_per_second"])
            for interval in intervals
            if overlay_start <= interval["start_seconds"] < overlay_end
        ]
        rates = [value for _, value in values]
        overlay_rate = interval_window_rate(intervals, overlay_start, overlay_end)
        baseline_rates = [
            interval["bits_per_second"] for interval in (baseline_intervals or [])
            if underlay_start <= interval["start_seconds"] < underlay_end
        ]
        underlay_rate = interval_window_rate(
            baseline_intervals, underlay_start, underlay_end
        )
        overlay_last5_start = max(overlay_start, overlay_end - 5)
        underlay_last5_start = max(underlay_start, underlay_end - 5)
        overlay_last5_rate = interval_window_rate(
            intervals, overlay_last5_start, overlay_end
        )
        underlay_last5_rate = interval_window_rate(
            baseline_intervals, underlay_last5_start, underlay_end
        )
        ping_values = [
            sample for sample in (pings or [])
            if overlay_start <= sample["second"] < overlay_end
        ]
        p50 = sorted(sample["p50_ms"] for sample in ping_values)
        result.append({
            "index": index,
            "start_seconds": requested_start,
            "end_seconds": requested_end,
            "overlay_applied_start_seconds": overlay_start,
            "overlay_applied_end_seconds": overlay_end,
            "underlay_applied_start_seconds": underlay_start,
            "underlay_applied_end_seconds": underlay_end,
            "netem_step": steps[index - 1]["changes"] if index else None,
            "overlay_mean_bits_per_second": overlay_rate,
            "overlay_median_bits_per_second": statistics.median(rates) if rates else None,
            "overlay_last5_mean_bits_per_second": overlay_last5_rate,
            "underlay_mean_bits_per_second": underlay_rate,
            "underlay_median_bits_per_second":
                statistics.median(baseline_rates) if baseline_rates else None,
            "underlay_last5_mean_bits_per_second": underlay_last5_rate,
            "overlay_to_underlay_ratio": (
                overlay_rate / underlay_rate
                if overlay_rate is not None and underlay_rate else None
            ),
            "settle_seconds": settle_seconds(values, overlay_start),
            "ping_seconds": len(ping_values),
            "ping_p50_of_second_p50_ms": p50[len(p50) // 2] if p50 else None,
            "ping_max_ms": max(sample["maximum_ms"] for sample in ping_values) if ping_values else None,
            "a_to_b_qdisc": qdisc_delta(labels[index], next_labels[index], "a-to-b"),
            "b_to_a_qdisc": qdisc_delta(labels[index], next_labels[index], "b-to-a"),
        })
    return result
def phase_qdisc_deltas():
    phases = {
        "underlay": ("netem-before-underlay", "netem-after-underlay"),
        "overlay": ("netem-before-overlay", "netem-after-overlay"),
    }
    result = {
        "counter_semantics": "phase_delta_after_epoch_restore",
        "rate_model": "netem_serializing_shallow_shaper",
    }
    for phase, (before, after) in phases.items():
        result[phase] = {
            "a_to_b": qdisc_delta(before, after, "a-to-b"),
            "b_to_a": qdisc_delta(before, after, "b-to-a"),
        }
        if any(value is None for value in result[phase].values()):
            raise SystemExit(f"missing {phase} qdisc phase counter snapshot")
    return result
TUNING_FIELDS = (
    "reason", "path_epoch", "samples", "rtt_micros", "minimum_rtt_micros",
    "congestion_window_bytes", "controller_pacing_rate_bytes_per_second",
    "loss_ppm", "tx_bytes_per_second", "rx_bytes_per_second",
    "cpu_utilization_per_mille", "train_target_bytes", "bulk_quantum_cells",
    "send_buffer_bytes", "receive_buffer_bytes", "latency_queue_sojourn_p95_micros",
)
def tuning_status_series(side):
    # The daemon logs one "V2 automatic tuning status" record every ten
    # samples. Align it to the saturation anchor so decisions can be read
    # against timeline steps. This is coarse by design; per-second recording
    # is the autotune recorder's job.
    path = out / f"{side}.log"
    if not path.exists() or saturation_started_ns is None:
        return None
    anchor = saturation_started_ns / 1e9
    series = []
    for line in path.read_text(errors="replace").splitlines():
        if "V2 automatic tuning status" not in line:
            continue
        line = ANSI.sub("", line)
        stamp = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?)Z", line)
        if not stamp:
            continue
        when = datetime.datetime.fromisoformat(stamp.group(1)).replace(
            tzinfo=datetime.timezone.utc).timestamp()
        record = {"offset_seconds": round(when - anchor, 3)}
        for field in TUNING_FIELDS:
            match = re.search(rf"\b{field}=(\"[^\"]*\"|\S+)", line)
            if match:
                value = match.group(1).strip('"')
                record[field] = int(value) if value.isdigit() else value
        fec = re.search(r"\bfec=(None|Some\(FecGeometryV2 \{ data_cells: (\d+), parity_cells: (\d+) \}\))", line)
        if fec:
            record["fec"] = None if fec.group(1) == "None" else f"{fec.group(2)}+{fec.group(3)}"
        series.append(record)
    return series
def autotune_tap_series(side):
    path = out / f"{side}.log"
    if not path.exists():
        return None
    anchor = saturation_started_ns / 1e9 if saturation_started_ns is not None else None
    series = []
    for raw_line in path.read_text(errors="replace").splitlines():
        if "V2 autotune tap" not in raw_line or " record=" not in raw_line:
            continue
        line = ANSI.sub("", raw_line)
        payload = line.split(" record=", 1)[1]
        try:
            record = json.loads(payload)
        except json.JSONDecodeError:
            continue
        sampled = record.get("sampled_unix_micros")
        record["offset_seconds"] = (
            round(sampled / 1e6 - anchor, 6)
            if anchor is not None and isinstance(sampled, int) else None
        )
        series.append(record)
    return series
def controller_interval_series(side, intervals):
    records = [
        record for record in (autotune_tap_series(side) or [])
        if isinstance(record.get("offset_seconds"), (int, float))
        and record["offset_seconds"] >= 0
    ]
    series = []
    for interval in intervals:
        midpoint = (interval["start_seconds"] + interval["end_seconds"]) / 2
        if not records:
            break
        record = min(records, key=lambda item: abs(item["offset_seconds"] - midpoint))
        if abs(record["offset_seconds"] - midpoint) > 1.5:
            continue
        telemetry = record.get("telemetry") or {}
        controller = record.get("controller") or {}
        decision = record.get("decision") or {}
        series.append({
            "start_seconds": interval["start_seconds"],
            "end_seconds": interval["end_seconds"],
            "tap_offset_seconds": record["offset_seconds"],
            "path_identity": record.get("path_identity"),
            "path_epoch": telemetry.get("path_epoch"),
            "overlay_bits_per_second": interval["bits_per_second"],
            "controller_state": telemetry.get("controller_state"),
            "controller_bw_bytes_per_second": telemetry.get("controller_bw_bytes_per_second"),
            "controller_pacing_rate_bytes_per_second": telemetry.get("controller_pacing_rate_bytes_per_second"),
            "controller_congestion_window_bytes": controller.get("congestion_window_bytes"),
            "adaptive_cwnd_floor_bytes": controller.get("adaptive_cwnd_floor_bytes"),
            "delivery_rate_bytes_per_second": telemetry.get("delivery_rate_bytes_per_second"),
            "tun_ingress_bytes_per_second": telemetry.get("tun_ingress_bytes_per_second"),
            "packet_train_queue_bytes": telemetry.get("packet_train_queue_bytes"),
            "queue_delay_micros": telemetry.get("queue_delay_micros"),
            "controller_app_limited": telemetry.get("controller_app_limited"),
            "bbr_preset": (decision.get("bbr") or {}).get("preset"),
        })
    return series
def controller_alignment_summary(series):
    if not series:
        return None
    steady = [
        row for row in series
        if row.get("controller_app_limited") is False
        and isinstance(row.get("packet_train_queue_bytes"), (int, float))
        and row["packet_train_queue_bytes"] >= 128 * 1024
    ]
    if not steady:
        steady = series
    def mean(field, rows):
        values = [float(row[field]) for row in rows if isinstance(row.get(field), (int, float))]
        return statistics.fmean(values) if values else None
    def correlation(field):
        pairs = [
            (float(row["overlay_bits_per_second"]), float(row[field]))
            for row in steady
            if isinstance(row.get(field), (int, float))
        ]
        if len(pairs) < 2 or len({x for x, _ in pairs}) < 2 or len({y for _, y in pairs}) < 2:
            return None
        return statistics.correlation([x for x, _ in pairs], [y for _, y in pairs])
    final = steady[-min(5, len(steady)):]
    identities = [row.get("path_identity") for row in series if row.get("path_identity")]
    epochs = [row.get("path_epoch") for row in series if isinstance(row.get("path_epoch"), int)]
    return {
        "samples": len(series),
        "steady_samples": len(steady),
        "path_identities": list(dict.fromkeys(identities)),
        "path_identity_switches": sum(a != b for a, b in zip(identities, identities[1:])),
        "path_epoch_switches": sum(a != b for a, b in zip(epochs, epochs[1:])),
        "overlay_controller_bw_correlation": correlation("controller_bw_bytes_per_second"),
        "overlay_cwnd_correlation": correlation("controller_congestion_window_bytes"),
        "overlay_cwnd_floor_correlation": correlation("adaptive_cwnd_floor_bytes"),
        "final5_overlay_bits_per_second_mean": mean("overlay_bits_per_second", final),
        "final5_controller_bw_bytes_per_second_mean": mean("controller_bw_bytes_per_second", final),
        "final5_controller_cwnd_bytes_mean": mean("controller_congestion_window_bytes", final),
        "final5_adaptive_cwnd_floor_bytes_mean": mean("adaptive_cwnd_floor_bytes", final),
        "final5_packet_train_queue_bytes_mean": mean("packet_train_queue_bytes", final),
    }
def autotune_summary(side):
    records = [
        record for record in (autotune_tap_series(side) or [])
        if isinstance(record.get("utility", {}).get("total"), (int, float))
        and (record.get("offset_seconds") is None or record["offset_seconds"] >= 0)
    ]
    if not records:
        return None
    utilities = [float(record["utility"]["total"]) for record in records]
    ordered = sorted(utilities)
    p10 = ordered[max(0, int((len(ordered) - 1) * 0.10))]
    final_window = utilities[-min(10, len(utilities)):]
    final_mean = statistics.fmean(final_window)
    tolerance = max(abs(final_mean) * 0.05, 1e-9)
    convergence = next((
        record.get("offset_seconds")
        for record, value in zip(records, utilities)
        if abs(value - final_mean) <= tolerance
    ), None)
    def action(record):
        decision = record.get("decision", {})
        return {
            key: decision.get(key) for key in (
                "train_target_bytes", "bulk_quantum_cells", "fec",
                "cover_profile", "cover_overhead_per_mille", "bbr",
            )
        }
    actions = [action(record) for record in records]
    switches = sum(left != right for left, right in zip(actions, actions[1:]))
    fec_histogram = {}
    for record in records:
        fec = record.get("decision", {}).get("fec")
        key = "off" if fec is None else f"{fec.get('data_cells')}+{fec.get('parity_cells')}"
        fec_histogram[key] = fec_histogram.get(key, 0) + 1
    residual = [
        record.get("telemetry", {}).get("residual_loss_ppm") for record in records
        if isinstance(record.get("telemetry", {}).get("residual_loss_ppm"), (int, float))
    ]
    sojourn = [
        record.get("telemetry", {}).get("latency_sojourn_p95_micros") for record in records
        if isinstance(record.get("telemetry", {}).get("latency_sojourn_p95_micros"), (int, float))
    ]
    learner_rollbacks = [
        record.get("learner", {}).get("rollbacks", 0) for record in records
        if isinstance(record.get("learner"), dict)
    ]
    pending_generations = sum(
        record.get("telemetry", {}).get("controller_tunables_generation")
        != record.get("telemetry", {}).get("controller_params_generation")
        for record in records
        if isinstance(record.get("telemetry", {}).get("controller_tunables_generation"), int)
        and isinstance(record.get("telemetry", {}).get("controller_params_generation"), int)
    )
    shadow_records = [
        record["shadow"] for record in records
        if isinstance(record.get("shadow"), dict)
    ]
    shadow_advantages = [
        float(candidate["trace"]["predicted_advantage"])
        for candidate in shadow_records
        if isinstance(candidate.get("trace", {}).get("predicted_advantage"), (int, float))
    ]
    shadow_presets = [
        candidate.get("trace", {}).get("proposed_preset")
        for candidate in shadow_records
        if candidate.get("trace", {}).get("proposed_preset") is not None
    ]
    shadow_histogram = {}
    for preset in shadow_presets:
        shadow_histogram[preset] = shadow_histogram.get(preset, 0) + 1
    shadow_summary = None
    if shadow_records:
        last_advantages = shadow_advantages[-min(10, len(shadow_advantages)):]
        shadow_summary = {
            "samples": len(shadow_records),
            "policy_id": shadow_records[-1].get("policy_id"),
            "final_proposed_preset": shadow_presets[-1] if shadow_presets else None,
            "preset_switches": sum(
                left != right for left, right in zip(shadow_presets, shadow_presets[1:])
            ),
            "preset_histogram": shadow_histogram,
            "predicted_advantage_mean": (
                statistics.fmean(shadow_advantages) if shadow_advantages else None
            ),
            "predicted_advantage_last10_mean": (
                statistics.fmean(last_advantages) if last_advantages else None
            ),
        }
    return {
        "samples": len(records),
        "utility_mean": statistics.fmean(utilities),
        "utility_last10_mean": final_mean,
        "utility_p10": p10,
        "final_preset": actions[-1],
        "preset_switches": switches,
        "rollbacks": max(learner_rollbacks, default=0),
        "controller_generation_pending_samples": pending_generations,
        "convergence_seconds": convergence,
        "fec_geometry_histogram": fec_histogram,
        "residual_loss_ppm_mean": statistics.fmean(residual) if residual else None,
        "latency_sojourn_p95_mean": statistics.fmean(sojourn) if sojourn else None,
        "shadow": shadow_summary,
    }
def concurrent_ping(kind):
    path = out / f"{kind}-concurrent-ping.txt"
    if not path.exists():
        return None
    text = path.read_text(errors="replace")
    samples = sorted(float(value) for value in re.findall(r"time[=<]([0-9.]+) ms", text))
    transmitted = re.search(r"(\d+) packets transmitted", text)
    received = re.search(r"(\d+) received", text)
    def percentile(p):
        if not samples:
            return None
        index = max(0, min(len(samples) - 1, int((len(samples) - 1) * p + 0.5)))
        return samples[index]
    sent = int(transmitted.group(1)) if transmitted else 0
    got = int(received.group(1)) if received else len(samples)
    return {
        "interval_ms": int(sys.argv[19]),
        "transmitted": sent,
        "received": got,
        "loss_percent": ((sent - got) * 100 / sent) if sent else None,
        "p50_ms": percentile(0.50),
        "p95_ms": percentile(0.95),
        "p99_ms": percentile(0.99),
        "maximum_ms": samples[-1] if samples else None,
    }
def udp_fairness():
    path = out / "overlay-fairness.json"
    if not path.exists():
        return None
    data = json.loads(path.read_text())
    offered_rates = []
    delivered_rates = []
    loss_percentages = []
    for stream in data.get("end", {}).get("streams", []):
        sample = stream.get("udp") or stream.get("receiver") or {}
        if "bits_per_second" in sample:
            offered = float(sample["bits_per_second"])
            packets = int(sample.get("packets", 0))
            lost = min(packets, max(0, int(sample.get("lost_packets", 0))))
            delivered = offered * (packets - lost) / packets if packets else offered
            offered_rates.append(offered)
            delivered_rates.append(delivered)
            loss_percentages.append(lost * 100 / packets if packets else None)
    if not delivered_rates:
        return None
    mean = sum(delivered_rates) / len(delivered_rates)
    squares = sum(value * value for value in delivered_rates)
    return {
        "streams": len(delivered_rates),
        "per_stream_offered_bits_per_second": offered_rates,
        "per_stream_delivered_bits_per_second": delivered_rates,
        "per_stream_loss_percent": loss_percentages,
        "mean_bits_per_second": mean,
        "maximum_deviation_percent":
            max(abs(value - mean) for value in delivered_rates) * 100 / mean if mean else None,
        "spread_percent":
            (max(delivered_rates) - min(delivered_rates)) * 100 / mean if mean else None,
        "jain_fairness":
            (sum(delivered_rates) ** 2) / (len(delivered_rates) * squares)
            if squares else None,
    }
def peer_traffic_value(peer, field):
    if field in peer:
        return int(peer[field] or 0)
    return int((peer.get("traffic") or {}).get(field, 0) or 0)
def peer_counter(side, label, field):
    path = out / f"{side}-{label}-status.json"
    if not path.exists():
        return None
    peers = json.loads(path.read_text()).get("peers", [])
    return sum(peer_traffic_value(peer, field) for peer in peers)
def counter_window(side, before, after, field):
    first = peer_counter(side, before, field)
    last = peer_counter(side, after, field)
    if first is None or last is None:
        return None
    return max(0, last - first)
def cover_profile():
    path = out / "overlay-cover.json"
    if not path.exists():
        return None
    delivered = rate("overlay-cover.json")
    active_cover = counter_window("a", "cover-before", "cover-after", "cover_tx_bytes")
    active_real = counter_window(
        "a", "cover-before", "cover-after", "cell_payload_tx_bytes"
    )
    saturated_cover = counter_window(
        "a", "saturation-before", "saturation-after", "cover_tx_bytes"
    )
    saturated_real = counter_window(
        "a", "saturation-before", "saturation-after", "cell_payload_tx_bytes"
    )
    return {
        "delivered_bits_per_second": delivered,
        "active_cover_tx_bytes": active_cover,
        "active_cell_payload_tx_bytes": active_real,
        "active_cover_to_cell_payload_ratio": (
            active_cover / active_real if active_real else None
        ),
        "saturated_cover_tx_bytes": saturated_cover,
        "saturated_cell_payload_tx_bytes": saturated_real,
        "saturated_cover_to_cell_payload_ratio": (
            saturated_cover / saturated_real if saturated_real else None
        ),
    }
def final_class_queues(side):
    peers = json.loads((out / f"{side}-final-status.json").read_text()).get("peers", [])
    train = sum(peer_traffic_value(peer, "packet_train_queue_bytes") for peer in peers)
    latency = sum(peer_traffic_value(peer, "latency_queue_bytes") for peer in peers)
    return {
        "peers": len(peers),
        "packet_train_queue_bytes": train,
        "latency_queue_bytes": latency,
        "drained": train == 0 and latency == 0,
    }
def final_tun_admission_shed(side):
    status = json.loads((out / f"{side}-final-status.json").read_text())
    peers = status.get("peers", [])
    return {
        "records": int(status.get("tun_admission_drop_records", 0)) + sum(
            peer_traffic_value(peer, "tun_admission_drop_records") for peer in peers
        ),
        "bytes": int(status.get("tun_admission_drop_bytes", 0)) + sum(
            peer_traffic_value(peer, "tun_admission_drop_bytes") for peer in peers
        ),
    }
def final_datagram_shape(side):
    peers = json.loads((out / f"{side}-final-status.json").read_text()).get("peers", [])
    cells = sum(peer_traffic_value(peer, "cells_built") for peer in peers)
    full = sum(peer_traffic_value(peer, "full_payload_cells_built") for peer in peers)
    cover = sum(peer_traffic_value(peer, "cover_tx_bytes") for peer in peers)
    real = sum(peer_traffic_value(peer, "cell_payload_tx_bytes") for peer in peers)
    return {
        "cells_built": cells,
        "full_payload_cells_built": full,
        "full_payload_cell_ratio": full / cells if cells else None,
        "cover_tx_bytes": cover,
        "cell_payload_tx_bytes": real,
        "cover_to_cell_payload_ratio": cover / real if real else None,
    }
underlay = rate("underlay.json")
overlay = rate("overlay.json")
comparison_path = out / "timeline-comparison.json"
comparison = json.loads(comparison_path.read_text()) if comparison_path.exists() else {
    "mode": "unknown", "comparable": False
}
synchronization_path = out / "timeline-synchronization.json"
synchronization = (
    json.loads(synchronization_path.read_text())
    if synchronization_path.exists() else None
)
underlay_ping = concurrent_ping("underlay")
overlay_ping = concurrent_ping("overlay")
latency_increment = None
if underlay_ping is not None and overlay_ping is not None:
    latency_increment = {
        key: (overlay_ping[key] - underlay_ping[key])
        if overlay_ping[key] is not None and underlay_ping[key] is not None else None
        for key in ("p50_ms", "p95_ms", "p99_ms", "maximum_ms")
    }
steps = timeline_steps()
intervals = overlay_intervals()
baseline_intervals = underlay_intervals() if comparison.get("comparable") else None
baseline_steps = (
    underlay_timeline_steps()
    if comparison.get("comparable") and steps else None
)
pings = ping_series()
active_side = "a" if sys.argv[20] == "forward" else "b"
controller_intervals = controller_interval_series(active_side, intervals)
segment_results = segments(
    steps, intervals, pings, baseline_intervals, baseline_steps
)
static_endpoint_consistency = None
if not steps and comparison.get("comparable") and segment_results:
    static_segment = segment_results[0]
    endpoint_ratio = overlay / underlay if underlay else None
    segment_ratio = static_segment["overlay_to_underlay_ratio"]
    def relative_error(measured, expected):
        return abs(measured / expected - 1.0) if measured is not None and expected else None
    relative_errors = {
        "overlay": relative_error(
            static_segment["overlay_mean_bits_per_second"], overlay
        ),
        "underlay": relative_error(
            static_segment["underlay_mean_bits_per_second"], underlay
        ),
        "ratio": relative_error(segment_ratio, endpoint_ratio),
    }
    # iperf's receiver endpoint includes its final partial interval, whose end
    # can extend slightly beyond the requested wall-clock window on a very
    # lossy low-rate path. Bound each endpoint independently; the ratio error
    # can legitimately contain both endpoint errors in opposite directions.
    endpoint_tolerance = 0.03
    ratio_tolerance = 2 * endpoint_tolerance / (1 - endpoint_tolerance)
    static_endpoint_consistency = {
        "receiver_interval_window_seconds": duration_seconds,
        "relative_tolerance": endpoint_tolerance,
        "ratio_relative_tolerance": ratio_tolerance,
        "relative_errors": relative_errors,
        "consistent": (
            all(
                relative_errors[key] is None
                or relative_errors[key] <= endpoint_tolerance
                for key in ("overlay", "underlay")
            )
            and (
                relative_errors["ratio"] is None
                or relative_errors["ratio"] <= ratio_tolerance
            )
        ),
    }
summary = {
    "scenario": sys.argv[21],
    "direction": sys.argv[20],
    "duration_seconds": duration_seconds,
    "autotune_objective": autotune_objective,
    "perf_enabled": perf_enabled,
    "sampling_frequency_hz": sampling_frequency_hz,
    "call_graph": sys.argv[17] if perf_enabled else None,
    "binary_sha256": sys.argv[18],
    "saturation_started_at": saturation_started_iso,
    "timeline_spec": sys.argv[22] or None,
    "timeline": steps,
    "throughput_comparison": comparison,
    "timeline_synchronization": synchronization,
    "segments": segment_results,
    "shallow_shaper_phase_counters": phase_qdisc_deltas(),
    "receiver_interval_source": {
        "overlay": receiver_interval_name("overlay"),
        "underlay": receiver_interval_name("underlay")
            if comparison.get("comparable") else None,
    },
    "static_endpoint_consistency": static_endpoint_consistency,
    "overlay_interval_series": intervals,
    "underlay_interval_series": baseline_intervals,
    "controller_interval_series": controller_intervals,
    "controller_alignment": controller_alignment_summary(controller_intervals),
    "overlay_ping_series": pings,
    "tuning_status": {side: tuning_status_series(side) for side in ("a", "b")},
    "autotune_tap": {side: autotune_tap_series(side) for side in ("a", "b")},
    "autotune": {side: autotune_summary(side) for side in ("a", "b")},
    "autotune_force": (
        json.loads((out / "autotune-force.json").read_text())
        if (out / "autotune-force.json").exists() else None
    ),
    "underlay_received_bits_per_second": underlay,
    "overlay_received_bits_per_second": overlay,
    "overlay_to_underlay_ratio": (
        overlay / underlay if comparison.get("comparable") and underlay else None
    ),
    "a_perf_lost_samples": lost_samples("a"),
    "b_perf_lost_samples": lost_samples("b"),
    "netem": {
        "a_to_b_delay_ms": float(sys.argv[3]),
        "a_to_b_jitter_ms": float(sys.argv[4]),
        "a_to_b_delay_correlation_percent": float(sys.argv[5]),
        "a_to_b_loss_percent": float(sys.argv[6]),
        "a_to_b_loss_correlation_percent": float(sys.argv[7]),
        "a_to_b_loss_model": "gilbert_elliott" if float(sys.argv[7]) else "random",
        "b_to_a_delay_ms": float(sys.argv[8]),
        "b_to_a_jitter_ms": float(sys.argv[9]),
        "b_to_a_delay_correlation_percent": float(sys.argv[10]),
        "b_to_a_loss_percent": float(sys.argv[11]),
        "b_to_a_loss_correlation_percent": float(sys.argv[12]),
        "b_to_a_loss_model": "gilbert_elliott" if float(sys.argv[12]) else "random",
        "a_to_b_rate_mbit": float(sys.argv[13]),
        "b_to_a_rate_mbit": float(sys.argv[14]),
        "rate_model": "netem_serializing_shallow_shaper",
        "a_to_b_queue_packets": int(sys.argv[15]),
        "b_to_a_queue_packets": int(sys.argv[16]),
        "queue_packets_semantics": "excess_beyond_normal_delay_tail_envelope",
        "normal_jitter_tail_sigmas": int(sys.argv[31]),
        "a_to_b_propagation_envelope_ms": float(sys.argv[32]),
        "a_to_b_propagation_packets": int(sys.argv[26]),
        "a_to_b_limit_packets": int(sys.argv[27]),
        "b_to_a_propagation_envelope_ms": float(sys.argv[33]),
        "b_to_a_propagation_packets": int(sys.argv[28]),
        "b_to_a_limit_packets": int(sys.argv[29]),
        "wire_packet_bytes": int(sys.argv[30]),
    },
    "netem_seed_provenance": json.loads(
        (out / "netem-seed-provenance.json").read_text()
    ),
    "second_path": json.loads((out / "second-path.json").read_text()),
    "underlay_concurrent_ping": underlay_ping,
    "overlay_concurrent_ping": overlay_ping,
    "overlay_ping_increment_ms": latency_increment,
    "overlay_udp_fairness": udp_fairness(),
    "automatic_cover_profile": cover_profile(),
    "final_class_queues": {
        side: final_class_queues(side) for side in ("a", "b")
    },
    "tun_admission_shed": {
        side: final_tun_admission_shed(side) for side in ("a", "b")
    },
    "final_datagram_shape": {
        side: final_datagram_shape(side) for side in ("a", "b")
    },
}
(out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps(summary, indent=2))
PY

final_status=0
cleanup || final_status=96
if ! verify_management_plane; then
  ((final_status != 0)) || final_status=97
fi
trap - EXIT INT TERM HUP
((final_status == 0)) || exit "$final_status"
echo "$OUT"
