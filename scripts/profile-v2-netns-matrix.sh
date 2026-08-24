#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PROFILE_SCRIPT="$ROOT/scripts/profile-v2-netns.sh"
STAMP=$(date -u +%Y%m%d-%H%M%S)
MATRIX_OUT=${IRONET_V2_MATRIX_OUT:-$ROOT/target/v2-netns-matrix-$STAMP}
MATRIX_OUT=$(realpath -m "$MATRIX_OUT")
DURATION=${IRONET_V2_MATRIX_SECONDS:-15}
STREAMS=${IRONET_V2_MATRIX_STREAMS:-4}
FREQUENCY=${IRONET_V2_MATRIX_FREQUENCY:-99}
CALL_GRAPH=${IRONET_V2_MATRIX_CALL_GRAPH:-lbr}
PING_INTERVAL_MS=${IRONET_V2_MATRIX_PING_INTERVAL_MS:-20}
FAIRNESS_SECONDS=${IRONET_V2_MATRIX_FAIRNESS_SECONDS:-0}
FAIRNESS_PER_STREAM_MBIT=${IRONET_V2_MATRIX_FAIRNESS_PER_STREAM_MBIT:-10}
SETTLE_SECONDS=${IRONET_V2_MATRIX_SETTLE_SECONDS:-2}
SCENARIO_FILTER=${IRONET_V2_MATRIX_SCENARIOS:-all}
RESUME=${IRONET_V2_MATRIX_RESUME:-0}
MIN_OVERALL_RATIO=${IRONET_V2_MATRIX_MIN_OVERALL_RATIO:-0.90}
QUEUE_DRAIN_TIMEOUT_SECONDS=${IRONET_V2_PROFILE_QUEUE_DRAIN_TIMEOUT_SECONDS:-15}
# 1 = perf + FlameGraph per scenario (CPU profiling matrix). 0 = tuner
# behaviour only; much cheaper and the right mode for dynamic timelines.
PERF_ENABLED=${IRONET_V2_MATRIX_PERF:-1}
PROFILE_RUST_LOG=${IRONET_V2_PROFILE_RUST_LOG:-info,ironet::autotune=debug}
PROFILE_NICE=${IRONET_V2_PROFILE_NICE:-10}
AUTOTUNE_FORCE=${IRONET_AUTOTUNE_FORCE:-}
AUTOTUNE_MODE=${IRONET_V2_PROFILE_AUTOTUNE_MODE:-shadow}
AUTOTUNE_OBJECTIVE=${IRONET_V2_PROFILE_AUTOTUNE_OBJECTIVE:-balanced}
AUTOTUNE_MEMORY=${IRONET_V2_PROFILE_AUTOTUNE_MEMORY:-0}
AUTOTUNE_POLICY=${IRONET_V2_PROFILE_AUTOTUNE_POLICY:-builtin}
AUTOTUNE_SHADOW_POLICY=${IRONET_V2_PROFILE_AUTOTUNE_SHADOW_POLICY:-}
COVER_SECONDS=${IRONET_V2_PROFILE_COVER_SECONDS:-0}
COVER_RATE_MBIT=${IRONET_V2_PROFILE_COVER_RATE_MBIT:-4}
SECOND_PATH=${IRONET_V2_PROFILE_SECOND_PATH:-0}
SECOND_PATH_DELAY_MS=${IRONET_V2_PROFILE_SECOND_PATH_DELAY_MS:-30}
SECOND_PATH_LOSS_PERCENT=${IRONET_V2_PROFILE_SECOND_PATH_LOSS_PERCENT:-0}
SECOND_PATH_RATE_MBIT=${IRONET_V2_PROFILE_SECOND_PATH_RATE_MBIT:-0}
SECOND_PATH_QUEUE_PACKETS=${IRONET_V2_PROFILE_SECOND_PATH_QUEUE_PACKETS:-1000}
NETEM_SEED_BASE=${IRONET_V2_PROFILE_NETEM_SEED:-20260822}
DEFAULT_BIN=$ROOT/target/x86_64-unknown-linux-musl/profiling/ironetd
DEFAULT_CLI=$ROOT/target/x86_64-unknown-linux-musl/profiling/ironet
BIN=${IRONETD_BIN:-$DEFAULT_BIN}
CLI=${IRONET_BIN:-$DEFAULT_CLI}
CARGO=${CARGO:-cargo}

if [[ -v IRONETD_BIN && -z $IRONETD_BIN ]] || [[ -v IRONET_BIN && -z $IRONET_BIN ]]; then
  echo "IRONETD_BIN and IRONET_BIN must be non-empty when explicitly set" >&2
  exit 1
fi
if [[ -v IRONETD_BIN && ! -v IRONET_BIN ]] || [[ ! -v IRONETD_BIN && -v IRONET_BIN ]]; then
  echo "set both IRONETD_BIN and IRONET_BIN, or neither for a fresh default build" >&2
  exit 1
fi

# Never leave an earlier successful gate visible while a new invocation is
# validating configuration, provenance, or scenarios.
MATRIX_OUT_EXISTED=0
[[ ! -e $MATRIX_OUT ]] || MATRIX_OUT_EXISTED=1
if [[ $MATRIX_OUT_EXISTED == 1 && ${1:-} != --list && ${1:-} != --self-check ]]; then
  rm -f "$MATRIX_OUT/gate.json"
fi

source_identity() {
  local revision output_relative path content_hash
  revision=$(git -C "$ROOT" rev-parse --verify HEAD 2>/dev/null) || return
  printf '%s:' "$revision"
  git -C "$ROOT" diff --binary HEAD | git hash-object --stdin
  printf ':'
  # Include every untracked source path and its content hash. The matrix
  # output itself is not source input, so exclude it when it lives inside
  # this checkout.
  if [[ $MATRIX_OUT == "$ROOT/"* ]]; then
    output_relative=${MATRIX_OUT#"$ROOT/"}
    while IFS= read -r -d '' path; do
      [[ $path == "$output_relative" || $path == "$output_relative/"* ]] && continue
      content_hash=$(git -C "$ROOT" hash-object -- "$path")
      printf '%s\0%s\0' "$path" "$content_hash"
    done < <(git -C "$ROOT" ls-files --others --exclude-standard -z) \
      | git hash-object --stdin
  else
    while IFS= read -r -d '' path; do
      content_hash=$(git -C "$ROOT" hash-object -- "$path")
      printf '%s\0%s\0' "$path" "$content_hash"
    done < <(git -C "$ROOT" ls-files --others --exclude-standard -z) \
      | git hash-object --stdin
  fi
}

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

policy_content_sha256() {
  local policy=$1
  if [[ -z $policy || $policy == builtin || ! -f $policy ]]; then
    return 0
  fi
  sha256sum "$policy" | awk '{print $1}'
}

# A matrix is meaningful only when the daemon and CLI were built from the
# source being measured.  The previous implementation merely accepted any
# executable at the default target path, which let an old profiling build
# survive a source update unnoticed.  Build the default pair incrementally on
# every run: Cargo makes this a no-op when it is already current, while a
# changed source tree gets a matching pair before netns setup starts.  An
# explicit binary path is a deliberate caller-owned artifact and is left
# untouched for release/remote build workflows.
ensure_profiling_binaries() {
  if [[ -z ${IRONETD_BIN+x} && -z ${IRONET_BIN+x} ]]; then
    MATRIX_BINARY_FRESHNESS=built-current-source
    command -v "$CARGO" >/dev/null 2>&1 \
      || { echo "missing cargo for fresh profiling build: $CARGO" >&2; exit 1; }
    SOURCE_IDENTITY_BEFORE_BUILD=$(source_identity) \
      || { echo "matrix requires a Git checkout to verify profiling-build freshness" >&2; exit 1; }
    echo "building profiling binaries for $SOURCE_IDENTITY_BEFORE_BUILD"
    "$CARGO" build --profile profiling --target x86_64-unknown-linux-musl \
      --locked --bin ironetd --bin ironet
    SOURCE_IDENTITY_AFTER_BUILD=$(source_identity) \
      || { echo "matrix source revision disappeared while building" >&2; exit 1; }
    [[ $SOURCE_IDENTITY_BEFORE_BUILD == "$SOURCE_IDENTITY_AFTER_BUILD" ]] \
      || { echo "source changed while building profiling binaries; rerun the matrix" >&2; exit 1; }
  else
    MATRIX_BINARY_FRESHNESS=caller-supplied-unverified
    echo "using caller-supplied profiling binaries; source freshness is caller-owned" >&2
  fi
}

[[ $DURATION =~ ^[1-9][0-9]*$ ]] || { echo "invalid matrix duration" >&2; exit 1; }
[[ $STREAMS =~ ^[1-9][0-9]*$ ]] || { echo "invalid matrix stream count" >&2; exit 1; }
[[ $FREQUENCY =~ ^[1-9][0-9]*$ ]] || { echo "invalid matrix frequency" >&2; exit 1; }
[[ $PING_INTERVAL_MS =~ ^[1-9][0-9]*$ ]] || { echo "invalid ping interval" >&2; exit 1; }
[[ $FAIRNESS_SECONDS =~ ^[0-9]+$ ]] || { echo "invalid matrix fairness duration" >&2; exit 1; }
[[ $FAIRNESS_PER_STREAM_MBIT =~ ^[0-9]+([.][0-9]+)?$ ]] \
  || { echo "invalid matrix fairness per-stream rate" >&2; exit 1; }
[[ $SETTLE_SECONDS =~ ^[0-9]+$ ]] || { echo "invalid matrix settle duration" >&2; exit 1; }
[[ $RESUME == 0 || $RESUME == 1 ]] || { echo "matrix resume must be 0 or 1" >&2; exit 1; }
[[ $PERF_ENABLED == 0 || $PERF_ENABLED == 1 ]] || { echo "matrix perf must be 0 or 1" >&2; exit 1; }
[[ $QUEUE_DRAIN_TIMEOUT_SECONDS =~ ^[1-9][0-9]*$ ]] \
  || { echo "invalid profile queue drain timeout" >&2; exit 1; }
[[ $MIN_OVERALL_RATIO =~ ^(0([.][0-9]+)?|1([.]0+)?)$ ]] \
  && awk -v ratio="$MIN_OVERALL_RATIO" 'BEGIN { exit !(ratio > 0 && ratio <= 1) }' \
  || { echo "IRONET_V2_MATRIX_MIN_OVERALL_RATIO must be greater than 0 and at most 1" >&2; exit 1; }
[[ $NETEM_SEED_BASE =~ ^[1-9][0-9]*$ ]] \
  && awk -v seed="$NETEM_SEED_BASE" 'BEGIN { exit !(seed <= 4294967295) }' \
  || { echo "IRONET_V2_PROFILE_NETEM_SEED must be an integer between 1 and 4294967295" >&2; exit 1; }

scenario_selected() {
  local name=$1 item
  [[ $SCENARIO_FILTER == all ]] && return 0
  IFS=, read -r -a selected <<<"$SCENARIO_FILTER"
  for item in "${selected[@]}"; do
    [[ $item == "$name" ]] && return 0
  done
  return 1
}

# Columns: name|direction|a_delay|a_jitter|a_delay_corr|a_loss|a_loss_corr|
# a_rate|a_queue|b_delay|b_jitter|b_delay_corr|b_loss|b_loss_corr|b_rate|
# b_queue|seconds|timeline|description. `seconds` 0 uses the matrix duration;
# dynamic scenarios declare their own so every timeline step is observed.
# `timeline` uses the profile script's IRONET_V2_PROFILE_TIMELINE grammar.
catalog() {
  cat <<'EOF'
host-local-clean|forward|0|0|0|0|0|100|1000|0|0|0|0|0|100|1000|0||同机房/宿主机级无附加时延链路，用于验证包含 userspace 调度开销后 min RTT <2 ms 的专用 cwnd floor
wifi-lan-light|forward|2|1|25|0.2|25|300|1000|2|1|25|0.2|25|300|1000|0||轻度局域网 Wi-Fi 干扰，约 4 ms 基础 RTT
wifi-lan-interference|forward|4|4|50|2.5|60|150|1000|4|4|50|2.5|60|150|1000|0||拥挤 Wi-Fi，相关抖动和成串丢包
p2-p6-capacity|forward|1.5|0.2|10|0|0|110|1000|1.5|0.2|10|0|0|110|1000|0||p2→p6 实测约 110M 容量、无显式随机丢包
p2-p6-shallow-policer|forward|1.5|0.2|10|0|0|110|20|1.5|0.2|10|0|0|110|20|0||p2→p6 型浅队列限速，验证超速诱发丢包而非随机丢包
p2-wuwei-lossy-upload|forward|42|8|50|12|70|50|2500|42|4|25|0.5|20|500|5000|0||p2→wuwei-ws 型约 85 ms RTT、前向 12% 成串丢包
cross-carrier-cn-upload|forward|18|4|25|1.2|35|100|1500|18|4|25|0.3|20|500|3000|0||国内跨运营商，家庭侧 100M 上行/500M 下行
cross-carrier-cn-download|reverse|18|4|25|1.2|35|100|1500|18|4|25|0.3|20|500|3000|0||国内跨运营商，家庭侧 100M 上行/500M 下行：下载
cross-carrier-cn-high-rtt-upload|forward|42|6|30|2.5|40|100|1800|42|4|25|0.5|20|500|3500|0||国内远距离跨运营商，约 85 ms RTT、100M 上行/500M 下行，作为 r2 留出集
intercontinental-upload|forward|90|12|25|1.5|40|100|2500|90|12|25|0.5|20|500|5000|0||约 180 ms RTT 的洲际非对称链路
intercontinental-download|reverse|90|12|25|1.5|40|100|2500|90|12|25|0.5|20|500|5000|0||约 180 ms RTT 的洲际非对称链路：下载
home-100d-50u-upload|forward|8|2|20|0.2|10|50|1000|8|2|20|0.1|10|100|1500|0||中国家庭 100M 下行/50M 上行：上传
home-100d-50u-download|reverse|8|2|20|0.2|10|50|1000|8|2|20|0.1|10|100|1500|0||中国家庭 100M 下行/50M 上行：下载
home-200d-50u-upload|forward|8|2|20|0.2|10|50|1000|8|2|20|0.1|10|200|2000|0||中国家庭 200M 下行/50M 上行：上传
home-200d-50u-download|reverse|8|2|20|0.2|10|50|1000|8|2|20|0.1|10|200|2000|0||中国家庭 200M 下行/50M 上行：下载
home-500d-100u-upload|forward|8|2|20|0.2|10|100|1500|8|2|20|0.1|10|500|4000|0||中国家庭 500M 下行/100M 上行：上传
home-500d-100u-download|reverse|8|2|20|0.2|10|100|1500|8|2|20|0.1|10|500|4000|0||中国家庭 500M 下行/100M 上行：下载
home-1000d-100u-upload|forward|8|2|20|0.2|10|100|1500|8|2|20|0.1|10|1000|8000|0||中国家庭 1000M 下行/100M 上行：上传
home-1000d-100u-download|reverse|8|2|20|0.2|10|100|1500|8|2|20|0.1|10|1000|8000|0||中国家庭 1000M 下行/100M 上行：下载
step-bw-100-20-100|forward|8|2|20|0.2|10|100|1500|8|2|20|0.1|10|100|1500|60|20:a_rate=20,a_queue=300;40:a_rate=100,a_queue=1500|动态：家庭 100M 上行在 20 s 跌到 20M（浅队列），40 s 恢复
burst-loss-0-5-0|forward|42|8|50|0|0|50|2500|42|4|25|0|0|500|5000|60|20:a_loss=5,a_loss_corr=70;40:a_loss=0,a_loss_corr=0|动态：85 ms RTT 路径在 20 s 出现 5% 成串丢包，40 s 消失
rtt-shift-40-120|forward|20|2|20|0|0|100|2000|20|2|20|0|0|100|2000|60|20:a_delay=60,b_delay=60;40:a_delay=20,b_delay=20|动态：RTT 在 20 s 从 40 ms 跳到 120 ms，40 s 回落
policer-onset|forward|1.5|0.2|10|0|0|110|1000|1.5|0.2|10|0|0|110|1000|45|20:a_queue=20|动态：110M 路径在 20 s 变成浅队列限速
wifi-degrade|forward|2|1|25|0.2|25|300|1000|2|1|25|0.2|25|300|1000|60|20:a_rate=60,a_jitter=4,a_loss=2.5,a_loss_corr=60;40:a_rate=300,a_jitter=1,a_loss=0.2,a_loss_corr=25|动态：Wi-Fi 在 20 s 受干扰（限速、抖动、成串丢包），40 s 恢复
EOF
}

if [[ ${1:-} == --list ]]; then
  catalog
  exit 0
fi

CATALOG_COUNT=$(catalog | awk 'END {print NR}')
[[ $CATALOG_COUNT == 24 ]] \
  || { echo "matrix catalog must contain exactly 24 scenarios, found $CATALOG_COUNT" >&2; exit 1; }
[[ $(catalog | awk -F'|' '{print $1}' | sort -u | wc -l) == "$CATALOG_COUNT" ]] \
  || { echo "matrix catalog contains duplicate scenario names" >&2; exit 1; }

if [[ ${1:-} == --self-check ]]; then
  python3 - <<'PY'
import hashlib
import json
import math

underlay = {"end": {"sum_received": {"bits_per_second": 100.0}}}
overlay = {"end": {"sum_received": {"bits_per_second": 91.0}}}
raw_ratio = (
    overlay["end"]["sum_received"]["bits_per_second"]
    / underlay["end"]["sum_received"]["bits_per_second"]
)
summary = {
    "underlay_received_bits_per_second": 100.0,
    "overlay_received_bits_per_second": 91.0,
    "overlay_to_underlay_ratio": 0.91,
}
assert math.isclose(raw_ratio, summary["overlay_to_underlay_ratio"], rel_tol=1e-12)
summary_hash = hashlib.sha256(json.dumps(summary, sort_keys=True).encode()).hexdigest()
credential = {"schema": "ironet-v2-netns-complete-v1", "summary_sha256": summary_hash}
assert credential["schema"].endswith("-v1") and len(credential["summary_sha256"]) == 64
PY
  bash -n "$PROFILE_SCRIPT" "$ROOT/scripts/profile-v2-netns-matrix.sh"
  echo "profile-v2 netns harness self-check passed ($CATALOG_COUNT catalog scenarios)"
  exit 0
fi

if [[ $MATRIX_OUT_EXISTED == 1 && $RESUME == 0 ]]; then
  echo "matrix output already exists: $MATRIX_OUT" >&2
  exit 1
fi

mkdir -p "$MATRIX_OUT"
ensure_profiling_binaries
[[ -x $PROFILE_SCRIPT ]] || { echo "missing profile script: $PROFILE_SCRIPT" >&2; exit 1; }
[[ -x $BIN ]] || { echo "missing profiling daemon: $BIN" >&2; exit 1; }
[[ -x $CLI ]] || { echo "missing profiling CLI: $CLI" >&2; exit 1; }
SOURCE_REVISION=$(git -C "$ROOT" rev-parse --verify HEAD 2>/dev/null || printf 'unknown')
SOURCE_IDENTITY=$(source_identity 2>/dev/null || printf 'unknown')
if [[ $MATRIX_BINARY_FRESHNESS == built-current-source \
  && $SOURCE_IDENTITY != "$SOURCE_IDENTITY_AFTER_BUILD" ]]; then
  echo "source changed after profiling build; rerun the matrix" >&2
  exit 1
fi
BIN_SHA256=$(sha256sum "$BIN" | awk '{print $1}')
CLI_SHA256=$(sha256sum "$CLI" | awk '{print $1}')
MATRIX_SCRIPT_SHA256=$(sha256sum "$ROOT/scripts/profile-v2-netns-matrix.sh" | awk '{print $1}')
PROFILE_SCRIPT_SHA256=$(sha256sum "$PROFILE_SCRIPT" | awk '{print $1}')
CATALOG_SHA256=$(catalog | sha256sum | awk '{print $1}')
AUTOTUNE_POLICY_SHA256=$(policy_content_sha256 "$AUTOTUNE_POLICY")
AUTOTUNE_SHADOW_POLICY_SHA256=$(policy_content_sha256 "$AUTOTUNE_SHADOW_POLICY")
PROFILE_ALLOWED_CPU_LIST=$(awk '/^Cpus_allowed_list:/ { print $2 }' /proc/self/status)
mapfile -t PROFILE_ALLOWED_CPUS < <(expand_cpu_list "$PROFILE_ALLOWED_CPU_LIST")
(( ${#PROFILE_ALLOWED_CPUS[@]} > 0 )) \
  || { echo "no CPUs available to the profiler" >&2; exit 1; }
PROFILE_DEFAULT_CPU_FIRST=$((${#PROFILE_ALLOWED_CPUS[@]} / 2))
PROFILE_DEFAULT_CPUSET=$(IFS=,; echo "${PROFILE_ALLOWED_CPUS[*]:$PROFILE_DEFAULT_CPU_FIRST}")
PROFILE_CPUSET=${IRONET_V2_PROFILE_CPUSET:-$PROFILE_DEFAULT_CPUSET}
RUN_CONFIG_JSON=$(python3 - "$DURATION" "$STREAMS" "$PERF_ENABLED" "$FREQUENCY" \
  "$CALL_GRAPH" "$PING_INTERVAL_MS" "$FAIRNESS_SECONDS" "$FAIRNESS_PER_STREAM_MBIT" \
  "$SETTLE_SECONDS" "$MATRIX_SCRIPT_SHA256" "$PROFILE_SCRIPT_SHA256" "$CATALOG_SHA256" \
  "$AUTOTUNE_FORCE" "$AUTOTUNE_MODE" "$AUTOTUNE_OBJECTIVE" "$AUTOTUNE_MEMORY" \
  "$AUTOTUNE_POLICY" "$AUTOTUNE_POLICY_SHA256" "$AUTOTUNE_SHADOW_POLICY" \
  "$AUTOTUNE_SHADOW_POLICY_SHA256" "$COVER_SECONDS" "$COVER_RATE_MBIT" "$SECOND_PATH" \
  "$SECOND_PATH_DELAY_MS" "$SECOND_PATH_LOSS_PERCENT" "$SECOND_PATH_RATE_MBIT" \
  "$SECOND_PATH_QUEUE_PACKETS" "$PROFILE_RUST_LOG" "$PROFILE_NICE" "$PROFILE_CPUSET" \
  "$PROFILE_ALLOWED_CPU_LIST" "$NETEM_SEED_BASE" "$SCENARIO_FILTER" \
  "$MIN_OVERALL_RATIO" "$QUEUE_DRAIN_TIMEOUT_SECONDS" <<'PY'
import json
import sys

keys = (
    "duration_seconds", "streams", "perf_enabled", "sampling_frequency_hz",
    "call_graph", "ping_interval_ms", "fairness_seconds", "fairness_per_stream_mbit",
    "settle_seconds", "matrix_script_sha256", "profile_script_sha256", "catalog_sha256",
    "autotune_force", "autotune_mode", "autotune_objective", "autotune_memory",
    "autotune_policy", "autotune_policy_sha256", "autotune_shadow_policy",
    "autotune_shadow_policy_sha256", "cover_seconds", "cover_rate_mbit", "second_path",
    "second_path_delay_ms", "second_path_loss_percent", "second_path_rate_mbit",
    "second_path_queue_packets", "profile_rust_log", "profile_nice", "profile_cpuset",
    "allowed_cpu_list", "netem_seed_base", "scenario_filter", "minimum_overall_ratio",
    "queue_drain_timeout_seconds",
)
config = dict(zip(keys, sys.argv[1:]))
config.update({
    "disable_tun_offload": "0",
    "preflight_only": "0",
    "startup_canary_only": "0",
})
print(json.dumps(config, sort_keys=True, separators=(",", ":")))
PY
)
RUN_CONFIG_SHA256=$(printf '%s' "$RUN_CONFIG_JSON" | sha256sum | awk '{print $1}')
if [[ $RESUME == 1 && -e $MATRIX_OUT/build.json ]]; then
  python3 - "$MATRIX_OUT/build.json" "$SOURCE_IDENTITY" "$BIN_SHA256" "$CLI_SHA256" \
    "$RUN_CONFIG_JSON" <<'PY'
import json
import pathlib
import sys

recorded = json.loads(pathlib.Path(sys.argv[1]).read_text())
expected = {
    "source_identity": sys.argv[2],
    "ironetd": sys.argv[3],
    "ironet": sys.argv[4],
    "run_config": json.loads(sys.argv[5]),
}
actual = {
    "source_identity": recorded.get("source_identity"),
    "ironetd": (recorded.get("ironetd") or {}).get("sha256"),
    "ironet": (recorded.get("ironet") or {}).get("sha256"),
    "run_config": recorded.get("run_config"),
}
if actual != expected:
    raise SystemExit(
        "cannot resume matrix with different source or profiling binaries; choose a new output directory"
    )
PY
elif [[ $RESUME == 1 ]] && find "$MATRIX_OUT" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
  echo "cannot resume matrix without build.json provenance; choose a new output directory" >&2
  exit 1
else
  python3 - "$MATRIX_OUT/build.json" "$MATRIX_BINARY_FRESHNESS" "$SOURCE_REVISION" \
  "$SOURCE_IDENTITY" "$BIN" "$BIN_SHA256" "$CLI" "$CLI_SHA256" "$RUN_CONFIG_JSON" <<'PY'
import json
import pathlib
import sys

pathlib.Path(sys.argv[1]).write_text(json.dumps({
    "binary_freshness": sys.argv[2],
    "source_revision": sys.argv[3],
    "source_identity": sys.argv[4],
    "ironetd": {"path": sys.argv[5], "sha256": sys.argv[6]},
    "ironet": {"path": sys.argv[7], "sha256": sys.argv[8]},
    "run_config": json.loads(sys.argv[9]),
}, indent=2) + "\n")
PY
fi
# Materialize the exact catalog subset this invocation must complete. Besides
# driving the final gate, this rejects a misspelled filter instead of silently
# producing a successful empty or partial matrix.
if [[ $SCENARIO_FILTER != all ]]; then
  IFS=, read -r -a requested_scenarios <<<"$SCENARIO_FILTER"
  for requested in "${requested_scenarios[@]}"; do
    [[ -n $requested ]] \
      || { echo "matrix scenario filter contains an empty name" >&2; exit 1; }
    catalog | awk -F'|' '{print $1}' | grep -Fqx -- "$requested" \
      || { echo "unknown matrix scenario: $requested" >&2; exit 1; }
  done
fi
EXPECTED_SCENARIOS="$MATRIX_OUT/expected-scenarios.tsv"
printf 'scenario\tdirection\tseconds\n' >"$EXPECTED_SCENARIOS"
while IFS='|' read -r expected_name expected_direction \
    expected_a_delay expected_a_jitter expected_a_delay_corr expected_a_loss \
    expected_a_loss_corr expected_a_rate expected_a_queue expected_b_delay \
    expected_b_jitter expected_b_delay_corr expected_b_loss expected_b_loss_corr \
    expected_b_rate expected_b_queue expected_seconds expected_timeline expected_description; do
  scenario_selected "$expected_name" || continue
  [[ $expected_seconds == 0 ]] && expected_seconds=$DURATION
  printf '%s\t%s\t%s\n' "$expected_name" "$expected_direction" "$expected_seconds" \
    >>"$EXPECTED_SCENARIOS"
done < <(catalog)
[[ $(wc -l <"$EXPECTED_SCENARIOS") -gt 1 ]] \
  || { echo "matrix scenario filter selected no scenarios" >&2; exit 1; }

validate_completion() {
  python3 - "$1" "$2" "$3" "$4" "$BIN_SHA256" "$SOURCE_IDENTITY" \
    "$RUN_CONFIG_SHA256" <<'PY'
import hashlib
import json
import math
import pathlib
import sys

out = pathlib.Path(sys.argv[1])
expected = {
    "schema": "ironet-v2-netns-complete-v1",
    "scenario": sys.argv[2],
    "direction": sys.argv[3],
    "duration_seconds": int(sys.argv[4]),
    "binary_sha256": sys.argv[5],
    "source_identity": sys.argv[6],
    "run_config_sha256": sys.argv[7],
}
try:
    completion = json.loads((out / ".complete.json").read_text())
    summary_bytes = (out / "summary.json").read_bytes()
    summary = json.loads(summary_bytes)
except (OSError, json.JSONDecodeError):
    raise SystemExit(1)
if any(completion.get(key) != value for key, value in expected.items()):
    raise SystemExit(1)
if completion.get("summary_sha256") != hashlib.sha256(summary_bytes).hexdigest():
    raise SystemExit(1)
if any(summary.get(key) != value for key, value in {
    "scenario": expected["scenario"],
    "direction": expected["direction"],
    "duration_seconds": expected["duration_seconds"],
    "binary_sha256": expected["binary_sha256"],
}.items()):
    raise SystemExit(1)
receiver_names = {
    "underlay": "underlay-server.json" if expected["direction"] == "forward" else "underlay.json",
    "overlay": "overlay-server.json" if expected["direction"] == "forward" else "overlay.json",
}
for role, name in receiver_names.items():
    try:
        raw = (out / name).read_bytes()
        rate = float(json.loads(raw)["end"]["sum_received"]["bits_per_second"])
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        raise SystemExit(1)
    recorded = (completion.get("receiver_files") or {}).get(role) or {}
    if (recorded.get("path") != name
            or recorded.get("sha256") != hashlib.sha256(raw).hexdigest()
            or not math.isfinite(rate)):
        raise SystemExit(1)
PY
}

write_completion() {
  python3 - "$1" "$2" "$3" "$4" "$BIN_SHA256" "$SOURCE_IDENTITY" \
    "$RUN_CONFIG_SHA256" <<'PY'
import hashlib
import json
import math
import os
import pathlib
import sys

out = pathlib.Path(sys.argv[1])
scenario, direction = sys.argv[2], sys.argv[3]
duration_seconds = int(sys.argv[4])
summary_path = out / "summary.json"
summary_bytes = summary_path.read_bytes()
summary = json.loads(summary_bytes)
expected_summary = {
    "scenario": scenario,
    "direction": direction,
    "duration_seconds": duration_seconds,
    "binary_sha256": sys.argv[5],
}
if any(summary.get(key) != value for key, value in expected_summary.items()):
    raise SystemExit("completed scenario summary identity differs from matrix")
receiver_names = {
    "underlay": "underlay-server.json" if direction == "forward" else "underlay.json",
    "overlay": "overlay-server.json" if direction == "forward" else "overlay.json",
}
receivers = {}
for role, name in receiver_names.items():
    raw = (out / name).read_bytes()
    rate = float(json.loads(raw)["end"]["sum_received"]["bits_per_second"])
    if not math.isfinite(rate) or rate < 0:
        raise SystemExit(f"invalid {role} receiver rate")
    receivers[role] = {
        "path": name,
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
record = {
    "schema": "ironet-v2-netns-complete-v1",
    **expected_summary,
    "source_identity": sys.argv[6],
    "run_config_sha256": sys.argv[7],
    "summary_sha256": hashlib.sha256(summary_bytes).hexdigest(),
    "receiver_files": receivers,
}
path = out / ".complete.json"
temporary = out / f".complete.json.tmp-{os.getpid()}"
with temporary.open("x") as handle:
    json.dump(record, handle, indent=2)
    handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())
os.replace(temporary, path)
PY
}

while IFS='|' read -r name direction \
    a_delay a_jitter a_delay_corr a_loss a_loss_corr a_rate a_queue \
    b_delay b_jitter b_delay_corr b_loss b_loss_corr b_rate b_queue \
    seconds timeline description; do
  scenario_selected "$name" || continue
  scenario_seconds=$DURATION
  [[ $seconds == 0 ]] || scenario_seconds=$seconds
  out="$MATRIX_OUT/$name"
  if [[ $RESUME == 1 && -s $out/.complete.json ]]; then
    if validate_completion "$out" "$name" "$direction" "$scenario_seconds"; then
      printf 'skipping completed %s\n' "$name"
      continue
    fi
    printf 'completion credential for %s is invalid; rerunning it\n' "$name" >&2
  elif [[ $RESUME == 1 && -s $out/summary.json ]]; then
    printf 'summary for %s has no completion credential; rerunning it\n' "$name" >&2
  fi
  if [[ -e $out ]]; then
    interrupted="$MATRIX_OUT/.interrupted-$name-$(date -u +%Y%m%d-%H%M%S)"
    printf 'preserving interrupted %s as %s\n' "$name" "$interrupted"
    mv "$out" "$interrupted"
  fi
  printf 'running %s (%s)\n' "$name" "$description"
  env \
    IRONETD_BIN="$BIN" \
    IRONET_BIN="$CLI" \
    IRONET_V2_PROFILE_OUT="$out" \
    IRONET_V2_PROFILE_SCENARIO_NAME="$name" \
    IRONET_V2_PROFILE_DIRECTION="$direction" \
    IRONET_V2_PROFILE_SECONDS="$scenario_seconds" \
    IRONET_V2_PROFILE_TIMELINE="$timeline" \
    IRONET_V2_PROFILE_PERF="$PERF_ENABLED" \
    IRONET_V2_PROFILE_STREAMS="$STREAMS" \
    IRONET_V2_PROFILE_FREQUENCY="$FREQUENCY" \
    IRONET_V2_PROFILE_CALL_GRAPH="$CALL_GRAPH" \
    IRONET_V2_PROFILE_DISABLE_TUN_OFFLOAD=0 \
    IRONET_V2_PROFILE_PREFLIGHT_ONLY=0 \
    IRONET_V2_PROFILE_STARTUP_CANARY_ONLY=0 \
    IRONET_V2_PROFILE_QUEUE_DRAIN_TIMEOUT_SECONDS="$QUEUE_DRAIN_TIMEOUT_SECONDS" \
    IRONET_V2_PROFILE_CONCURRENT_PING_INTERVAL_MS="$PING_INTERVAL_MS" \
    IRONET_V2_PROFILE_FAIRNESS_SECONDS="$FAIRNESS_SECONDS" \
    IRONET_V2_PROFILE_FAIRNESS_PER_STREAM_MBIT="$FAIRNESS_PER_STREAM_MBIT" \
    IRONET_V2_PROFILE_A_TO_B_DELAY_MS="$a_delay" \
    IRONET_V2_PROFILE_A_TO_B_JITTER_MS="$a_jitter" \
    IRONET_V2_PROFILE_A_TO_B_DELAY_CORRELATION_PERCENT="$a_delay_corr" \
    IRONET_V2_PROFILE_A_TO_B_LOSS_PERCENT="$a_loss" \
    IRONET_V2_PROFILE_A_TO_B_LOSS_CORRELATION_PERCENT="$a_loss_corr" \
    IRONET_V2_PROFILE_A_TO_B_RATE_MBIT="$a_rate" \
    IRONET_V2_PROFILE_A_TO_B_QUEUE_PACKETS="$a_queue" \
    IRONET_V2_PROFILE_B_TO_A_DELAY_MS="$b_delay" \
    IRONET_V2_PROFILE_B_TO_A_JITTER_MS="$b_jitter" \
    IRONET_V2_PROFILE_B_TO_A_DELAY_CORRELATION_PERCENT="$b_delay_corr" \
    IRONET_V2_PROFILE_B_TO_A_LOSS_PERCENT="$b_loss" \
    IRONET_V2_PROFILE_B_TO_A_LOSS_CORRELATION_PERCENT="$b_loss_corr" \
    IRONET_V2_PROFILE_B_TO_A_RATE_MBIT="$b_rate" \
    IRONET_V2_PROFILE_B_TO_A_QUEUE_PACKETS="$b_queue" \
    IRONET_V2_PROFILE_NETEM_SEED="$NETEM_SEED_BASE" \
    bash "$PROFILE_SCRIPT"
  write_completion "$out" "$name" "$direction" "$scenario_seconds"
  # perf/daemon descendants are fully joined by the scenario script, but the
  # host flock file descriptor can remain alive for a final scheduler tick on
  # some sudo/perf process trees. Avoid a false overlap rejection.
  sleep "$SETTLE_SECONDS"
done < <(catalog)

# Rebuild rather than append: resumed runs otherwise accumulate duplicates or
# retain entries whose interrupted output was moved aside.
MANIFEST_TMP="$MATRIX_OUT/.manifest.tsv.tmp-$$"
printf 'scenario\tdirection\tdescription\toutput\n' >"$MANIFEST_TMP"
while IFS='|' read -r manifest_name manifest_direction \
    manifest_a_delay manifest_a_jitter manifest_a_delay_corr manifest_a_loss \
    manifest_a_loss_corr manifest_a_rate manifest_a_queue manifest_b_delay \
    manifest_b_jitter manifest_b_delay_corr manifest_b_loss manifest_b_loss_corr \
    manifest_b_rate manifest_b_queue manifest_seconds manifest_timeline \
    manifest_description; do
  scenario_selected "$manifest_name" || continue
  printf '%s\t%s\t%s\t%s\n' "$manifest_name" "$manifest_direction" \
    "$manifest_description" "$MATRIX_OUT/$manifest_name" >>"$MANIFEST_TMP"
done < <(catalog)
python3 - "$MANIFEST_TMP" "$EXPECTED_SCENARIOS" "$MATRIX_OUT" <<'PY'
import csv
import pathlib
import sys

manifest_path, expected_path = map(pathlib.Path, sys.argv[1:3])
root = pathlib.Path(sys.argv[3])
with manifest_path.open(newline="") as handle:
    manifest = list(csv.DictReader(handle, delimiter="\t"))
with expected_path.open(newline="") as handle:
    expected = list(csv.DictReader(handle, delimiter="\t"))
names = [row["scenario"] for row in manifest]
expected_names = [row["scenario"] for row in expected]
if len(names) != len(set(names)) or names != expected_names:
    raise SystemExit("rebuilt manifest is duplicate, missing, or out of catalog order")
for row, expected_row in zip(manifest, expected):
    if (row["direction"] != expected_row["direction"]
            or pathlib.Path(row["output"]) != root / row["scenario"]):
        raise SystemExit(f"invalid manifest row for {row['scenario']}")
PY
mv -f "$MANIFEST_TMP" "$MATRIX_OUT/manifest.tsv"

SOURCE_IDENTITY_BEFORE_GATE=$(source_identity 2>/dev/null || printf 'unknown')
if [[ $SOURCE_IDENTITY_BEFORE_GATE != "$SOURCE_IDENTITY" ]]; then
  python3 - "$MATRIX_OUT" "$EXPECTED_SCENARIOS" "$CATALOG_COUNT" \
    "$SCENARIO_FILTER" <<'PY'
import csv
import json
import os
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
with pathlib.Path(sys.argv[2]).open(newline="") as handle:
    selected = [row["scenario"] for row in csv.DictReader(handle, delimiter="\t")]
failure = "source identity changed while the matrix was running; results are not reproducible"
gate = {
    "passed": False,
    "full_catalog": sys.argv[4] == "all" and len(selected) == int(sys.argv[3]),
    "scope": (
        "full_catalog"
        if sys.argv[4] == "all" and len(selected) == int(sys.argv[3])
        else "selected_subset"
    ),
    "catalog_count": int(sys.argv[3]),
    "selected_count": len(selected),
    "validated_count": 0,
    "selected_scenarios": selected,
    "validated_scenarios": [],
    "failures": [failure],
}
temporary = root / f".gate.json.tmp-{os.getpid()}"
with temporary.open("x") as handle:
    json.dump(gate, handle, ensure_ascii=False, indent=2)
    handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())
os.replace(temporary, root / "gate.json")
PY
  echo "matrix gate failed: source identity changed while the matrix was running" >&2
  exit 1
fi

python3 - "$MATRIX_OUT" "$EXPECTED_SCENARIOS" "$MIN_OVERALL_RATIO" "$BIN_SHA256" \
  "$SOURCE_IDENTITY" "$RUN_CONFIG_SHA256" "$CATALOG_COUNT" "$SCENARIO_FILTER" <<'PY'
import csv
import hashlib
import json
import math
import os
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
expected_path = pathlib.Path(sys.argv[2])
minimum_overall_ratio = float(sys.argv[3])
expected_binary_sha256 = sys.argv[4]
expected_source_identity = sys.argv[5]
expected_run_config_sha256 = sys.argv[6]
catalog_count = int(sys.argv[7])
full_catalog = sys.argv[8] == "all"
with expected_path.open(newline="") as handle:
    expected_rows = list(csv.DictReader(handle, delimiter="\t"))
expected = {row["scenario"]: row for row in expected_rows}
if len(expected) != len(expected_rows):
    raise SystemExit("selected matrix catalog contains duplicate scenario names")
rows = []
summaries = {}
raw_results = {}
artifact_failures = {}

def numeric_ratio(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )

def file_sha256(contents):
    return hashlib.sha256(contents).hexdigest()

def load_artifacts(name, expected_row):
    failures = []
    scenario_out = root / name
    try:
        summary_bytes = (scenario_out / "summary.json").read_bytes()
        summary = json.loads(summary_bytes)
    except (OSError, json.JSONDecodeError):
        summary_bytes, summary = None, None
        failures.append(f"{name}: summary.json is missing or invalid")
    try:
        completion = json.loads((scenario_out / ".complete.json").read_text())
    except (OSError, json.JSONDecodeError):
        completion = None
        failures.append(f"{name}: atomic completion credential is missing or invalid")
    expected_completion = {
        "schema": "ironet-v2-netns-complete-v1",
        "scenario": name,
        "direction": expected_row["direction"],
        "duration_seconds": int(expected_row["seconds"]),
        "binary_sha256": expected_binary_sha256,
        "source_identity": expected_source_identity,
        "run_config_sha256": expected_run_config_sha256,
    }
    if completion is not None:
        for key, value in expected_completion.items():
            if completion.get(key) != value:
                failures.append(f"{name}: completion credential {key} differs")
        if (summary_bytes is None
                or completion.get("summary_sha256") != file_sha256(summary_bytes)):
            failures.append(f"{name}: completion credential does not cover summary.json")
    receiver_names = {
        "underlay": (
            "underlay-server.json"
            if expected_row["direction"] == "forward" else "underlay.json"
        ),
        "overlay": (
            "overlay-server.json"
            if expected_row["direction"] == "forward" else "overlay.json"
        ),
    }
    rates = {}
    for role, receiver_name in receiver_names.items():
        try:
            receiver_bytes = (scenario_out / receiver_name).read_bytes()
            receiver = json.loads(receiver_bytes)
            value = receiver["end"]["sum_received"]["bits_per_second"]
            if not numeric_ratio(value) or value < 0:
                raise ValueError
            rates[role] = float(value)
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
            failures.append(f"{name}: original {role} receiver JSON is missing or invalid")
            continue
        recorded = ((completion or {}).get("receiver_files") or {}).get(role) or {}
        if (recorded.get("path") != receiver_name
                or recorded.get("sha256") != file_sha256(receiver_bytes)):
            failures.append(
                f"{name}: completion credential does not cover original {role} receiver JSON"
            )
    raw = None
    if set(rates) == {"underlay", "overlay"}:
        if rates["underlay"] <= 0:
            failures.append(f"{name}: original underlay receiver rate is not positive")
        else:
            raw = {
                **rates,
                "ratio": rates["overlay"] / rates["underlay"],
            }
    return summary, raw, failures

for scenario, expected_row in expected.items():
    data, raw, failures = load_artifacts(scenario, expected_row)
    artifact_failures[scenario] = failures
    if data is None:
        continue
    summaries[scenario] = data
    if raw is not None:
        raw_results[scenario] = raw
    scenario_out = root / scenario
    netem = data.get("netem") or {}
    active_rate = (
        netem.get("a_to_b_rate_mbit")
        if data.get("direction") == "forward"
        else netem.get("b_to_a_rate_mbit")
    )
    segments = data.get("segments") or []
    settle = [
        segment["settle_seconds"] for segment in segments[1:]
        if segment.get("settle_seconds") is not None
    ]
    unsettled = sum(
        1 for segment in segments[1:] if segment.get("settle_seconds") is None
    )
    active_side = "a" if data.get("direction") == "forward" else "b"
    autotune = (data.get("autotune") or {}).get(active_side) or {}
    fairness = data.get("overlay_udp_fairness") or {}
    admission_shed = (data.get("tun_admission_shed") or {}).get(active_side) or {}
    controller = data.get("controller_alignment") or {}
    rows.append({
        "scenario": data.get("scenario"),
        "direction": data.get("direction"),
        "seconds": data.get("duration_seconds"),
        "autotune_objective": data.get("autotune_objective"),
        "timeline_steps": len(data.get("timeline") or []),
        "max_settle_seconds": max(settle) if settle else None,
        "unsettled_segments": unsettled if segments else None,
        "path_rate_mbit": active_rate,
        "underlay_mbit": (data.get("underlay_received_bits_per_second") or 0) / 1e6,
        "overlay_mbit": (data.get("overlay_received_bits_per_second") or 0) / 1e6,
        "overlay_underlay_ratio": data.get("overlay_to_underlay_ratio"),
        "throughput_comparison_mode": (data.get("throughput_comparison") or {}).get("mode"),
        "throughput_comparison_comparable": (data.get("throughput_comparison") or {}).get("comparable"),
        "timeline_synchronization_validated": (data.get("timeline_synchronization") or {}).get("comparable"),
        "aligned_segment_ratios": sum(
            1 for segment in segments
            if segment.get("overlay_to_underlay_ratio") is not None
        ),
        "underlay_ping_p95_ms": (data.get("underlay_concurrent_ping") or {}).get("p95_ms"),
        "overlay_ping_p95_ms": (data.get("overlay_concurrent_ping") or {}).get("p95_ms"),
        "utility_mean": autotune.get("utility_mean"),
        "utility_last10_mean": autotune.get("utility_last10_mean"),
        "utility_p10": autotune.get("utility_p10"),
        "preset_switches": autotune.get("preset_switches"),
        "rollbacks": autotune.get("rollbacks"),
        "convergence_seconds": autotune.get("convergence_seconds"),
        "residual_loss_ppm_mean": autotune.get("residual_loss_ppm_mean"),
        "latency_sojourn_p95_mean": autotune.get("latency_sojourn_p95_mean"),
        "shadow_policy_id": (autotune.get("shadow") or {}).get("policy_id"),
        "shadow_final_preset": (autotune.get("shadow") or {}).get("final_proposed_preset"),
        "shadow_advantage_mean": (autotune.get("shadow") or {}).get("predicted_advantage_mean"),
        "shadow_advantage_last10_mean": (autotune.get("shadow") or {}).get("predicted_advantage_last10_mean"),
        "fairness_streams": fairness.get("streams"),
        "fairness_jain": fairness.get("jain_fairness"),
        "fairness_spread_percent": fairness.get("spread_percent"),
        "fairness_maximum_deviation_percent": fairness.get("maximum_deviation_percent"),
        "tun_admission_shed_records": admission_shed.get("records"),
        "tun_admission_shed_bytes": admission_shed.get("bytes"),
        "controller_alignment_samples": controller.get("samples"),
        "controller_alignment_steady_samples": controller.get("steady_samples"),
        "path_identity_switches": controller.get("path_identity_switches"),
        "path_epoch_switches": controller.get("path_epoch_switches"),
        "overlay_controller_bw_correlation": controller.get("overlay_controller_bw_correlation"),
        "overlay_cwnd_correlation": controller.get("overlay_cwnd_correlation"),
        "overlay_cwnd_floor_correlation": controller.get("overlay_cwnd_floor_correlation"),
        "final5_controller_bw_bytes_per_second_mean": controller.get("final5_controller_bw_bytes_per_second_mean"),
        "final5_controller_cwnd_bytes_mean": controller.get("final5_controller_cwnd_bytes_mean"),
        "final5_adaptive_cwnd_floor_bytes_mean": controller.get("final5_adaptive_cwnd_floor_bytes_mean"),
        "final5_packet_train_queue_bytes_mean": controller.get("final5_packet_train_queue_bytes_mean"),
        "a_perf_lost_samples": data.get("a_perf_lost_samples"),
        "b_perf_lost_samples": data.get("b_perf_lost_samples"),
        "output": str(scenario_out),
    })
(root / "aggregate.json").write_text(json.dumps(rows, ensure_ascii=False, indent=2) + "\n")
with (root / "aggregate.csv").open("w", newline="") as handle:
    writer = csv.DictWriter(handle, fieldnames=list(rows[0]) if rows else ["scenario"])
    writer.writeheader()
    writer.writerows(rows)
print(json.dumps(rows, ensure_ascii=False, indent=2))

def validate_summary(name, summary, expected_row, raw):
    failures = []
    if summary is None:
        return [f"{name}: summary.json is missing"]
    if summary.get("scenario") != name:
        failures.append(f"{name}: summary scenario identity differs")
    if summary.get("direction") != expected_row["direction"]:
        failures.append(f"{name}: summary direction differs from catalog")
    if summary.get("duration_seconds") != int(expected_row["seconds"]):
        failures.append(f"{name}: summary duration differs from catalog")
    if summary.get("binary_sha256") != expected_binary_sha256:
        failures.append(f"{name}: summary binary differs from matrix provenance")
    comparison = summary.get("throughput_comparison") or {}
    if comparison.get("comparable") is not True:
        failures.append(f"{name}: underlay/overlay comparison is not proven comparable")
    timeline = summary.get("timeline") or []
    if timeline:
        synchronization = summary.get("timeline_synchronization") or {}
        if synchronization.get("comparable") is not True:
            failures.append(f"{name}: dynamic timeline synchronization is not validated")
    else:
        consistency = summary.get("static_endpoint_consistency") or {}
        relative_errors = consistency.get("relative_errors") or {}
        required_errors = ("overlay", "underlay", "ratio")
        if (
            consistency.get("consistent") is not True
            or any(not numeric_ratio(relative_errors.get(key)) for key in required_errors)
        ):
            failures.append(f"{name}: static receiver interval/endpoint consistency failed")
    ratio = summary.get("overlay_to_underlay_ratio")
    if not numeric_ratio(ratio):
        failures.append(f"{name}: overall receiver ratio is missing or non-numeric")
    if raw is None:
        failures.append(f"{name}: ratio cannot be recomputed from original receiver JSON")
    else:
        summary_values = {
            "underlay_received_bits_per_second": raw["underlay"],
            "overlay_received_bits_per_second": raw["overlay"],
            "overlay_to_underlay_ratio": raw["ratio"],
        }
        for key, recomputed in summary_values.items():
            recorded = summary.get(key)
            if (not numeric_ratio(recorded)
                    or not math.isclose(recorded, recomputed, rel_tol=1e-12, abs_tol=1e-9)):
                failures.append(
                    f"{name}: summary {key} differs from original receiver JSON"
                )
        if raw["ratio"] < minimum_overall_ratio:
            failures.append(
                f"{name}: recomputed overall receiver ratio {raw['ratio']:.6f} is below "
                f"{minimum_overall_ratio:.6f}"
            )
    # Segment ratios remain diagnostic. They are deliberately not included in
    # the default exit gate until the product target explicitly requires every
    # transition window, rather than each scenario's overall receiver result.
    return failures

def validate_gate_fixture():
    row = {"scenario": "fixture", "direction": "forward", "seconds": "15"}
    valid = {
        "scenario": "fixture", "direction": "forward", "duration_seconds": 15,
        "binary_sha256": expected_binary_sha256,
        "throughput_comparison": {"comparable": True},
        "timeline": [],
        "static_endpoint_consistency": {
            "consistent": True,
            "relative_errors": {"overlay": 0.0, "underlay": 0.0, "ratio": 0.0},
        },
        "overlay_to_underlay_ratio": minimum_overall_ratio,
        "underlay_received_bits_per_second": 100.0,
        "overlay_received_bits_per_second": 100.0 * minimum_overall_ratio,
    }
    raw = {
        "underlay": 100.0,
        "overlay": 100.0 * minimum_overall_ratio,
        "ratio": minimum_overall_ratio,
    }
    if validate_summary("fixture", valid, row, raw):
        raise SystemExit("matrix gate valid-summary fixture failed")
    if not validate_summary("fixture", None, row, raw):
        raise SystemExit("matrix gate missing-summary fixture failed")
    wrong_binary = dict(valid)
    wrong_binary["binary_sha256"] = "wrong"
    if not validate_summary("fixture", wrong_binary, row, raw):
        raise SystemExit("matrix gate binary-identity fixture failed")
    wrong_duration = dict(valid)
    wrong_duration["duration_seconds"] = 16
    if not validate_summary("fixture", wrong_duration, row, raw):
        raise SystemExit("matrix gate duration-identity fixture failed")
    incomparable = dict(valid)
    incomparable["throughput_comparison"] = {"comparable": False}
    if not validate_summary("fixture", incomparable, row, raw):
        raise SystemExit("matrix gate comparability fixture failed")
    invalid = dict(valid)
    invalid["overlay_to_underlay_ratio"] = minimum_overall_ratio / 2
    if not validate_summary("fixture", invalid, row, raw):
        raise SystemExit("matrix gate below-threshold fixture failed")
    nonfinite = dict(valid)
    nonfinite["overlay_to_underlay_ratio"] = float("nan")
    if not validate_summary("fixture", nonfinite, row, raw):
        raise SystemExit("matrix gate non-finite-ratio fixture failed")
    inconsistent = dict(valid)
    inconsistent["static_endpoint_consistency"] = {
        "consistent": False,
        "relative_errors": {"overlay": 0.0, "underlay": 0.0, "ratio": 0.0},
    }
    if not validate_summary("fixture", inconsistent, row, raw):
        raise SystemExit("matrix gate static-consistency fixture failed")
    dynamic = dict(valid)
    dynamic["timeline"] = [{"step": 1}]
    dynamic["timeline_synchronization"] = {"comparable": True}
    if validate_summary("fixture", dynamic, row, raw):
        raise SystemExit("matrix gate synchronized-dynamic fixture failed")
    mismatched = dict(valid)
    mismatched["overlay_to_underlay_ratio"] = minimum_overall_ratio + 0.01
    if not validate_summary("fixture", mismatched, row, raw):
        raise SystemExit("matrix gate raw-receiver mismatch fixture failed")

validate_gate_fixture()
gate_failures = []
validated = []
for name, expected_row in expected.items():
    scenario_failures = list(artifact_failures.get(name) or [])
    scenario_failures.extend(
        validate_summary(name, summaries.get(name), expected_row, raw_results.get(name))
    )
    gate_failures.extend(scenario_failures)
    if not scenario_failures:
        validated.append(name)
full_catalog = full_catalog and len(expected) == catalog_count
gate = {
    "passed": not gate_failures,
    "full_catalog": full_catalog,
    "scope": "full_catalog" if full_catalog else "selected_subset",
    "catalog_count": catalog_count,
    "selected_count": len(expected),
    "validated_count": len(validated),
    "minimum_overall_ratio": minimum_overall_ratio,
    "selected_scenarios": list(expected),
    "validated_scenarios": validated,
    "ratios_recomputed_from_original_receiver_json": True,
    "recomputed_receiver_ratios": {
        name: raw_results[name]["ratio"] for name in expected if name in raw_results
    },
    "segment_ratios_are_diagnostic": True,
    "failures": gate_failures,
}
temporary = root / f".gate.json.tmp-{os.getpid()}"
with temporary.open("x") as handle:
    json.dump(gate, handle, ensure_ascii=False, indent=2)
    handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())
os.replace(temporary, root / "gate.json")
if gate_failures:
    raise SystemExit("matrix gate failed:\n  " + "\n  ".join(gate_failures))
PY

echo "$MATRIX_OUT"
