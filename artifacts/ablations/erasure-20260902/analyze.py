#!/usr/bin/env python3
"""Summarize the 2026-09-02 BBR3 erasure ablation netns runs."""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import statistics
from collections import defaultdict
from pathlib import Path


RUNS = {
    "cross-highrtt": {
        "conventional-loss": ["conventional-loss-r0", "conventional-loss-r1", "conventional-loss-r2"],
        "classify-only": ["classify-only-r0", "classify-only-r1", "classify-only-r2"],
        "full": ["full-off-r0", "full-host-r1", "full-host-r2"],
    },
    "severe-loss": {
        "conventional-loss": ["conventional-loss-r0", "conventional-loss-r1", "conventional-loss-r2"],
        "classify-only": ["classify-only-r0", "classify-only-r1", "classify-only-r2"],
        "full": ["full-host-r0", "full-host-r1", "full-host-r2"],
    },
    "clean": {
        "conventional-loss": ["conventional-loss-r0"],
        "classify-only": ["classify-only-r0", "classify-only-r1", "classify-only-r2"],
        "full": ["full-host-r0", "full-host-r1", "full-host-r2"],
    },
    "shallow-fec": {
        "fec-off": ["fec-off-r0", "fec-off-r1", "fec-off-r2"],
        "fec-on": ["fec-on-r0", "fec-on-r1", "fec-on-r2"],
    },
}

METRICS = (
    "overlay_mbps",
    "underlay_mbps",
    "overlay_to_underlay_ratio",
    "ping_p95_ms",
    "utility_last10_mean",
    "residual_loss_ppm_mean",
    "final5_cwnd_kib",
    "final5_pacing_mbps",
    "parity_to_payload_ratio",
)


def finite(value: object) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(f"non-finite metric: {value!r}")
    return number


def load_run(raw_root: Path, scenario: str, variant: str, run_name: str) -> dict[str, object]:
    path = raw_root / "runs" / scenario / run_name / "summary.json"
    with path.open() as handle:
        data = json.load(handle)

    if not data.get("throughput_comparison", {}).get("comparable"):
        raise ValueError(f"run is not comparable: {path}")

    duration = int(data["duration_seconds"])
    taps = [
        sample
        for sample in data["autotune_tap"]["a"]
        if 0 <= finite(sample["offset_seconds"]) <= duration
    ]
    parity_bytes = sum(int(sample["wire_cost"]["parity_bytes"]) for sample in taps)
    payload_bytes = sum(int(sample["wire_cost"]["payload_bytes"]) for sample in taps)
    loss_flags = sorted({
        bool(sample["decision"]["bbr"]["loss_is_congestion"])
        for sample in taps
    })
    controller_tail = data["controller_interval_series"][-5:]
    pacing_mbps = statistics.mean(
        finite(sample["controller_pacing_rate_bytes_per_second"]) for sample in controller_tail
    ) * 8 / 1_000_000

    repetition = int(re.search(r"-r(\d+)$", run_name).group(1))
    return {
        "scenario": scenario,
        "variant": variant,
        "repetition": repetition,
        "raw_run": run_name,
        "binary_sha256": data["binary_sha256"],
        "duration_seconds": duration,
        "overlay_mbps": finite(data["overlay_received_bits_per_second"]) / 1_000_000,
        "underlay_mbps": finite(data["underlay_received_bits_per_second"]) / 1_000_000,
        "overlay_to_underlay_ratio": finite(data["overlay_to_underlay_ratio"]),
        "ping_p95_ms": finite(data["overlay_concurrent_ping"]["p95_ms"]),
        "utility_last10_mean": finite(data["autotune"]["a"]["utility_last10_mean"]),
        "residual_loss_ppm_mean": finite(data["autotune"]["a"]["residual_loss_ppm_mean"]),
        "final5_cwnd_kib": finite(data["controller_alignment"]["final5_controller_cwnd_bytes_mean"]) / 1024,
        "final5_pacing_mbps": pacing_mbps,
        "parity_to_payload_ratio": parity_bytes / payload_bytes if payload_bytes else 0.0,
        "loss_is_congestion_values": json.dumps(loss_flags, separators=(",", ":")),
        "fec_geometry_histogram": json.dumps(
            data["autotune"]["a"]["fec_geometry_histogram"], sort_keys=True, separators=(",", ":")
        ),
        "force": json.dumps(data["autotune_force"], sort_keys=True, separators=(",", ":")),
        "summary_path": str(path),
    }


def aggregate(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    groups: dict[tuple[str, str], list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        groups[(str(row["scenario"]), str(row["variant"]))].append(row)

    output = []
    for (scenario, variant), group in groups.items():
        item: dict[str, object] = {"scenario": scenario, "variant": variant, "n": len(group)}
        for metric in METRICS:
            values = [finite(row[metric]) for row in group]
            item[f"{metric}_median"] = statistics.median(values)
            item[f"{metric}_mean"] = statistics.mean(values)
            item[f"{metric}_min"] = min(values)
            item[f"{metric}_max"] = max(values)
            item[f"{metric}_cv_percent"] = (
                statistics.pstdev(values) / statistics.mean(values) * 100
                if len(values) > 1 and statistics.mean(values) != 0
                else 0.0
            )
        output.append(item)
    return sorted(output, key=lambda row: (str(row["scenario"]), str(row["variant"])))


def comparisons(aggregates: list[dict[str, object]]) -> list[dict[str, object]]:
    by_key = {(row["scenario"], row["variant"]): row for row in aggregates}
    pairs = (
        ("cross-highrtt", "conventional-loss", "classify-only"),
        ("cross-highrtt", "conventional-loss", "full"),
        ("cross-highrtt", "classify-only", "full"),
        ("severe-loss", "conventional-loss", "classify-only"),
        ("severe-loss", "conventional-loss", "full"),
        ("severe-loss", "classify-only", "full"),
        ("clean", "classify-only", "full"),
        ("shallow-fec", "fec-off", "fec-on"),
    )
    output = []
    for scenario, baseline_name, candidate_name in pairs:
        baseline = by_key[(scenario, baseline_name)]
        candidate = by_key[(scenario, candidate_name)]
        row: dict[str, object] = {
            "scenario": scenario,
            "baseline": baseline_name,
            "candidate": candidate_name,
            "baseline_n": baseline["n"],
            "candidate_n": candidate["n"],
        }
        for metric in METRICS:
            base = finite(baseline[f"{metric}_median"])
            value = finite(candidate[f"{metric}_median"])
            row[f"{metric}_absolute_delta"] = value - base
            row[f"{metric}_percent_delta"] = (value / base - 1) * 100 if base else None
        output.append(row)
    return output


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    if not rows:
        raise ValueError(f"no rows for {path}")
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    repo = Path(__file__).resolve().parents[3]
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--raw-root",
        type=Path,
        default=repo / "target" / "ablation-erasure-20260902",
    )
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()

    rows = [
        load_run(args.raw_root, scenario, variant, run_name)
        for scenario, variants in RUNS.items()
        for variant, run_names in variants.items()
        for run_name in run_names
    ]
    aggregates = aggregate(rows)
    deltas = comparisons(aggregates)
    args.output.mkdir(parents=True, exist_ok=True)
    write_csv(args.output / "results.csv", rows)
    write_csv(args.output / "aggregate.csv", aggregates)
    write_csv(args.output / "deltas.csv", deltas)
    with (args.output / "summary.json").open("w") as handle:
        json.dump(
            {"schema_version": 1, "runs": rows, "aggregates": aggregates, "comparisons": deltas},
            handle,
            indent=2,
            sort_keys=True,
        )
        handle.write("\n")


if __name__ == "__main__":
    main()
