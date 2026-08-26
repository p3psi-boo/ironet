# Ironet noq-proto V2 patch

- Upstream crate: `noq-proto 1.1.1`
- crates.io checksum: recorded in `Cargo.lock`
- Integration: the root `[patch.crates-io]` selects `crates/noq-proto-v2` for
  every Ironet build. This directory is excluded from the root workspace so its
  upstream examples and development dependencies remain isolated.

## Ownership boundary

The upstream BBR3 algorithm remains in `src/congestion/bbr3/mod.rs`. Ironet's
runtime-tunable contract is isolated in `src/congestion/bbr3/tunables.rs`:

- `Bbr3Tunables` is the host-to-controller shared, generation-versioned input.
- `Bbr3Params` is the controller-local validated snapshot read at a round
  boundary.
- BBR3 reports controller state through the upstream congestion interface; the
  Ironet runtime consumes that state without reaching into BBR3 internals.

The remaining Ironet-specific BBR behavior covers bounded capacity probes,
short-path queue protection, and shallow-policer pacing. Keep it behind BBR3
hook points and move new host-policy state to `tunables.rs` rather than adding
more product state to `Bbr3`.

## Rebase and verification contract

Maintain this fork as a patch series on the documented upstream release:

1. Rebase each local change onto the recorded upstream tag.
2. Keep `tunables.rs` and the explicit BBR3 hook diff reviewable separately
   from upstream algorithm changes.
3. Run the root workspace gate plus the vendored crate gate below before
   updating this manifest.

```bash
cargo test --manifest-path crates/noq-proto-v2/Cargo.toml --locked
cargo check --manifest-path crates/noq-proto-v2/Cargo.toml --features qlog --locked
```
