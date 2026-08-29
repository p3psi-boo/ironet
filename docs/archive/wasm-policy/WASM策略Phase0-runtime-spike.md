# WASM 策略 Phase 0：Wasmtime runtime spike 报告（历史）

> **归档状态（2026-08-22）**：本报告记录 Rust 1.91 / Wasmtime 43 的一次选型测量。当前仓库使用 Rust 1.95 / Wasmtime 48；现行运行时契约见[策略运行时架构](../../策略运行时架构.md)。
> 对应[WASM 策略模块化实施计划](WASM策略模块化实施计划.md)的 Phase 0 “用 Pulley 与 Cranelift 两种 Wasmtime 配置各做一次 spike”。
> 日期：2026-08-21。执行机：NixOS（Linux 6.18.43，16 核，23 GiB 内存），Rust 1.91.0（独立 flake devShell）。
> 可复现源码保留在 [`tools/phase0-spike`](../../../tools/phase0-spike/README.md)。生成的二进制、`.cwasm`、构建日志和原始文本输出已从仓库移除；按第 10 节命令可重新生成到本地忽略目录。

## 1. 环境与工具链可用性

| 项目 | 结果 |
| --- | --- |
| 裸 shell 中的 `rustc`/`cargo`/`rustup` | 均不存在（NixOS，没有 rustup；`~/.rustup/toolchains/stable-*` 目录存在但没有二进制） |
| `nix develop`（仓库 flake devShell） | 可用：`rustc 1.91.0 (f8297e351 2025-10-28)`、`cargo 1.91.0`，来自 rust-overlay `rust-bin.stable."1.91.0"` |
| devShell 已装 target | 仅 `x86_64-unknown-linux-gnu`、`x86_64-unknown-linux-musl`；**没有 `wasm32-unknown-unknown` 的 rust-std** |
| `rustc --print target-list \| grep wasm32` | 列出 `wasm32-unknown-unknown`、`wasm32-wasip1`、`wasm32-wasip2`、`wasm32v1-none` 等（编译器认识，但缺 std 库） |
| `rustup target add` | 不可用（无 rustup）。替代方案：rust-overlay 的 `targets = [ "wasm32-unknown-unknown" ]`，验证可行（见下） |
| `wasm-tools` / `wit-bindgen` / `wasm-opt` | 裸 shell 与 devShell 中均不存在 |
| 通过 nixpkgs 获取 | 用仓库保留的独立 flake（`tools/phase0-spike/nix-wasm-shell/flake.nix`，含自身锁文件）加入 `pkgs.wasm-tools`、`pkgs.wit-bindgen` 并给 rust 加 `wasm32-unknown-unknown` target：**首次进入 27 s 完成**（从 cache.nixos.org 拉取 `wasm-tools 1.254.0`、`wit-bindgen-cli 0.60.0`，从 static.rust-lang.org 拉取 `rust-std-1.91.0-wasm32-unknown-unknown`） |
| 其他工具 | `bc`、`file` 不在 devShell（测量脚本改用 GNU `time`）；`strip` 来自 binutils 2.46 |
| 磁盘 | 原始测量机的临时文件系统容量不足以容纳三个 Cranelift target 目录；当前复现脚本将所有输出写入可配置的 `OUT` 目录 |

仓库 `flake.nix` 未做任何修改；建议改法见第 8 节。

## 2. 网络可用性

- `static.rust-lang.org` HTTP 200；crates.io 索引和下载正常（`cargo search` / `cargo info` / `cargo fetch` 均成功）；cache.nixos.org 正常。
- 因此 spike 使用的是 crates.io 最新可用版本，未依赖 `~/.cargo/registry` 中的旧缓存。

## 3. wasmtime 版本与 feature 集

### 3.1 版本选择（MSRV 约束）

`cargo info wasmtime@<v>` 查得的 `rust-version`：

| wasmtime | rust-version | 备注 |
| --- | --- | --- |
| 48.0.0（crates.io 最新） | 1.95.0 | LTS 线（24/36/48）。仓库 toolchain 1.91 **编不了** |
| 47.0.0 / 46.0.0 | 1.94.0 | |
| 45.0.0 | 1.93.0 | |
| 44.0.0 | 1.92.0 | |
| **43.0.x** | **1.91.0** | 本次 spike 实际使用 **43.0.2**（resolver 3 按 rust-version 自动选到的最新兼容版） |
| 42.0.0 | 1.91.0 | |
| 41.0.0 | 1.90.0 | |
| 36.0.0–36.0.10 | 1.86.0 | 上一条 LTS 线，仍在维护；与 1.91 兼容 |

结论：保持 Rust 1.91 则只能用 43.x（非 LTS，下一版发布后停止打补丁）或 36.x LTS；若想用 48 LTS 需把 `rust-toolchain.toml` / `flake.nix` 提到 ≥ 1.95。48.0.0 的 feature 名称与门控（`pulley = []`、`cranelift`、`runtime`、`component-model`、`std`、`Component::new` 的 `cfg(any(feature = "cranelift", feature = "winch"))`）与 43 完全一致，下文结论不随版本变化。

### 3.2 feature 集与一个关键发现

spike host 使用 `default-features = false, features = ["runtime", "component-model", "std"]`，在此之上做三种配置：

| 配置 | 追加 feature | 能做什么 |
| --- | --- | --- |
| (a) `pulley`（无编译器） | `pulley` | 只能 `Component::deserialize*()` 加载**预编译** `.cwasm`（pulley64 字节码或本机机器码都能加载）；`Component::new` / `Engine::precompile_component` 在编译期不存在 |
| (b) `cranelift,pulley` | `cranelift` + `pulley` | 运行时把 `.wasm` 编译成 pulley64 字节码并用 Pulley 解释执行（`Config::target("pulley64")`），也可编译成本机码 |
| (c) `cranelift` | `cranelift` | 运行时 JIT 到本机码；**没有 `pulley` feature 时 `Config::target("pulley64")` 会被 Engine 拒绝**（"target does not match the host"） |

发现（影响计划 7.1 的前提）：

1. wasmtime 中 `pulley = []` 只是一个**标记 feature**：允许 Engine 以 `pulley64` 为目标并走解释器；Pulley 解释器本身（`pulley-interpreter/interp`）已随 `runtime` feature 无条件编入。
2. **把 wasm 编译成 Pulley 字节码的编译器就是 Cranelift**（`wasmtime-cranelift` 以 `features = ["pulley"]` 依赖 `cranelift-codegen`，Pulley 是它的一个后端），而且 `cranelift-codegen` 被强制打开 `host-arch`（x86 后端）。因此"Pulley 执行 + 进程内编译"与"Cranelift JIT"的二进制增量**几乎一样**（相差约 60 KiB），计划 7.1 表中"Pulley 解释器（cranelift feature 关闭）二进制增量小数 MB 级"**只对 AOT-only（进程内无编译器）成立**。
3. `gc`/`threads` feature 关闭时，`Config::wasm_gc/wasm_threads/wasm_reference_types/wasm_function_references/wasm_exceptions` 这些方法**不存在**（编译错误），对应提案在 `WasmFeatures` 里按 `cfg!(feature)` 静态关闭；不必也不能在代码里再调用。
4. `Component::deserialize*` 是 `unsafe`（信任 `.cwasm` 内部元数据；对本机目标等同于加载机器码）；`.cwasm` 与 wasmtime 版本及 `Engine::precompile_compatibility_hash()` 绑定，版本升级必须重编。
5. `runtime` feature 带 `cc` 构建 C helper（`wasmtime-helpers`），musl 静态构建需要 `CC_x86_64_unknown_linux_musl`（仓库 `devShells.static` 已设置）。

## 4. 二进制增量

宿主 spike crate：`phase0-host`（一个 bin，包含 `wasmtime::component::bindgen!` 宿主绑定、fuel/epoch/StoreLimits 配置与测量代码）。基线为一个只 `println!` 的空 bin。两种 profile 各测一次，均为冷构建（空 target 目录，16 核）。

### 4.1 spike profile（`opt-level=3, lto="fat", codegen-units=1, panic="abort"`，手工 `strip`）

| 二进制 | stripped 大小 | 相对基线增量 | 冷构建墙钟 / user CPU | 构建峰值 RSS |
| --- | ---: | ---: | --- | ---: |
| baseline-empty | 318,736 B (0.30 MiB) | — | 2.3 s | — |
| (a) `pulley`（无编译器） | 1,225,080 B (1.17 MiB) | **+906 KiB (+0.86 MiB)** | 50.9 s / 131.8 s | 0.78 GiB |
| (c) `cranelift` | 10,014,168 B (9.55 MiB) | **+9,695 KiB (+9.25 MiB)** | 138.4 s / 334.3 s | 1.32 GiB |
| (b) `cranelift,pulley` | 10,074,696 B (9.61 MiB) | **+9,754 KiB (+9.30 MiB)** | 145.0 s / 336.9 s | 1.32 GiB |

### 4.2 仓库 profile（`lto="thin", codegen-units=1, strip=true`, panic=unwind，与 ironet `[profile.release]` 一致）

| 二进制 | 大小 | 相对基线增量 | 冷构建墙钟 / user CPU |
| --- | ---: | ---: | --- |
| baseline-empty | 350,688 B (0.33 MiB) | — | — |
| (a) `pulley` | 1,499,552 B (1.43 MiB) | **+1,122 KiB (+1.10 MiB)** | 45.3 s / 136.0 s |
| (c) `cranelift` | 12,125,568 B (11.56 MiB) | **+11,499 KiB (+11.23 MiB)** | 121.7 s / 392.7 s |
| (b) `cranelift,pulley` | 12,192,736 B (11.63 MiB) | **+11,564 KiB (+11.29 MiB)** | 128.2 s / 414.2 s |

参照：当前 `target/release/ironetd`（stripped）22,025,880 B（21.0 MiB），`dist/ironet_0.1.0_amd64.deb` 9.4 MiB。即按仓库 profile 估算，带编译器的配置让 ironetd 增大约 **+11.3 MiB（≈ +54 %）**，无编译器配置约 **+1.1 MiB（≈ +5 %）**（thin LTO + panic=unwind 比 spike profile 多约 2 MiB）。

guest 侧：`wasm32-unknown-unknown` cdylib（`opt-level="s"`, lto fat, panic abort）冷构建 16.2 s（含 wit-bindgen 过程宏依赖），core wasm 11,397 B，`wasm-tools component new` 后 component 11,486 B。

## 5. 运行时测量

### 5.1 方法

- guest：WIT world `decide: func(input: list<u8>) -> list<u8>`（`wit/policy.wit`），Rust 实现做 f64 EWMA + 8 个候选动作各 32 轮打分（纯计算，无 import、无 WASI、无分配热点），用 wit-bindgen 0.60 `generate!` + `wasm-tools component new` 打包成 component。
- host：`wasmtime::component::bindgen!` 绑定，Engine 打开 `consume_fuel(true)`、`epoch_interruption(true)`（后台线程每 10 ms `increment_epoch`，每次调用 `set_epoch_deadline(2)`）、`StoreLimits`（memory 8 MiB、1 instance）、`max_wasm_stack(512 KiB)`、`memory_reservation(8 MiB)`、nan canonicalization on、relaxed-simd/simd/memory64/multi-memory/tail-call 全关。
- 每次调用前 `set_fuel(1e9)`，调用后 `get_fuel()` 差值即 fuel 消耗；先 1 次首调 + 100 次预热，再计时 1000 次；实例化用 100 次全新 `Store` 计时。输入默认 1 KiB（64 个 (rtt, loss) f64 样本）。
- 每个后端重复跑 4 次取区间。原始输出未保留；可用 `tools/phase0-spike/run.sh` 重新生成可比输出。

### 5.2 主表（输入 1 KiB，1000 次）

| 执行方式（宿主构建） | 编译/加载 component | 实例化 p50 / p99 | 首调 | 调用 p50 | 调用 p99 | 调用 max | fuel/次 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Cranelift 本机 JIT（(b) 或 (c)，`Component::new`） | 15.9–20.9 ms | 3.4 µs / 27 µs | 19 µs | **2.5–3.2 µs** | **3.5–4.1 µs** | 5–14 µs | 7,379 |
| Pulley，进程内编译（(b)，`Component::new` + `target("pulley64")`） | 14.1–19.1 ms | 2.6 µs / 7.9 µs | 96 µs | **55–83 µs** | **74–164 µs** | 100–193 µs | 7,379 |
| Pulley，AOT 加载（(a)，`deserialize` pulley64 `.cwasm` 135,376 B） | **0.13–0.21 ms** | 3.2 µs / 13 µs | 98 µs | **62–73 µs** | **72–121 µs** | 103–203 µs | 7,379 |
| 本机码 AOT 加载（(a)，`deserialize` 本机 `.cwasm` 49,368 B） | 0.14 ms | 3.8 µs / 11 µs | 22 µs | 2.7 µs | 4.0 µs | 4.9 µs | 7,379 |

- 四种方式输出字节完全一致（`out0_hex` 与 1000 次 checksum 相同），fuel 消耗完全一致（fuel 在 Cranelift 中端插桩，与后端无关）。
- `Engine::precompile_component` 耗时 14.5 ms（pulley64）/ 16.9 ms（本机）。
- 进程 RSS：含 Cranelift 的宿主编译后约 12 MiB；无编译器宿主加载 `.cwasm` 后约 3.3 MiB。

### 5.3 输入规模扩展（Cranelift 本机 vs Pulley AOT）

| 输入 | fuel/次 | 本机 p50 / p99 | Pulley p50 / p99 / max |
| ---: | ---: | ---: | ---: |
| 64 B | 5,583 | 2.3 / 3.4 µs | 51 / 86 / 94 µs |
| 1 KiB | 7,379 | 2.8 / 3.9 µs | 69 / 81 / 135 µs |
| 4 KiB | 12,947 | 4.3 / 5.6 µs | 127 / 151 / 251 µs |
| 16 KiB | 35,219 | 11.5 / 14.9 µs | 336 / 392 / 543 µs |
| 64 KiB（计划 7.3 最大输入） | 124,307 | 39.7 / 51.2 µs | **1.23 / 1.93 / 2.04 ms** |

经验换算：Pulley 约 8–10 ns/fuel，本机约 0.35–0.4 ns/fuel，Pulley 慢 20–30 倍；10 ms deadline 在 Pulley 上约对应 **1.0–1.2 M fuel**。

## 6. Engine / Store API 名称清单（wasmtime 43.0.2，48.0.0 同名）

| 计划 7.3/7.3.1 条目 | 准确 API | 备注 |
| --- | --- | --- |
| relaxed_simd off | `Config::wasm_relaxed_simd(false)` | 默认 on，必须显式关 |
| simd off | `Config::wasm_simd(false)` | |
| threads / shared memory off | `Config::wasm_threads(bool)` 仅在 `threads` feature 下存在；**不开该 feature 即静态关闭** | |
| nan canonicalization on | `Config::cranelift_nan_canonicalization(true)`，`#[cfg(any(feature="cranelift", feature="winch"))]` | Pulley 字节码也由 Cranelift 生成，该 pass 同样生效；AOT 模式下该 flag 在 `precompile` 时烘入 `.cwasm`，加载 Engine 必须配置相同值否则 `deserialize` 报 flag 不兼容 |
| memory64 / multi_memory / gc off | `Config::wasm_memory64(false)`、`Config::wasm_multi_memory(false)`；`wasm_gc/wasm_reference_types/wasm_function_references/wasm_exceptions` 仅在 `gc` feature 下存在，不开即关 | `tail_call`、`wide_arithmetic`、`custom_page_sizes`、`extended_const`、`stack_switching` 也有同名 `wasm_*` 开关 |
| fuel | `Config::consume_fuel(true)`；`Store::set_fuel(u64)`、`Store::get_fuel() -> Result<u64>`、`Store::fuel_async_yield_interval` | 耗尽返回 `Trap::OutOfFuel` |
| epoch deadline | `Config::epoch_interruption(true)`；`Store::set_epoch_deadline(ticks)`、`Store::epoch_deadline_trap()`、`Store::epoch_deadline_callback(..)`；`Engine::increment_epoch()` | 需宿主自建 ticker 线程 |
| 内存/表/实例上限 | `wasmtime::StoreLimitsBuilder::new().memory_size(..).memories(..).tables(..).table_elements(..).instances(..).trap_on_grow_failure(..).build() -> StoreLimits`；`Store::limiter(\|s\| &mut s.limits)`；自定义实现 `ResourceLimiter` trait | |
| 线性内存布局 | `Config::memory_reservation(bytes)`、`memory_reservation_for_growth`、`memory_guard_size`、`guard_before_linear_memory`、`memory_may_move(false)`、`memory_init_cow` | `max_memory_size` 属于 `PoolingAllocationConfig`，不是 `Config` |
| 栈 | `Config::max_wasm_stack(usize)` | |
| 编译目标 / 策略 | `Config::target("pulley64")`、`Config::strategy(Strategy::{Auto,Cranelift,Winch})`、`Config::cranelift_opt_level(OptLevel)` | 没有 `Strategy::Pulley`，Pulley 由 target 决定 |
| 编译 / AOT | `Component::new/from_binary/from_file`（需 `cranelift`/`winch`）、`Engine::precompile_component(&[u8]) -> Vec<u8>`、`unsafe Component::deserialize/deserialize_file/deserialize_raw`、`Component::serialize`、`Engine::detect_precompiled[_file]`、`Engine::precompile_compatibility_hash()` | |
| 其他 | `Config::wasm_backtrace_max_frames(None)`（`wasm_backtrace` 已弃用）、`native_unwind_info(false)`、`generate_address_map(false)`、`parallel_compilation` 仅在 `parallel-compilation` feature 下存在 | |

## 7. 结论：默认 Pulley 还是 Cranelift

1. **执行后端：默认 Pulley 成立。** 计划 7.3 的 deadline 是 10 ms、每 peer 每秒一次。Pulley 在 1 KiB 输入下 p99 ≤ 0.2 ms、64 KiB 极限输入下 p99 ≤ 2 ms，留有 5–50 倍余量；单 worker 每秒可完成约 1 万次 1 KiB 调用，远超目标 peer 数。本机 JIT 的 3 µs 没有业务价值。Pulley 还同时满足"无 W^X 可执行页、hot reload 无 JIT CPU 峰值、与 native 输出逐位一致"（本次验证输出与 fuel 逐位相同）。
2. **二进制增量需要改写计划 7.1 的预期。** 真正的分水岭不是 Pulley vs Cranelift，而是 **进程内有没有编译器**：
   - 有编译器（能在 ironetd 里把任意 `.wasm` 变成可执行）：+9.3 MiB（spike profile）/ +11.3 MiB（仓库 profile），无论最终用 Pulley 还是 JIT 执行。
   - 无编译器（AOT-only）：+0.86 MiB（spike profile）/ +1.10 MiB（仓库 profile），但只能加载与 wasmtime 版本锁定的 `.cwasm`，第三方 `.wasm` 必须由别的进程预编译，且 `deserialize` 是 `unsafe`、信任输入。
3. **建议的默认：Phase 2 起 features = `runtime, component-model, std, cranelift, pulley`，`Config::target("pulley64")`**（Pulley 执行 + 进程内 Cranelift 编译）。理由：第三方单文件 `.wasm` 热切换、按 digest 共享编译结果、CI 不必维护与 wasmtime 版本耦合的 `.cwasm`；11 KiB component 编译 15–20 ms，真实 builtin 预计百 KiB 级、百毫秒级，按计划 7.2 放在 worker 线程即可，**不需要 `cache` feature 的磁盘缓存**。接受 ironetd 约 +11 MiB（仓库 profile；若改 fat LTO + panic=abort 约 +9.3 MiB）。
4. **体积优化备选（若 +9 MiB 超过验收预算）**：ironetd 用 (a) 无编译器构建，`builtin.wasm` 在构建时预编译为 pulley64 `.cwasm` 并 `include_bytes!`；第三方策略由带 Cranelift 的 `ironet` CLI（`ironet policy compile`）或 CI 预编译到按 `(digest, precompile_compatibility_hash)` 命名的缓存目录，ironetd 只 `deserialize`。代价：`.cwasm` 随每次 wasmtime 升级失效、需要额外签名/校验链、热切换多一跳。本次数据表明 AOT 路径的加载时间（0.13–0.21 ms）和调用延迟与进程内编译一致，技术上可行，建议列为 Phase 3/6 的可选项而不是 MVP。
5. **fuel 预算标定**：本 spike guest 7,379 fuel/次（1 KiB），与后端无关；按计划 7.3 "builtin 实测 p99 × 10" 初始化，且 Pulley 上 10 ms ≈ 1.0–1.2 M fuel，fuel 上限应取 `min(10 × builtin_p99, ~1M)` 量级并在 Phase 2 用真实 builtin 重标。
6. **wasmtime 版本**：Rust 1.91 下用 `43.0.x`（最新兼容，非 LTS）或 `36.0.x`（LTS，MSRV 1.86）；建议在引入前把 toolchain 提到 1.95 并直接用 `48.0.x` LTS（rust-overlay 改一行即可），否则选 36 LTS 以获得补丁支持。

## 8. Nix / CI 引入 wasm32 target 与 wasm-tools 的建议

`flake.nix`（不在本次修改范围，建议 diff）：

```nix
rust = pkgs.rust-bin.stable."1.91.0".default.override {
  extensions = [ "clippy" "rust-src" "rustfmt" ];
  targets = [ "x86_64-unknown-linux-musl" "wasm32-unknown-unknown" ];   # + wasm32
};
# devShells.default.packages 追加：
pkgs.wasm-tools      # 1.254.0（当前 flake.lock 的 nixpkgs）
pkgs.wit-bindgen     # wit-bindgen-cli 0.60.0，只在需要命令行生成绑定/检查 WIT 时用；guest 用 wit-bindgen crate 的 generate! 不依赖它
```

- 已用相同 lock 在 scratchpad flake 中验证：进入 shell 27 s，`rustc --print sysroot/lib/rustlib/` 出现 `wasm32-unknown-unknown`，`cargo build --target wasm32-unknown-unknown` 与 `wasm-tools component new/validate/component wit` 正常。
- `devShells.static`（musl 打包）不需要 wasm32，只需保证 `CC_x86_64_unknown_linux_musl`（已有）供 wasmtime `runtime` 的 C helper 编译。
- `packages.default`（`buildRustPackage`）不交叉编译 guest：按计划 10.1，`builtin.wasm` 是提交进仓库的产物，`build.rs` 只 `include_bytes!` + 校验 digest。
- CI（`.forgejo/workflows/ci.yml` / `.github/workflows/ci.yml`）：
  - `rustup toolchain install 1.91.0 ... --target x86_64-unknown-linux-musl,wasm32-unknown-unknown`
  - 安装 wasm-tools：`cargo install wasm-tools --locked --version 1.254.0`（或下载 GitHub release 二进制并校验 sha256），版本与 flake 保持一致；
  - 新增步骤 `scripts/build-policy-guest.sh` 重建 `builtin.wasm` 并 `cmp` 与提交文件一致（digest 门禁）；
  - CI 缓存 `~/.cargo/registry` 与 target：wasmtime(cranelift) 冷编译在 16 核下 2.5 min / 337 s CPU，CI 机器上预计 5–10 min，建议开启 sccache 或 actions cache。
- 可复现性：guest 构建参数固定 `-C panic=abort`、`opt-level="s"`、`lto=fat`、`codegen-units=1`、`strip=true`，并在脚本里 `export SOURCE_DATE_EPOCH`、`CARGO_HOME` 相对路径（`--remap-path-prefix`）以保证 digest 稳定。

## 9. 建议写入仓库 Cargo.toml 的依赖行（待 Phase 2）

```toml
# ironet（宿主）
[dependencies]
wasmtime = { version = "43.0", default-features = false, features = [
    "runtime", "component-model", "std",
    "cranelift",   # 进程内编译（也是 Pulley 字节码编译器）
    "pulley",      # 允许 Config::target("pulley64")
] }
# 若决定 AOT-only 体积路线：去掉 "cranelift"，保留 "pulley"，只用 Component::deserialize。
# 若 toolchain 升到 >= 1.95：version = "48.0"（LTS）；若留 1.91 且要 LTS：version = "36.0"。
# 不要打开：async、cache、wat、gc*、threads、profiling、parallel-compilation、pooling-allocator、
# coredump、debug-builtins、addr2line、component-model-async、stack-switching。

# crates/ironet-policy-sdk / crates/ironet-policy-builtin（guest，target wasm32-unknown-unknown）
[dependencies]
wit-bindgen = { version = "0.60", default-features = false, features = ["macros"] }
[lib]
crate-type = ["cdylib"]
[profile.release]
opt-level = "s"
lto = "fat"
codegen-units = 1
panic = "abort"
strip = true
```

测试/工具侧如需 `wat`（手写 fixture）只在 `dev-dependencies` 或 `wasmtime = { ..., features = ["wat"] }` 的 dev 配置中打开。

## 10. spike 源码与复现

仓库目录 `tools/phase0-spike/`：

```text
nix-wasm-shell/flake.nix, flake.lock   # Rust 1.91 + wasm32 + wasm-tools 的历史复现 shell
wit/policy.wit                         # world policy { export decide: func(input: list<u8>) -> list<u8>; }
guest/                                 # wasm32-unknown-unknown cdylib，wit-bindgen generate!
host/                                  # phase0-host：features pulley / cranelift；modes run | precompile | load
run.sh                                 # 构建 guest、运行 JIT/Pulley/AOT 组合并写入 OUT
out/                                   # 本地生成目录，受 .gitignore 保护
```

复现要点：

```sh
# 从仓库根目录运行；输出默认写到 tools/phase0-spike/out/
nix develop ./tools/phase0-spike/nix-wasm-shell -c ./tools/phase0-spike/run.sh

# 或将生成的 target、component、.cwasm 与文本输出置于其他位置
OUT=/var/tmp/ironet-phase0 \
  nix develop ./tools/phase0-spike/nix-wasm-shell -c ./tools/phase0-spike/run.sh
```

脚本使用该目录的锁文件和 `--locked` Cargo 构建；它重新生成的是可比的本地测量，不试图复现当日机器负载、内核、缓存或精确的微秒数。

## 11. 阻塞与注意事项

- 无阻塞性问题；全部测量完成。
- 环境限制：`/tmp`（scratchpad 所在）只有 2 GiB tmpfs，Cranelift 构建目录需放 `/home`；devShell 缺 `bc`/`file`。
- wasmtime 最新版（48）与仓库 toolchain（1.91）不兼容，需要在"升 toolchain 用 48 LTS"与"留 1.91 用 43 或 36 LTS"之间做决定。
- spike guest 很小（11 KiB component），真实 builtin 的 hot-reload 编译时间与 fuel 需在 Phase 2 重新标定；Pulley 的 "tier" 稳定性声明请在引入时核对 docs.wasmtime.dev/stability-tiers。
- 本 spike 使用同步 API、单线程调用，未测 `PolicyExecutor` worker 池并发；Pulley/本机的单次数字足够支撑 7.1/7.3 的选型。
