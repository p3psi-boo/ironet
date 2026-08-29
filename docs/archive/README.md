# 历史档案

本目录保存已经完成、被替代或仅用于追溯决策过程的设计计划、交接记录和测量报告。它们不是当前部署、接口或验收的规范；阅读和修改生产配置时，应以主文档区为准。

## 当前规范入口

- [策略运行时架构](../策略运行时架构.md)：策略 ABI、宿主边界、装载层级与运行时裁决的当前概览。
- [配置参考](../配置参考.md)：`[autotune]`、`[autotune.wasm]`、签名信任根与热切换的现行配置语义。
- [开发与测试](../开发与测试.md)：WIT、builtin guest 构建和当前验证命令。
- [性能验证](../性能验证.md)：当前性能/网络验收流程。

## 归档内容

| 材料 | 归档原因 | 仍有价值 |
| --- | --- | --- |
| [WASM 策略模块化实施计划](wasm-policy/WASM策略模块化实施计划.md) | 阶段计划已完成，依赖版本、迁移窗口和待办已被当前实现取代。 | ABI、guardrail、包格式和决策取舍的设计背景。 |
| [WASM 策略实施交接记录](wasm-policy/WASM策略交接记录.md) | 一次性会话交接，记录的“进行中”状态和验证环境均已过期。 | Phase 0–6 的落地轨迹与历史测试证据。 |
| [Phase 0 runtime spike 报告](wasm-policy/WASM策略Phase0-runtime-spike.md) | 基准针对 Rust 1.91 / Wasmtime 43；当前仓库使用 Rust 1.95 / Wasmtime 48。 | Pulley 与 Cranelift 取舍的原始测量和方法。 |
| [自适应调优交接](autotune/自适应调优交接.md) | 以 JSON `PolicyArtifact` 加载路径为前提，生产配置现已只接受 `native`、`builtin` 或 `.wasm`。 | 早期调优实验、场景和问题定位记录。 |

Phase 0 的可复现源码保留在 [`tools/phase0-spike`](../../tools/phase0-spike/README.md)。生成的二进制、`.cwasm`、日志和原始输出不入库；运行该目录的脚本会在本地忽略目录中重新生成。
