# BBR3 丢包视作擦除：消融实验（2026-09-02）

## 结论

在本机 network-namespace 基准中，**将随机丢包从拥塞信号中分离**是本次改动的主要收益来源；新增的 **gross-wire 补偿在本轮两个有损场景中没有产生额外吞吐收益**。浅队列整形场景则明确支持默认关闭 FEC。

- 中等相关丢包：`classify-only` 相对传统丢包处理的吞吐中位数提高 **34.15%**；完整实现相对 `classify-only` 低 **6.53%**。
- 严重相关丢包：`classify-only` 相对传统处理提高 **100.66%**；完整实现相对 `classify-only` 低 **18.74%**。
- 干净链路：完整实现相对 `classify-only` 低 **1.25%**；`n=3`，只能视为无明确收益且可能有小幅成本，不能据此作显著性结论。
- 浅队列整形：强制 `8+1` FEC 相对关闭 FEC，吞吐中位数低 **10.56%**、延迟 p95 高 **1.3 ms**、效用中位数低 **37.03%**；两组控制器 pacing 几乎相同，差异来自 parity 占用 wire budget。

因此，保留 loss-as-erasure 的分类、lower-bound/queue-guard 语义；gross-wire 补偿暂不视为已验证收益项，后续应冻结动态 FEC 安全守卫后再单独复测。

## 消融定义

基线提交：`dcf9e4bd12d7`（`feat: treat packet loss as erasure in BBR3`）。三个 BBR 变体使用同一 Rust 1.95.0 profiling 构建配置。

| 变体 | `loss_is_congestion` | gross-wire 补偿 | 含义 | `ironetd` SHA-256 |
|---|---:|---:|---|---|
| `conventional-loss` | `true` | 关闭 | 恢复传统“丢包即拥塞”，消融完整 loss-as-erasure 语义 | `75c65320f3a7d7dd628e4d077e128c7ecc5df0c7138524608a1974d61279d150` |
| `classify-only` | `false` | 关闭 | 保留丢包分类及其 lower-bound/queue-guard 行为，只消融 gross-wire 补偿 | `a4683bf57308eab683f26b8212f8a8bab038ea5cd744ca5c93406321e116a60f` |
| `full` | `false` | 开启 | 当前完整实现 | `25eac033596e7bf598e02b0efa1d33fab0c95fe77f972d8a89cd3b105346a5bd` |

运行期 tap 共核对 360 个有损场景样本：`conventional-loss` 的 120 个样本全部为 `true`，另外两个变体的 240 个样本全部为 `false`。

## 结果

表内是三次重复的中位数；吞吐 CV 使用三次样本的总体标准差计算。

### BBR 丢包语义

| 场景 | 变体 | n | Overlay Mbps | 吞吐 CV | Overlay/Underlay | Ping p95 | Utility last-10 | Final-5 cwnd | Final-5 pacing |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 中等丢包 | `conventional-loss` | 3 | 16.68 | 10.70% | 3.261 | 106 ms | 0.982 | 327 KiB | 56.45 Mbps |
| 中等丢包 | `classify-only` | 3 | **22.37** | 2.49% | **4.245** | 106 ms | **1.321** | 1309 KiB | 53.86 Mbps |
| 中等丢包 | `full` | 3 | 20.91 | 6.52% | 4.131 | 106 ms | 1.167 | 1681 KiB | 69.74 Mbps |
| 严重丢包 | `conventional-loss` | 3 | 2.81 | 21.74% | 1.495 | 108 ms | -5.284 | 191 KiB | 20.64 Mbps |
| 严重丢包 | `classify-only` | 3 | **5.63** | 14.20% | **2.917** | 110 ms | -2.687 | 1027 KiB | 50.10 Mbps |
| 严重丢包 | `full` | 3 | 4.58 | 21.57% | 2.507 | 109 ms | **-2.581** | 785 KiB | 35.04 Mbps |
| 干净链路 | `classify-only` | 3 | **258.62** | 1.03% | **0.916** | 20.0 ms | **4.161** | 471 KiB | — |
| 干净链路 | `full` | 3 | 255.39 | 1.23% | 0.904 | 17.7 ms | 4.087 | 512 KiB | — |

干净链路的 `conventional-loss` 仅运行了一次（256.33 Mbps），不纳入三重复比较。

完整实现在中等丢包中把 pacing 中位数提高到 69.74 Mbps、cwnd 提高到 1681 KiB，却没有转化为更高 goodput；这与补偿过量或补偿和动态 FEC 反馈互相作用一致。在严重丢包中，完整实现反而比 `classify-only` 使用更低的 pacing/cwnd。当前 profile 没有导出补偿 transition 计数，所以这里只把二进制代码级消融视为因果开关，不声称已直接测得每次补偿状态迁移。

### 浅队列整形中的 FEC

场景为双向 110 Mbps、1.5 ms、20-packet queue、无注入随机丢包；完整 BBR 二进制固定 train=16 KiB、quantum=1，只切换 FEC。

| FEC | n | Overlay Mbps | Overlay/Underlay | Ping p95 | Utility last-10 | Parity/Payload | Final-5 pacing |
|---|---:|---:|---:|---:|---:|---:|---:|
| off | 3 | **84.00** | **0.811** | **10.2 ms** | **4.284** | 0 | 112.27 Mbps |
| `8+1` | 3 | 75.13 | 0.725 | 11.5 ms | 2.698 | 0.172 | 112.29 Mbps |

`8+1` 的实测 parity/payload wire-cost 比值为 17.2%；它与固定 pacing 一起解释了吞吐损失，支持 policer/shallow-shaper 默认 FEC off。

## 实验条件

- 4 条 iperf3 stream；丢包/FEC场景 20 秒，干净场景 15 秒；每秒采样。
- 并发 ping 间隔 50 ms；关闭 perf，避免采样开销污染吞吐。
- deterministic netem seed：`20260902`；采用交错/反平衡运行顺序降低单调主机负载偏差。
- 中等丢包 A→B：100 Mbps、42±6 ms、2.5% loss / 40% correlation、queue 1800；B→A：500 Mbps、42±4 ms、0.5% / 20%、queue 3500。
- 严重丢包 A→B：50 Mbps、42±8 ms、12% loss / 70% correlation、queue 2500；B→A：500 Mbps、42±4 ms、0.5% / 20%、queue 5000。
- 干净控制：双向 300 Mbps、2±1 ms、0.2% / 25%、queue 1000。
- BBR 三变体都请求 `lossy-radio`、FEC off、train 32 KiB、quantum 2、idle cover。

生产安全守卫在残余丢包升高时会覆盖“强制 FEC off”请求；所以有损场景中动态 parity 是控制回路的中介变量，而不是被完全固定的因素。这不影响三个变体初始策略一致，但意味着 gross-wire 补偿与 FEC 的完全正交实验仍需再做一次。

## 数据与复现

- 单次结果：`results.csv`
- 聚合统计：`aggregate.csv`
- 变体差值：`deltas.csv`
- 完整机器可读结果：`summary.json`
- 聚合脚本：`analyze.py`
- 原始数据：`/home/bubu/sdwan/target/ablation-erasure-20260902/runs/`
- 变体补丁：`/home/bubu/sdwan/target/ablation-erasure-20260902/bin/classify-only/patch.diff`、`/home/bubu/sdwan/target/ablation-erasure-20260902/bin/conventional-loss/patch.diff`
- 实际运行脚本：`/home/bubu/sdwan/target/ablation-erasure-20260902/run.sh`、`/home/bubu/sdwan/target/ablation-erasure-20260902/run-more.sh`

重新生成表格：

```bash
cd /home/bubu/sdwan
python3 /home/bubu/sdwan/artifacts/ablations/erasure-20260902/analyze.py
```
