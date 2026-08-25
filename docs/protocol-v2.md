# Ironet Protocol V2

V2 是 Ironet 唯一的数据面协议。外层使用标准 QUIC v1 与 `h3` ALPN；可见 SNI 从网络级 cover pool 稳定选择，真实 EndpointId、网络成员资格和能力边界只在完成 TLS 后的 `ISV2` SessionHello 中认证。实现没有 V1 decoder、版本降级或 fallback。

## 数据面

1. TUN 输入先按 Flow 分类为 latency 或 Bulk。
2. 同一批 IP/GSO 记录组成 PacketTrain；Record 保留包边界和 GSO 元数据。
3. PacketTrain 被切成独立 Cell。Cell 携带 route epoch/label、train/stripe 信息和覆盖 hop limit。
4. latency Cell 可抢占 Bulk admission；Bulk 由有界 DRR 公平调度。
5. QUIC DATAGRAM 承载数据、parity 与 cover Cell；可靠双向 stream 承载 Presence、反馈、Repair 与 OAM。

## 可靠性

- FEC geometry、Repair cache 和接收预算由路径丢包、RTT、吞吐、恢复率、parity 浪费及内存压力自动调节。
- 低损路径允许关闭 FEC；突发丢包先启用快速保护，反馈稳定后自动降低冗余。
- Repair request 每个 Stripe 至多发送一次；响应是发送端缓存的最终快照。
- 所有 decoder、reassembly、Repair 与 Presence 集合都有协商上限和本地硬预算。

## 路由与中转

- 签名 Presence v2 分离传播 overlay 节点 `/32`/`/128` 地址、声明子网前缀、邻接成本和 transit 能力；租约过期会同时撤销地址与前缀。
- 每个 generation 编译成不可变 route/label snapshot；热路径只读取快照。
- 每个目的按不同可用首跳最多编译 4 条无环完整路径；短流优先低 RTT，持续流在租约边界按流压力、队列和方向有效容量重新选择；候选须产生超过 5% 的 ETA 收益并连续胜出两个窗口，避免测量噪声触发振荡。
- 最终目的按 route epoch/label 返回端到端交付速率，源端以首跳 BBR 容量冷启动，并用完整路径交付样本约束后续 ETA。
- 中转节点只修改覆盖 hop limit 和 V2 label，不解码或重组完整 IP PacketTrain。
- 声明子网支持纯路由以及默认开启的 IPv4 MASQUERADE/IPv6 NAT66。

## OAM 与 Trace

- source 将内层探测包的 TTL/Hop-Limit 写入 Cell overlay hop budget；每个 transit 只在固定 routing shim 中原位递减。
- budget 到期时，transit 生成带 route epoch/label、train/cell 和 reporter EndpointId 的有界 OAM，并沿编译快照中的反向 label 通过可靠 QUIC stream 返回。
- source 使用 `(route_epoch, route_label, train_id)` 将 OAM 与本地 trace request 严格关联；`ironet trace` 随后流式显示 Presence 中该 reporter 的同地址族 overlay 地址和 EndpointId。
- transit 不解析 Record、内层 UDP payload 或 FEC，不伪造 IP/UDP 响应；未知、过期、错误地址族和无法认证的 reporter 不产生 trace hop。

## 不兼容边界

- V2 不接受 `IRN1` envelope、V1 Session/Feature 或 V1 FEC shard。
- `ironetd` 只启动 V2 runtime；配置 reload 只替换 V2 generation。
- `ironet status` 与 `ironet metrics` 直接读取运行中 V2 snapshot，不读取周期 status/metrics 文件，也不保留旧字段别名。
- QUIC v1 是标准传输版本号，不表示 Ironet Protocol V1。
