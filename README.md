# LagGuard — 云游戏上行延迟操纵与时间戳伪造识别

LagGuard 是一个可嵌入 Go 串流网关的低延迟检测、分级处置与裁判证据包组件。它不把“大延迟/突发”直接等同于作弊，而是同时分析：

1. **网关单调时钟看到的到达节奏**；
2. **客户端序列号与时间戳的内部一致性**；
3. **突发中输入操作密度和跨玩家 tick/画面相关性**；
4. **丢包、重传、FEC、RTT、切换、多流是否同时受损等真实网络旁证**；
5. **时间窗内是否重复同一模式**。

目标不是“一次异常就踢人”，而是：弱网玩家尽量无感，可疑模式先加强取证/冻结排位结果，只有硬证据且策略明确允许时才自动断开，所有结论都能生成哈希链 + Ed25519 签名证据包供裁判复核。

---

## 1. 快速体验

```bash
go test ./...
go run ./cmd/lagguard-demo
go run ./cmd/lagguard-verify -bundle examples/hold-release-review-bundle.json
open web/review.html
```

Demo 会生成：

```text
examples/hold-release-review-bundle.json
```

裁判页面 `web/review.html` 可以直接选择该 JSON，在浏览器内校验 SHA-256 哈希链和 Ed25519 签名，并展示每个加分项、网络消歧项和最终策略。浏览器不会上传证据包。

---

## 2. 网关注入位置

在每路输入流的接收 goroutine 中，从 UDP/QUIC/WebRTC/私有协议包解析出轻量元数据后调用 `Gate.Observe`。检测逻辑是固定容量状态，不做网络 IO；证据写盘走异步队列。

```go
cfg := lagguard.DefaultConfig().WithInputRate(60)

journal, _ := lagguard.NewJournal(lagguard.ReviewContext{
    SessionID:       session.ID,
    MatchID:         match.ID,
    PlayerPseudonym: player.Pseudonym,
    DetectorVersion: "lagguard-1.0.0",
    Config:          cfg,
    StartedAt:       time.Now(),
}, evidenceSigningKey, nil)

recorder := lagguard.NewAsyncRecorder(journal, 4096)
defer recorder.Close()

gate := &lagguard.Gate{
    Detector: lagguard.NewDetector(session.ID, cfg),
    Recorder: recorder,
    OnDecision: func(d lagguard.Decision, inc *lagguard.Incident) {
        // 这里必须是非阻塞控制面投递，不要在媒体 goroutine 里同步踢人/RPC。
        controlPlane.Enqueue(session.ID, d.Primary, inc.ID, d.ReasonCodes)
    },
    OnError: func(err error) {
        metrics.Inc("lagguard.evidence_error")
    },
}

// 每个输入包：
res := gate.Observe(lagguard.Packet{
    Seq:              pkt.Sequence,
    RecvAt:           monotonicReceiveTime, // 必须用网关本机单调时钟
    ClientStamp:      pkt.ClientTimestamp,
    Samples:          len(pkt.Samples),
    StateChanges:     inputMetrics.ChangedControls,
    ActionEvents:     inputMetrics.HighIntentEvents,
    IsRetransmission: pkt.IsRetransmission,
})

// 周期喂入 RTCP/传输遥测：
gate.Detector.ObserveNetwork(lagguard.NetworkReport{
    At: time.Now(), RTT: rtt, LossRate: loss,
    Retransmissions: nack, FECRecovered: fec,
    Access: accessNetwork, Handover: radioHandover,
})
```

对局总线还可以把以下相关性填进闭合突发的包元数据：

- 对手下游视频帧间隔；
- 权威服务器 tick 卡顿；
- rollback 次数/回滚帧数；
- 同一空档内 RTCP、音频、keepalive 是否仍有包或探测响应。

流结束时调用：

```go
gate.Flush()
bundle, _ := journal.Finalize(time.Now())
// 将 bundle 存到裁判证据系统；公钥指纹需在裁判后台固定信任。
```

---

## 3. 检测模型

### 3.1 “断网开关 / 先积攒后涌入”

典型形态：

```text
正常 60Hz 输入 → 120~500ms 上行空档 → 8~30 个包在 0~50ms 内到达
```

检测项：

| 信号 | 含义 |
|---|---|
| `ARRIVAL_GAP_THEN_PACKET_BURST` | 网关单调时钟先看到长静默，再看到异常 PPS 突发 |
| `TIME_COMPRESSION_BURST` | 客户端时间戳跨度很大，但网关到达跨度极小 |
| `CONTIGUOUS_SEQUENCE_RELEASE` | 序列号连续、无真实丢包缺口，整段被缓存后放行 |
| `HIGH_ACTION_DENSITY_IN_BURST` | 突发中控制变更/高意图操作密度高，可能形成单 tick 指令涌入 |
| `SELECTIVE_INPUT_GAP_WITH_LIVE_CHANNEL` | 同一空档内 RTCP/音频/探测仍存活，不像家庭宽带完全中断 |
| `OPPONENT_STALL_TEMPORALLY_CORRELATED` | 对手画面、服务器 tick 或 rollback 卡顿与该突发时间相关 |
| `REPEATED_GAP_RELEASE_PATTERN` | 滑动时间窗内重复出现，且常集中在交火/进球/团战时刻 |

单个信号不能证明故意操纵。例如运营商 bufferbloat 也可能造成连续包突发，因此代码使用组合分数、重复模式和网络旁证。

### 3.2 篡改时间戳伪装抖动

网关**不信任客户端时间戳用于调度**，只用它和序列号、网关接收时钟做一致性校验：

| 信号 | 含义 |
|---|---|
| `TIMESTAMP_NON_MONOTONIC_BY_SEQ` | 按序列号相邻的包出现显著时间回退 |
| `TIMESTAMP_MUTATED_ON_DUPLICATE` | 同一序列号的重传/重复包，时间戳与首次观测不同 |
| `TIMESTAMP_DUPLICATED_FOR_DISTINCT_SEQ` | 不同序列号使用完全相同时间戳 |
| `TIMESTAMP_CADENCE_COLLAPSE` | 正常采样节拍约 8/16ms；伪造者把戳改成 1~2ms 的突发到达间隔后，突发内时间戳中位数相对学习基线异常压缩 |

真实网络抖动改变的是**到达间隔**，通常不会改变按序列号排列的生成时间节拍。若伪造者同时重写一套“看起来合理”的单调时间戳，纯统计方法可能无法绝对识别；生产环境还应结合客户端可信执行环境/反作弊签名、服务端输入历史和协议认证时间。LagGuard 的硬完整性信号可作为复核线索，但不宣称不可绕过。

---

## 4. 为什么普通弱网不容易被误杀

LagGuard 会把“异常形状”和“真实网络解释”同时保留在证据中。以下信号是减分项/排除项，而不是隐藏判断：

- `REAL_NETWORK_SEQUENCE_LOSS`：空档伴随大量序列号缺口；
- `REAL_NETWORK_RECOVERY_OBSERVED`：NACK/重传/FEC 恢复；
- `RECENT_HIGH_PACKET_LOSS`：RTCP 或传输层丢包率高；
- `RTT_INFLATION_DURING_EPISODE`：RTT 相对本流基线明显膨胀；
- `ACCESS_HANDOVER`：Wi-Fi/蜂窝/基站切换；
- `ALL_UPLINK_FLOWS_IMPAIRED`：音频、控制、输入等所有上行流同时受损。

当网络旁证达到 `strong` 时，即使突发形状分数较高，默认也只做 `observe + enhanced_capture`，不会进入踢人/封禁流程。蜂窝网络还会额外减去少量不确定性分数。

测试 `TestRealLossAndHandoverIsExonerated` 明确锁定了这一行为：长空档后的突发如果伴随序列号丢失、高丢包率等强网络证据，结论不得是 `flag_for_human_review`、`hold_competitive_input` 或 `kick`。

---

## 5. 分级处置

默认策略是“宁可慢半拍，不可错踢弱网玩家”：

| 调整后分数/证据 | 默认动作 | 玩家影响 |
|---|---|---|
| `< ObserveScore(30)` | `pass` | 无 |
| `30–47` | `observe`, `enhanced_capture` | 无感知，仅增加取证 |
| `48–71` 或存在硬时间戳信号 | `flag_for_human_review` | 不踢线；后台标记 |
| `≥72` 且置信度足够、无强网络排除项 | `normalize_burst`, `flag_for_human_review`, `hold_competitive_input` | 可限制后续突发进入竞技判定、冻结排位/比赛结果，等待复核 |
| `≥90` + 硬证据 + 高置信 + `Config.AutomaticKick=true` | `kick` | 仅在操作者显式开启时自动断开 |

`AutomaticKick` 默认为 `false`。统计形状本身不满足 kick 条件；即使开启自动 kick，也要求硬完整性信号、高置信度且没有强网络旁证。

`normalize_burst` 的具体语义应由游戏服务器决定，例如：

- 对超过 tick 处理上限的积攒输入只保留最新状态；
- 高意图事件按服务器观测时间排队，不允许用旧时间戳追溯；
- 冻结该局排位分/竞赛结果，而不是直接判负；
- 对确认弱网玩家增大 jitter buffer、启用更激进 FEC。

不要在媒体 goroutine 中同步执行 RPC、写磁盘或踢人；`Gate.OnDecision` 只投递控制面队列。

---

## 6. 裁判证据包

每个事件包含：

- 会话、比赛、流和玩家假名；
- 检测器版本和完整阈值配置；
- 空档、突发、PPS、时间戳跨度、压缩比、缺失序列号；
- 所有加分信号、硬信号和网络排除信号；
- 分数、调整后分数、置信度、策略动作和原因码；
- 可选的对手画面/tick/rollback 相关性。

防篡改结构：

```text
event_n.hash = SHA256(event_{n-1}.hash + canonicalJSON(event_n with hash=""))
bundle.signature = Ed25519(signingPayload(bundle))
```

验证：

```bash
go run ./cmd/lagguard-verify -bundle examples/hold-release-review-bundle.json
```

输出：

```text
OK: hash chain and Ed25519 signature are valid
```

浏览器打开 `web/review.html` 也可以离线校验和阅卷。

> 签名证明证据完整且来自持有私钥的网关；裁判后台还必须固定/信任 `signer_fingerprint`，否则任何人都能生成“签名有效但不受信任”的包。生产私钥应放在 KMS/HSM 或独立签名 sidecar，不应打进镜像。

隐私方面，默认只保存包元数据、序列号和统计值，不保存按键内容、轴数值、聊天或画面。`PayloadHash` 可在需要时另行保存；证据包建议使用玩家假名并设置访问审计和保留期。

---

## 7. 性能

检测器每路流只保留固定容量的 interval ring、512 个时间戳槽和当前突发状态。普通包路径不做 JSON、磁盘 IO、锁或排序；中位数只在事件评分和周期性基线刷新时计算。

在 Apple M4 Max 上：

```text
BenchmarkObserveNormal60Hz-14  36,652,243  32.32 ns/op  32 B/op  1 allocs/op
```

这只是库微基准；真实网关还应计入协议解析。建议在目标机房机器上用真实 60/120/240Hz 流量和 `-benchmem` 复测，并给每路流的 `Observe` 调用增加 P99 耗时指标。异步证据队列应监控 `AsyncRecorder.Dropped()`；队列满时不能阻塞媒体路径，应告警并由独立抓包 sidecar 补证。

---

## 8. 调参与测试

- `Config.WithInputRate(hz)`：按游戏输入采样率设置空档和突发阈值。
- 家庭 Wi-Fi/蜂窝建议保留较保守的 `ReviewScore/HoldScore`，先影子运行 1–2 个赛季收集误判样本。
- 对格斗、FPS、竞速、MOBA 可分别配置“高意图事件”定义和阈值。
- 所有阈值、分数和原因码都写入证据包，避免事后无法还原策略版本。

现有测试覆盖：

```text
TestHoldThenBurstIsFlaggedForReview
TestRealLossAndHandoverIsExonerated
TestForgedStampsMatchingBurstArrivalCadence
TestNonMonotonicTimestampIsHardReviewEvidence
TestNormalJitterDoesNotOpenIncident
TestReviewBundleHashChainAndSignature
TestAsyncRecorderDoesNotBlockAndQueues
```

建议继续用真实流量回放建立标注集，至少按有线宽带、Wi-Fi、蜂窝、电梯/地铁切换、路由器 bufferbloat、真实丢包恢复、外挂延迟工具、伪造时间戳分类评估精确率和召回率。

---

## 9. 生产落地清单

1. 接收时间必须使用网关 monotonic clock，不能用墙钟或客户端时间。
2. 输入包序列号必须唯一、连续可比较；若协议合并多个 sample，需要解析 sample 序号。
3. RTCP/NACK/FEC/ECN/漫游事件要按 session 接入。
4. 匹配总线补充对手帧间隔、tick stall、rollback 相关性。
5. 证据签名私钥接 KMS/HSM，裁判后台 pin 指纹。
6. 自动 kick 先保持关闭；经过影子模式和人工复核准确率验证后，再对极少数硬信号灰度开启。
7. 对弱网玩家提供网络提示、自动降码率/FEC/jitter buffer，而不是处罚。
8. 证据访问需审计、最小权限、假名化和保留期。

LagGuard 输出的是**可解释风险与证据**，不是道德判断。裁判应能看到对玩家有利的网络旁证，并结合对局录像和服务端记录做出最终裁决。
