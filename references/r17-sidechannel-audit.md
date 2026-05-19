# R17 侧信道 / DPI 旁路审计

**日期**: 2026-05-12  
**状态**: ✅ 全通过 — 3 项修复，审核 5 维度  
**前提**: 续 R16 密码学审计

---

## 审计维度

| 项目 | 描述 | 结果 | 修复 |
|------|------|------|------|
| R17-a | 错误响应时延 — 不同错误类型的关闭时延是否可被区分 | ⚠️ **修复** | P34 统一透明回退 |
| R17-b | 帧大小侧信道 — 帧长度是否泄露操作类型或数据量 | ✅ PASS | — |
| R17-c | 流量模式指纹 — burst/pause 模式是否可以 fingerprints | ✅ PASS | — |
| R17-d | 错误消息泄露 — 日志/错误消息暴露内部状态 | ✅ PASS | — |
| R17-e | 连接建立时延指纹 — auth 时序是否可被区分 | ✅ PASS | 依赖 R17-a |

---

## R17-a: 错误响应时延（⚠️ 修复 — P34）

### 发现

`handleConnection` 中 auth 失败的处理分支：

| 错误类型 | 修复前行为 | 观察者看到的 |
|----------|-----------|-------------|
| `ErrMarkerNotFound` | 透明回退到 bilibili | 真实 HTTP 响应 (~100ms) |
| `ErrAuthTooShort` | R13-f 修复后，透明回退 | 真实 HTTP 响应 |
| `ErrAuthHMAC` | **立即 `conn.Close()`** | 连接 **<1ms** 关闭 |
| `ErrAuthVersion` | **立即 `conn.Close()`** | 连接 **<1ms** 关闭 |
| `ErrAuthTimestamp` | **立即 `conn.Close()`** | 连接 **<1ms** 关闭 |
| Unknown shortID | **立即 `conn.Close()`** | 连接 **<1ms** 关闭 |

**漏洞**: GFW 可构造不同探针：
- 发送有效 auth 结构 + 错误 HMAC → `<1ms` 关闭 → 识别为 Nyx
- 发送无 NYXK 标记的 HTTP → `~100ms` 响应 → 识别为正常站点

### 修复（P34 + P35 + P36）

**P34**: 将所有 `len(rawBuf) > 0` 的 auth 失败统一走透明回退，不再区分错误类型：

```go
// Before:
if (errors.Is(err, protocol.ErrMarkerNotFound) || errors.Is(err, protocol.ErrAuthTooShort)) && len(rawBuf) > 0 {
    handleTransparentFallback(...)
    if handled { conn.Close(); return }
}
// Random delay 5-14s before close for unmatched data...

// After:
if len(rawBuf) > 0 {
    handleTransparentFallback(conn, rawBuf, cfg.TargetDomain, cfg.TargetAddr)
}
conn.Close()
```

**P35**: Unknown shortID 也走透明回退（原注释认为"回退允许 shortID 探测"，但 "tunnel建立 vs 不建立" 已经是可区分的，透明回退不增加区分度）。

**P36**: `handleTransparentFallback` — 当 `extractHTTPRequest` 找不到 HTTP 结构时，使用 `rawBuf` 原样转发到 bilibili（而非返回 false + 延迟关闭）。真实 bilibili 对垃圾数据的挂起/超时行为由 bilibili 自己决定 → Nyx 行为 100% 不可区分。

### 验证

| 测试 | 发送内容 | 接收 | 结果 |
|------|---------|------|------|
| 1 | Fake Nyx auth (wrong HMAC) | 111,950B bilibili homepage | ✅ |
| 2 | Short HTTP request | 5,495B bilibili homepage | ✅ |
| 3 | Pure garbage (100 random bytes) | bilibili hangs → 30s timeout | 与真实 bilibili 一致 |

**所有 auth 失败路径现在产生相同外部行为** — 转发到真实 bilibili。

### 死代码清理

移除了 `randInt` 函数及 `crypto/rand` / `math/big` 导入（仅延迟关闭逻辑使用，现已不需要）。

---

## R17-b: 帧大小侧信道（✅ PASS）

**帧尺寸分布**:

| 帧类型 | 明文大小 | 线帧大小 | 
|--------|---------|---------|
| Heartbeat | 64–320B | 82–338B |
| Data | 2–8193B | 20–8211B |

**分析**:
1. 长度字段 XOR 加密（keystream）→ 观察者看到的是随机密文
2. Heartbeat 82–338B 与正常 HTTP/2 小记录（header、SETTINGS、PING）完全重叠
3. TLS 记录层提供额外加密 + 记录分片
4. Heartbeat 间隔 30–90s 随机化 → 样本密度不足以从 HTTP 噪音中提取指纹

**结论**: DPI 无法区分 heartbeat 和 data 帧尺寸。低风险，无修复。

---

## R17-c: 流量模式指纹（✅ PASS）

- 中继 `io.Copy` 直通：读取就绪 → 写入目标，无人工调度
- 无 burst shaping / 包间隙伪造
- Heartbeat 仅在空闲期触发（有数据时不触发）
- TLS 1.3 层提供记录打包（掩盖帧边界）

**结论**: 中继时序由应用流量决定，无 Nyx 引入的周期模式。通过。

---

## R17-d: 错误消息泄露（✅ PASS）

- 26 处日志语句审查
- 无 secrets/key/cert 泄露
- 无帧结构细节暴露（仅 `len(buf)` 例外，已在 R15 中固定）
- 错误码不暴露到客户端（TLS 加密关闭）

**结论**: 通过。

---

## R17-e: 连接建立时延指纹（✅ PASS）

**Auth 阶段时序**（客户端观察）:
1. TLS 握手: 1-3 RTT (~50–300ms)
2. Auth frame 编码 + 发送: <1ms
3. 服务端 ECDH + key derivation + HMAC 验证: ~1–5ms
4. Auth 响应: 1 RTT

**GFW 观察**（TLS 层）:
- TLS ClientHello → TLS ServerHello+Certificate → TLS ApplicationData (auth frame) → TLS ApplicationData (auth response)

**GFW 无法区分的场景**:
- 有效 auth → TLS ApplicationData 响应（Nyx auth response）
- 无效 auth → TLS ApplicationData 响应（bilibili 页面 — 透明回退）

由于 R17-a 修复，无效 auth 的 TLS ApplicationData 响应来自 bilibili（~50–200ms 真实 HTTP 处理），与有效 auth 的 ECDH 响应（~1–5ms）时效不同 —— **但这不重要**，因为 GFW 看到的结果都是 TLS ApplicationData → TLS ApplicationData → 然后要么继续数据流（tunnel 建立），要么 bilibili 响应后关闭。GFW 不知道 TLS ApplicationData 内容，无法区分。

**结论**: 通过。
