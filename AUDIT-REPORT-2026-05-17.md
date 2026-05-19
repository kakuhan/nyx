# Nyx 协议审计报告

**日期：** 2026-05-17  
**范围：** `~/projects/nyx` 完整协议栈  
**方法：** 逐文件审查 + 已知翻墙协议对比 + 修复验证

---

## 一、Nyx 协议架构总览

Nyx 是一个**类 HTTPS 隧道协议**，设计目标是让加密流量与目标域名的正常 HTTPS 流量不可区分。

```
客户端                                   服务端
──────────────────────────────────────────────
                                        
1. TCP Connect ──────────────────────────→
                                        
2. TLS 1.3 (uTLS 指纹随机化)              
   SNI = target_domain                   
   ClientHello(Chrome/Firefox/Safari)     
   ← TLS 1.3 ServerHello(target cert)    
                                        
3. Application Data (TLS 加密)            
   发送 Nyx Auth Frame：                   
   [HTTP_preamble|pad|NYXK|auth_body]    
                                        
4. 认证成功 → yamux 多路复用               
   认证失败 → transparent fallback         
   （转发 HTTP 请求到真实目标，返回         ←── GFW 探测无差异
    真实响应）                             
```

**协议栈层次：**
```
应用层： SOCKS5 / HTTP CONNECT
复用层： yamux（每连接一个 TLS 隧道）
认证层： X25519 ECDH + HKDF + HMAC + Replay 防护
伪装层： HTTP preamble + Reality 证书
传输层： TLS 1.3 + uTLS 指纹随机化
```

## 二、从现有协议借鉴的设计

| 借鉴点 | 来源协议 | Nyx 实现 | 评价 |
|--------|----------|----------|------|
| 浏览器 TLS 指纹伪装 | uTLS (Trojan-Go) | `internal/tls/fingerprint.go` 14 个指纹随机选择 | ✅ 优于单一 Go TLS 指纹 |
| 目标域名证书伪装 | Reality (XTLS) | `internal/reality/cert.go` 动态获取目标域证书 | ✅ TLS 层无法判定非目标站 |
| 认证帧埋在 HTTP 前缀中 | VMess AEAD | Auth Frame = HTTP_preamble + pad + NYXK + body | ✅ DPI 看像正常 HTTP 请求 |
| 双向会话密钥（HKDF） | Shadowsocks AEAD-2022 | X25519 ECDH → HKDF 派生 client_send / server_send | ✅ 正确实现 |
| 连接多路复用 | Hysteria2 | yamux，一个 TLS 隧道承载多个 SOCKS5 连接 | ✅ 减少握手次数 |
| 认证失败透明回退 | VLESS fallback | `handleTransparentFallback` 转发 HTTP 到目标 | ✅ 探测流量得到真实响应 |

## 三、本次审计发现 & 修复

### R18: TLS SNI 拒绝指纹 [已修复]

**文件:** `cmd/server/main.go:154-175`

**问题：** `tls.Config.GetConfigForClient` 在 SNI ≠ `target_domain` 时返回 error，导致 TLS 握手**终止**。GFW 探针发送 `SNI=google.com` 时收到 TLS Alert 而非 ServerHello，形成可检测指纹。

**影响：**
```
GFW 探针 → TLS ClientHello(SNI=google.com)
             ↓
旧代码：     TLS Alert (internal_error) → 连接关闭  ← 指纹！
新代码：     TLS ServerHello(bilibili 证书) → AppData → 透明回退 → 真实响应
```

**修复：** 移除 `GetConfigForClient`，让 TLS 握手始终正常完成。与 Hysteria2、Reality、真实 HTTPS 服务器行为一致。

### R19: uTLS 指纹池扩展 [已修复]

**文件:** `internal/tls/fingerprint.go:33-52`

**问题：** 只有 5 个指纹（Chrome 120、Chrome 106 Shuffle、Firefox 120、Safari 16.0、Edge 106），重复率高 → 可被聚类分析。

**修复：** 扩展到 14 个指纹，覆盖 Chrome 83-120 / Firefox 99-120 / Edge 85-106 / Safari 16.0。真实互联网中数十个浏览器版本在流通，14 个指纹让 Nyx 连接更难以聚类。

**Kyber 限制说明：** Chrome 124+ 默认启用 Kyber 后量子密钥交换，Go 的 `crypto/tls` 服务端不支持 Kyber → `tls: protocol version not supported`。等 Go 支持 Kyber 后可升级到最新 Chrome 指纹（届时由 uTLS `HelloChrome_Auto` 自动选取最新可用指纹）。

### 验证通过（无需修改）

| 检查项 | 结论 | 证据 |
|--------|------|------|
| HMAC 密钥派生 | ✅ 已用 HKDF | `auth.go:283` `deriveHKDF(f.ShortID, SaltAuthHMAC, 32)` |
| 双向会话密钥 | ✅ HKDF-SHA256 | `auth.go:518-544` `DeriveBidirectionalKeys` |
| 透明回退超时 | ✅ 已有 deadline | `main.go:618` `remote.SetDeadline(30s)` + `main.go:624` `conn.SetDeadline(30s)` |
| Replay 防护 | ✅ timestamp + window | `auth.go` 90 秒窗口 |
| yamux 流隔离 | ✅ 正常 | `internal/mux/mux.go` 每 Stream 独立 SOCKS5 |
| 速率限制 | ✅ 存在 | `main.go` MaxConnsPerWindow + RateLimitWindow |

## 四、与 GFW 检测技术的对抗矩阵

| GFW 检测手段 | Nyx 对策 | 状态 |
|-------------|----------|------|
| TLS ClientHello 指纹 | uTLS，14 个浏览器指纹随机选择 | ✅ |
| SNI 探测（非目标域名 SNI） | 不拒绝，正常完成 TLS 握手 + 透明回退 | ✅ (R18) |
| 深度包检测 (DPI) | HTTP preamble 伪装 + TLS 1.3 加密 | ✅ |
| 主动探测（伪造连接） | 透明回退返回真实 HTTP 响应 | ✅ |
| 流量分析（时间/尺寸模式） | yamux 多路复用混合多流 | ⚠️ 可改进 |
| 证书链分析 | 单域自签证书（非 CA 签发） | ⚠️ 可改进 |
| 连接持续时间分析 | yamux 长连接 | ⚠️ 可加心跳抖动 |

## 五、剩余风险 & 后续建议

### 短期
1. **uTLS 版本升级：** 当前 uTLS v1.6.7 缺乏最新浏览器指纹。升级 to latest + Go 支持 Kyber 后可大幅扩展指纹空间。
2. **Reality 证书：** 单域自签证书 vs 真实 Let's Encrypt 证书链不同。未来可考虑集成 `cert-manager` 或定期同步目标证书。

### 中期
3. **流量整形：** yamux 多路复用可添加 `Padding` 帧模拟 HTTP/2 流量模式（参考 Hysteria2 的 `masq_speed` 和 `defense_slow_start`）。
4. **心跳抖动：** 当前心跳固定间隔，可添加随机抖动。

### 长期
5. **QUIC 迁移：** GFW 对 QUIC 的检测能力远弱于 TCP+TLS。Nyx over QUIC → 接近 Hysteria2 的终极形态。

## 六、修复证据索引

```
cmd/server/main.go:154-175    R18: 移除 SNI 拒绝，TLS 握手始终完成
internal/tls/fingerprint.go:33-52  R19: uTLS 指纹池 5→14
cmd/apk/main.go                    R17: APK 配置搜索路径优化
build-apk/assets/nyx-client.json   生产服务器地址
internal/protocol/auth.go:538-544  HKDF key derivation (验证通过)
cmd/server/main.go:618,624         io.Copy deadlines (验证通过)
```
