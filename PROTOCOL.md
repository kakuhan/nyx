# Nyx Protocol v2.4 — 抗审查隧道协议规格

## 设计哲学

Nyx 融合了 REALITY（TLS 伪装）、ShadowTLS（握手劫持）、Hysteria（高性能传输）的核心优势，专门针对 GFW 的 SET-bit 检测、主动探测、TLS 指纹分析、SNI 白名单、死空检测五重防线设计。

**v2.2 核心创新**：
1. **uTLS 指纹随机化** — 每次连接随机选择 Chrome/Firefox/Safari 等 7 种浏览器的 JA3 指纹
2. **全透明 Fallback** — 认证失败时提取 HTTP Preamble 转发到真实目标网站，GFW 主动探测无迹可寻
3. **空闲心跳帧** — 随机间隔(30-90s)发送加密心跳，消灭死空检测
4. **协议类型标记** — AEAD 载荷首字节区分数据帧/心跳帧，心跳对上层透明
5. **Sentinel Error 体系** — `errors.Is` 替换脆弱字符串匹配

## 协议层次

```
┌─────────────────────────────────────────┐
│  第1层: 传输伪装                          │
│  TLS 1.3 + 随机化 JA3 指纹 + 真实证书     │
├─────────────────────────────────────────┤
│  第2层: 认证帧                            │
│  ApplicationData[0]: 合法HTTP请求 + auth  │
├─────────────────────────────────────────┤
│  第3层: 加密隧道 (v2.2 帧格式)            │
│  XChaCha20-Poly1305 AEAD + 帧类型标记     │
│  双向非耦合 nonce + 可变填充               │
└─────────────────────────────────────────┘
```

## 握手流程

```
Client                                    Server (nyx-proxy)
  |                                         |
  |  1. TLS 1.3 ClientHello ------------->  |
  |     SNI = bilibili.com                  |  2. TLS 1.3 ServerHello
  |     JA3 = random browser (uTLS)         |     Certificate = bilibili.com
  |     (Chrome/Firefox/Safari/iOS/Safari)  |     (pre-fetched or self-signed)
  |  <----------- TLS Finished ------------ |
  |                                         |
  |  3. NyxAuthFrame -------------------->  |  4. 验证 shortId + HMAC
  |     [Printable HTTP Preamble]           |     派生 session keys
  |     [NYXK marker]                       |
  |     [shortId + ECDHpk + timestamp +     |     认证成功 ↓
  |      HMAC]                              |     认证失败 → transparent fallback
  |                                         |
  |  <--- Encrypted AuthResponse --------   |  5. 认证响应
  |     nonce(24) + server_pub(32) +        |
  |     AEAD{version(1)||status(1)}         |
  |                                         |
  |  6. 双向加密隧道 ======================  |  7. 双向加密隧道
  |     NyxDataFrame <-> NyxDataFrame       |     + heartbeat 心跳帧 (30-90s)
  |     [type:0x00|data]                    |     [type:0x01|random_pad]
```

## 认证帧格式 (ApplicationData[0])

```
NyxAuthFrame (客户端 → 服务器):
┌──────────┬─────────────────────┬────────┬──────────────────────────────┐
│ Pad      │ HTTP Preamble       │ Marker │ Auth Body                     │
│ 16-64B   │ 200-512B (~80%      │ 4B     │ version(1) + shortId(8) +     │
│ (random) │  可打印ASCII)       │ "NYXK" │ timestamp(8) + clientPub(32)  │
│          │                     │        │ + HMAC-SHA256(32)             │
└──────────┴─────────────────────┴────────┴──────────────────────────────┘

HTTP Preamble: "GET / HTTP/1.1\r\nHost: bilibili.com\r\nUser-Agent: ...\r\nAccept: */*\r\n\r\n" + 空格填充
              → 确保第一个数据包 ≥60B 可打印 ASCII，通过 GFW SET-bit 豁免
```

**AuthResponse 格式 (v2.2 修复版，74 bytes)**:

```
nonce(24) || server_pubkey_cleartext(32) || XChaCha20-Poly1305{version(1)||status(1)}
```

> **v2 关键修复**：server 公钥放在 AEAD 外部明文传输，客户端可用 `ParseServerPubkey()` 直接提取，
> 再用它派生 `serverSendKey`，最后用 `DecodeAuthResponse(serverSendKey, nonce, ciphertext)` 解密验证。
> 避免 v1 中"先有鸡还是先有蛋"的非对称解密死锁。

**Session Key 派生**:
```
sharedSecret = X25519(clientPriv, serverPub)
serverSendKey = HKDF-SHA256(sharedSecret, salt="nyx-v2-server-send", info="")
clientSendKey = HKDF-SHA256(sharedSecret, salt="nyx-v2-client-send", info="")
```

## 数据帧格式 (后续 ApplicationData) — v2.2

```
NyxDataFrame v2.2:
┌──────────┬────────────────────────────────────────────────┐
│ enc_len  │ AEAD ciphertext                                 │
│ 2B       │ XChaCha20-Poly1305( nonce, plaintext, nil )    │
│ (XOR'd)  │ plaintext = [type(1)] [payload] [random_pad]   │
└──────────┴────────────────────────────────────────────────┘

enc_len:   actual_ciphertext_len XOR keystream[0:2]
type:      0x00 = 数据帧 (data frame)
           0x01 = 心跳帧 (heartbeat, emitted by StartHeartbeat)

Nonce 设计 (XChaCha20 24-byte):
  数据帧 nonce:     counter(8 LE) || 0x00...0x00  → AEAD encrypt/decrypt
  长度字段 nonce:   counter(8 LE) || 0x00...0xFF  → len field XOR keystream
  字节23不同(0x00 vs 0xFF)，零 nonce 复用风险

Payload:  最小 64 字节，最大 8192 字节 (不含type byte)
Padding:  0-512 字节随机填充，使总帧长度符合真实流量分布
Tag:      Poly1305 认证标签 (16 字节)，内嵌于 AEAD ciphertext
```

**心跳帧**：
- 帧类型标记 `0x01`，载荷为 64 字节随机填充
- 线缆上与数据帧不可区分（同为 82 字节左右）
- `NyxConn.Read()` 自动跳过心跳帧，对上层 SOCKS5 透明
- 间隔随机化（30-90 秒），防止定时模式指纹

## Fallback 机制 — v2.2 透明代理

认证失败时（非 Nyx 流量），服务器执行真实透明代理：

1. 从 `rawBuf` 中提取 HTTP Preamble（`GET ...\r\n\r\n`）
2. 新建 TLS 连接至 `target_addr`（如 bilibili.com:443）
3. 将提取的 HTTP 请求原样转发
4. 将真实网站的 HTTP 响应原样返回客户端
5. GFW 主动探测看到的是完整 HTTPS 请求/响应周期，无法与真实浏览区分

## 抗检测分析

| 检测方式        | Nyx v2.2 防御                                       |
|----------------|-----------------------------------------------------|
| SET-bit 豁免   | HTTP Preamble 提供 200-512B 可打印 ASCII            |
| TLS JA3 指纹   | uTLS 随机化 7 种浏览器指纹 (Chrome/Firefox/Safari) |
| TLS JA4 指纹   | 随机化 QUIC/HTTP2 ALPN 组合                         |
| SNI 白名单     | SNI = bilibili.com (或其他白名单真实域名)            |
| 主动探测       | 透明 Fallback → 真实网站完整响应，与正常 HTTPS 一致 |
| 死空检测       | 加密心跳帧(30-90s 随机间隔)，线缆上不可区分         |
| 流量模式       | 随机填充(0-512B) + 可变分块 + 心跳虚假流量          |
| 重放攻击       | HMAC-SHA256 绑定 timestamp + counter 防重放         |
| 前向安全性     | X25519 临时 ECDH 密钥，每次连接新 session           |
| 时序指纹       | 心跳间隔随机化，填充长度随机化                       |

## 配置参数

```json
// Server config (nyx-server.json)
{
  "listen": ":443",
  "short_ids": ["a1b2c3d4e5f6a7b8"],
  "target_domain": "bilibili.com",
  "target_addr": "bilibili.com:443",
  "cert_path": "/etc/nyx/bilibili.pem",
  "key_path": "/etc/nyx/bilibili.key"
}

// Client config (nyx-client.json)
{
  "server": "your-server.com:443",
  "short_id": "a1b2c3d4e5f6a7b8",
  "target_domain": "bilibili.com",
  "socks5_listen": "127.0.0.1:1080"
}
```

## Sentinel Errors (v2.2)

认证层暴露以下 sentinel errors 替代字符串匹配：

| Error                | 含义                         |
|---------------------|------------------------------|
| `ErrMarkerNotFound` | 非 Nyx 流量 → 触发 fallback  |
| `ErrAuthTooShort`   | 帧长度不足                   |
| `ErrAuthVersion`    | 协议版本不匹配               |
| `ErrAuthHMAC`       | HMAC 验证失败 (密钥错误)     |
| `ErrTimeSkew`       | 时间戳偏差超出容忍范围        |

## 版本历史

| 版本   | 日期       | 变更                                       |
|--------|-----------|-------------------------------------------|
| v1.0   | 2026-04   | 初始设计：HTTP Preamble + NYXK marker + HMAC |
| v2.0   | 2026-05   | AuthResponse 修复 (pubkey 移至明文), 双通道 nonce |
| v2.1   | 2026-05   | 预创建 keystream AEAD，ReadFrame 合并读取      |
| v2.2   | 2026-05   | uTLS 指纹随机化, 透明 fallback, 心跳帧, sentinel errors |
