# Nyx 协议完整说明文档

> **版本:** v2.4  
> **日期:** 2026-05-17  
> **协议作者:** KaKu Han  
> **代码仓库:** `~/projects/nyx` | `~/projects/flclash-nyx`

---

## 目录

1. [设计理念](#1-设计理念)
2. [协议架构](#2-协议架构)
3. [协议细节](#3-协议细节)
4. [从现有协议的借鉴与创新](#4-从现有协议的借鉴与创新)
5. [GFW 对抗策略](#5-gfw-对抗策略)
6. [优缺点分析](#6-优缺点分析)
7. [Linux 服务端部署](#7-linux-服务端部署)
8. [客户端部署](#8-客户端部署)
9. [常用命令速查](#9-常用命令速查)

---

## 1. 设计理念

Nyx 的核心设计哲学是**"像正常 HTTPS 流量一样通信"**，而非"把自己藏起来"。

大多数翻墙协议追求将流量伪装成其他协议——Trojan 伪装 HTTPS、VMess 伪装 WebSocket、Shadowsocks 干脆不伪装。但 GFW 的深度包检测（DPI）和主动探测能力已高度成熟——**单纯的协议伪装不再安全**。

Nyx 的差异化思路：

| 传统协议 | Nyx |
|---------|-----|
| 伪装成"看起来像 HTTPS" | 用真正的 TLS 1.3，与目标域名的 HTTPS 流量**完全相同** |
| 证书随便自签 | 从目标域名实时获取真实证书 |
| 连接指纹可被聚类 | 14 个浏览器 TLS 指纹随机选择 |
| 探测时返回错误/断开 | 探测时返回真实网页（透明回退） |
| 每个连接独立 | yamux 多路复用，减少握手痕迹 |

---

## 2. 协议架构

### 2.1 协议栈

```
┌─────────────────────────────────────────────┐
│  应用层: SOCKS5 / HTTP CONNECT              │
├─────────────────────────────────────────────┤
│  复用层: yamux Stream Multiplexing         │
│         (一个 TLS 隧道承载多个 SOCKS5 连接)  │
├─────────────────────────────────────────────┤
│  认证层: X25519 ECDH + HKDF-SHA256 + HMAC  │
│         + Replay 防护 (90s 窗口)            │
├─────────────────────────────────────────────┤
│  伪装层: HTTP Preamble + 真实目标证书       │
│         + 透明回退 (针对 GFW 主动探测)       │
├─────────────────────────────────────────────┤
│  传输层: TLS 1.3 + uTLS 指纹随机化         │
│         (14 个浏览器指纹: Chrome/Firefox/...)│
├─────────────────────────────────────────────┤
│  网络层: TCP                                │
└─────────────────────────────────────────────┘
```

### 2.2 整体流程

```
客户端                                        服务端
───────────────────────────────────────────────────

① TCP Connect ────────────────────────────→
                                          → 接收连接

② TLS 1.3 握手 (uTLS 随机指纹)
   SNI = 目标域名 (如 www.bilibili.com)
   ← TLS ServerHello + 真实目标域名证书

③ Application Data (TLS 加密内):
   发送 Nyx Auth Frame:
   ┌──────────────────────────────────────┐
   │ GET / HTTP/1.1\r\n                  │ ← HTTP Preamble (200-768B)
   │ Host: target.com\r\n                │   DPI 看到正常 HTTP 请求
   │ User-Agent: Chrome/120...\r\n\r\n   │
   ├──────────────────────────────────────┤
   │ [随机填充: 0-64B]                    │ ← 打乱帧长度分布
   ├──────────────────────────────────────┤
   │ "NYXK"  (4B 明文标记)               │ ← 帧内搜索定位点
   ├──────────────────────────────────────┤
   │ [version][shortID][preambleLen]     │
   │ [timestamp][clientX25519PubKey]     │ ← Auth Body (81B)
   │ [HMAC-SHA256(31B)]                  │
   └──────────────────────────────────────┘

④ 认证判断:
   成功 → 发送 auth response
   失败 → 透明回退 (转发到目标域名)

⑤ Auth Response:
   → [nonce:24B][serverX25519PubKey:32B]
     [encrypted{version,status}:18B]

⑥ 双向密钥协商 (X25519 ECDH):
   sharedSecret = ECDH(clientPriv, serverPub) = ECDH(serverPriv, clientPub)
   masterKey    = HKDF(sharedSecret, "nyx-v2-session", 32)
   clientSend   = HKDF(masterKey, "nyx-v2-client-send", 32)
   serverSend   = HKDF(masterKey, "nyx-v2-server-send", 32)

   加密套件: XChaCha20-Poly1305 AEAD (Shadowsocks AEAD-2022 风格)

⑦ 数据隧道:
   [encrypted_length:2B][AEAD_ciphertext:variable]
   yamux 流多路复用 → 多个 SOCKS5 连接共享一个 TLS 隧道
```

### 2.3 透明回退机制

当认证失败时（GFW 探针扫描、非法客户端），服务端**不会拒绝连接或返回错误**——而是：

```
GFW 探针 ——→ TLS 握手完成 ——→ 发送任意数据
                                   ↓
                            未找到 "NYXK" 标记
                                   ↓
                            把数据当作 HTTP 请求
                            转发到真实目标域名 (bilibili.com)
                                   ↓
                            返回 bilibili.com 的真实首页
```

GFW 看到的：一个正常的 TLS 连接 → 一个正常的 HTTP 请求 → 一个正常的 HTTP 响应。**完全可区分度为零。**

这借鉴了 VLESS fallback 机制，但更彻底——不是转发到另一个端口，而是在**同一连接内**完成整个透明回退。

### 2.4 重放攻击防护

```
认证帧包含 [timestamp:8B] —— Unix 时间戳，秒精度

服务端验证:
  now - 90s ≤ timestamp ≤ now + 90s  → 时间窗口内
  timestamp NOT in replay_seen_map    → 未重放

每连接独立时间戳 → 即使截获也是一次性的
```

---

## 3. 协议细节

### 3.1 认证帧 (Auth Frame) 字段规格

| 字段 | 偏移 | 大小 | 说明 |
|------|------|------|------|
| HTTP Preamble | 0 | 200-768B | 正常 HTTP 请求头，内容不固定 |
| Random Pad | 可变 | 0-64B | 随机填充，让帧长度随机化 |
| Marker "NYXK" | 可变 | 4B | 版本标记，HTTP 头中不可能出现 |
| Version | +0 | 1B | `0x02` (协议版本号) |
| Short ID  | +1 | 8B | 服务器短期标识符 |
| Preamble Len | +9 | 2B | HTTP Preamble 实际长度 (big-endian) |
| Timestamp | +11 | 8B | Unix 时间戳 (big-endian) |
| Client PubKey | +19 | 32B | 客户端 X25519 公钥 |
| HMAC | +51 | 32B | HMAC-SHA256(body, HKDF(shortID, "nyx-auth-hmac")) |

**总长度:** Preamble(200-768B) + Pad(0-64B) + Marker(4B) + Body(83B) = **287-919B**

### 3.2 双向会话密钥

```
X25519 ECDH 共享密钥
    ↓
HKDF-SHA256(sharedSecret, "nyx-v2-session", 32) → masterKey
    ↓
    ├── HKDF-SHA256(masterKey, "nyx-v2-client-send", 32) → clientSendKey
    └── HKDF-SHA256(masterKey, "nyx-v2-server-send", 32) → serverSendKey

客户端用 clientSendKey 加密 → 服务端用 clientSendKey 解密
服务端用 serverSendKey 加密 → 客户端用 serverSendKey 解密

加密: XChaCha20-Poly1305 AEAD
Nonce 构造: base_nonce(12B) XOR counter(8B, big-endian)
```

### 3.3 数据帧格式

每个数据帧 = 长度前缀 + AEAD 密文:

```
[encrypted_length:2B][ciphertext:encrypted_length]
                          ↓ AEAD 解密后:
                    [payload:encrypted_length - overhead]
```

overhead = 16B (Poly1305 tag)

### 3.4 yamux 多路复用

一个 TLS 连接内通过 yamux 协议创建多个 Stream:

```
TLS 隧道
  ├── Stream 1 → SOCKS5 连接 1 → 目标 IP1
  ├── Stream 2 → SOCKS5 连接 2 → 目标 IP2
  └── Stream N → SOCKS5 连接 N → 目标 IP N
```

每个 Stream 有独立的 sessionKey，所有数据仍然经过 XChaCha20-Poly1305 AEAD 加密。

---

## 4. 从现有协议的借鉴与创新

| 借鉴来源 | 借鉴点 | Nyx 的改进 |
|----------|--------|-----------|
| **Trojan-Go (uTLS)** | 浏览器 TLS 指纹伪装 | 扩展到 14 个指纹随机选择，覆盖 Chrome 83-120 / Firefox 99-120 / Edge 85-106 / Safari 16.0 |
| **XTLS Reality** | 目标域名证书伪装 | 实时获取目标域证书，TLS 层无法判定非目标站点 |
| **VMess AEAD** | 认证帧嵌入 HTTP 前缀 | 认证数据埋在正常 HTTP 请求体内，加上随机填充打乱长度分布 |
| **Shadowsocks AEAD-2022** | 双向 HKDF 密钥派生 | 完全匹配 SS 的 clientSend/serverSend 设计 |
| **Hysteria2** | 连接多路复用 | yamux 减少握手次数，降低指纹暴露频率 |
| **VLESS fallback** | 透明回退 | 同一连接内的实时回退，而非端口转发 |

### Nyx 的独特创新

1. **"NYXK" 标记搜索机制**：认证帧没有固定起始偏移，服务端在 HTTP 数据流中搜索 `NYXK` 标记来定位帧体。这打破了数据包长度维度的指纹。

2. **随机填充长度**：0-64B 的随机填充让每次握手的帧长都不同，对抗流量分析。

3. **SNI 宽容处理**（R18 修复）：不拒绝错误的 SNI，而是正常完成握手后再判断，避免了 "SNI 不匹配就断开" 这一常见指纹。

---

## 5. GFW 对抗策略

| GFW 检测手段 | Nyx 对策 | 效果 |
|-------------|----------|------|
| **TLS ClientHello 指纹** | uTLS 14 个浏览器指纹随机选择 | ✅ 强 |
| **SNI 探测**（非预期 SNI） | 不拒绝，正常完成握手 + 透明回退 | ✅ 强 |
| **深度包检测 (DPI)** | HTTP preamble + TLS 1.3 全加密 | ✅ 强 |
| **主动探测**（伪造连接） | 透明回退返回目标域真实 HTTP 响应 | ✅ 强 |
| **证书链分析** | 使用真实目标域证书 | ✅ 强 |
| **流量模式分析** | yamux 多路复用混合多流 | ⚠️ 中 |
| **长连接检测** | 可以加心跳抖动 | ⚠️ 中 |

### 已知待改进项

| 问题 | 严重性 | 建议方案 |
|------|--------|----------|
| 没有流量整形 | 中 | 添加 Padding 帧模拟 HTTP/2 流量模式 |
| 心跳固定间隔 | 低 | 添加随机抖动 |
| 不抗重放重放窗 90s | 低 | GC 策略已实现，可调参 |
| 无 QUIC 支持 | 中期 | QUIC 的抗检测性远优于 TCP+TLS |

---

## 6. 优缺点分析

### 优势

1. **识别难度极高** — TLS 层完全与目标域相同（uTLS 指纹 + 真实证书），GFW 无法从 TLS 握手判定异常
2. **透明回退优雅** — 被探测时返回真实网页，而非错误响应
3. **协议极简** — 核心认证+加密不到 2000 行 Go 代码，审查维护成本低
4. **纯 Go 实现** — 单二进制部署，无运行时依赖，交叉编译支持 Linux/Windows/macOS/ARM
5. **现代密码学** — X25519 + XChaCha20-Poly1305 + HKDF-SHA256，不依赖老算法
6. **多路复用** — 减少 TLS 握手次数，降低指纹暴露频率

### 劣势

1. **单服务器节点** — 没有内置的负载均衡/多服务器支持（可在外层用 Clash 实现）
2. **没有流量整形** — 长时间 yamux 连接缺乏模拟 HTTP/2 的心跳/帧间隔
3. **不抗重放** — 90s 重放窗口在同步攻击下时间较短
4. **uTLS 版本旧** — uTLS 版本不支持最新 Chrome 指纹和 Kyber 后量子密钥
5. **无 WebSocket/gRPC** — 纯 TCP，不支持 CDN/Cloudflare 中转
6. **配置灵活性有限** — server 端参数硬编码，不支持配置文件

---

## 7. Linux 服务端部署

### 7.1 系统要求

- Linux x86_64（或任意 Go 编译目标平台）
- 防火墙开放指定端口（默认 8443）
- 无特殊硬件要求，512MB 内存足够

### 7.2 部署步骤

**第一步：上传二进制**

```bash
# 上传 nyx-server 到服务器
scp nyx-server-linux root@your-server.com:/root/nyx-server
chmod +x /root/nyx-server
```

**第二步：启动服务**

```bash
# 前台运行（调试用）
/root/nyx-server

# 后台运行（生产用）
nohup /root/nyx-server &>/root/nyx.log &

# systemd 服务（推荐）
cat > /etc/systemd/system/nyx.service << 'EOF'
[Unit]
Description=Nyx Tunnel Server v2.4
After=network.target

[Service]
Type=simple
ExecStart=/root/nyx-server
Restart=always
RestartSec=5
StandardOutput=append:/root/nyx.log
StandardError=append:/root/nyx.log

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now nyx
systemctl status nyx
```

**第三步：开放端口**

```bash
# firewalld
firewall-cmd --add-port=8443/tcp --permanent && firewall-cmd --reload

# ufw
ufw allow 8443/tcp

# iptables
iptables -A INPUT -p tcp --dport 8443 -j ACCEPT
```

**第四步：验证运行**

```bash
# 检查进程
ps aux | grep nyx-server

# 检查日志
tail -f /root/nyx.log

# 检查端口监听
ss -tlnp | grep 8443
```

### 7.3 服务端参数说明

所有参数目前为硬编码（位于 `cmd/server/main.go` 中）：

| 参数 | 值 | 说明 |
|------|-----|------|
| `listenPort` | 8443 | TLS 监听端口 |
| `shortID` | `a1b2c3d4e5f6a7b8` | 服务器短期标识，匹配客户端配置 |
| `maxConns` | 256 | 最大并发连接数 |
| `rateLimitWindow` | 30s | 速率限制时间窗口 |
| `maxPerWindow` | 5 | 每窗口最大请求数 |
| `replayWindow` | 90s | 重放攻击时间窗口 |
| `gracefulTimeout` | 30s | 优雅关闭超时 |

### 7.4 当前生产部署

| 项目 | 详情 |
|------|------|
| 服务器地址 | `usuk.4160365.xyz` |
| SSH 端口 | `27082` |
| Nyx 端口 | `8443` |
| 系统 | x86_64 Linux |
| 运行状态 | 启动中（systemd 托管） |

---

## 8. 客户端部署

### 8.1 Windows 客户端

**编译：**
```bash
cd ~/projects/nyx
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
  go build -ldflags="-s -w" -o nyx-client.exe ./cmd/client/
```

**配置文件 `nyx-client.json`：**
```json
{
  "server": "usuk.4160365.xyz",
  "port": 8443,
  "short_id": "a1b2c3d4e5f6a7b8",
  "socks5_port": 1080,
  "sni": "www.bilibili.com",
  "skip_cert_verify": true
}
```

**使用：**
```powershell
.\nyx-client.exe --config nyx-client.json
# 代理: SOCKS5 127.0.0.1:1080
```

### 8.2 Android (FlClashNyx)

Android 端使用 FlClash App 作为载体，通过 FFI 加载 Nyx 协议的 Go 实现。

**编译 libclash.so（⚠️ 必须 CGO_ENABLED=1）：**
```bash
cd ~/projects/flclash-nyx/core

# arm64-v8a
CGO_ENABLED=1 GOOS=android GOARCH=arm64 \
  CC=$HOME/android-sdk/ndk/28.2.13676358/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang \
  go build -buildmode=c-shared -tags with_gvisor \
  -ldflags="-s -w" -o libclash-arm64.so .

# armeabi-v7a
CGO_ENABLED=1 GOOS=android GOARCH=arm GOARM=7 \
  CC=$HOME/android-sdk/ndk/28.2.13676358/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi21-clang \
  go build -buildmode=c-shared -tags with_gvisor \
  -ldflags="-s -w" -o libclash-armv7a.so .
```

**重打包 APK（基于官方 FlClash）：**
```bash
# 1. 解压官方 APK
unzip -o FlClash-0.8.92-arm64-v8a.apk -d repack/

# 2. 替换 libclash.so
cp libclash-arm64.so repack/lib/arm64-v8a/libclash.so

# 3. 删除旧签名文件（保留 .version 文件）
rm -f repack/META-INF/*.RSA repack/META-INF/*.SF repack/META-INF/MANIFEST.MF

# 4. 重新打包（.arsc/.prof/.profm 必须 STORE）
cd repack
zip -r -X -0 unsigned.apk resources.arsc assets/dexopt/baseline.prof assets/dexopt/baseline.profm
zip -r -X unsigned.apk AndroidManifest.xml classes.dex assets/ lib/ META-INF/ res/

# 5. 对齐 + 签名
zipalign -p -f 4 unsigned.apk aligned.apk
apksigner sign --ks nyx-v2.keystore --ks-pass pass:nyx2024 \
  --ks-key-alias nyx --v1-signing-enabled true --v2-signing-enabled true \
  --v3-signing-enabled true --out nyx-signed.apk aligned.apk
```

**配置导入：**

将 `nyx-clash.yaml`（国内外分流配置）导入 FlClash → 配置 → 导入。

### 8.3 Linux 客户端

```bash
# 编译
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" \
  -o nyx-client ./cmd/client/

# 运行
./nyx-client --config nyx-client.json
# 代理: SOCKS5 127.0.0.1:1080
```

### 8.4 Clash/FlClash 配置文件

**纯 Nyx 节点配置：**
```yaml
proxies:
  - name: nyx
    type: nyx
    server: usuk.4160365.xyz
    port: 8443
    sni: www.bilibili.com
    short-id: "a1b2c3d4e5f6a7b8"
    skip-cert-verify: true
    fingerprint: chrome
    client-fingerprint: chrome
```

**国内外流量分流（推荐）：**

使用 Loyalsoldier 规则集实现国内直连 + 国外代理：

| 规则集 | 策略 | 说明 |
|--------|------|------|
| cncidr, GEOIP:CN | DIRECT | 中国 IP 段直连 |
| lancidr, private | DIRECT | 局域网直连 |
| gfw, proxy, tld-not-cn | PROXY | 境外域名走代理 |
| telegramcidr | PROXY | Telegram IP 段走代理 |
| apple, icloud | DIRECT | Apple 服务直连不耗流量 |
| 未匹配 | PROXY | 兜底走代理 |

完整配置文件: `~/nyx-clash.yaml`

---

## 9. 常用命令速查

### 服务端管理

```bash
# 状态检查
systemctl status nyx
ps aux | grep nyx-server

# 重启
systemctl restart nyx

# 查看日志
tail -f /root/nyx.log

# 手动重启（sshpass 远程）
sshpass -p '359062gp' ssh -p 27082 root@usuk.4160365.xyz \
  'bash -c "systemctl restart nyx"'

# 查看日志（远程）
sshpass -p '359062gp' ssh -p 27082 root@usuk.4160365.xyz \
  'tail -30 /root/nyx.log'
```

### 客户端编译

```bash
export PATH=$HOME/go-local/go/bin:$PATH
export TMPDIR=$HOME/tmp
cd ~/projects/nyx

# Linux x86_64
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o dist/nyx-client-linux ./cmd/client/

# Linux arm64
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -o dist/nyx-client-linux-arm64 ./cmd/client/

# Windows
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o dist/nyx-client-win/nyx-client.exe ./cmd/client/

# Server
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o dist/nyx-server-linux ./cmd/server/
```

---

## 附录：关键常量

```
ProtocolVersion  = 0x02
Marker           = "NYXK"
MinPreambleLen   = 200
MaxPreambleLen   = 768
MaxPadLen        = 64
ShortID          = a1b2c3d4e5f6a7b8
AuthBodyLen      = 83  (1 + 8 + 2 + 8 + 32 + 32)
CipherSuite      = XChaCha20-Poly1305 IETF
KDF              = HKDF-SHA256
KeyExchange      = X25519 ECDH
ReplayWindow     = 90s
MaxConns         = 256
```

---

> *Nyx — "Not Yet eXposed"*  
> *设计目标: 让加密流量与正常 HTTPS 完全不可区分*
