# Nyx 透明代理协议

**借鉴 Shadowsocks AEAD / VMess / Trojan / Hysteria2 优点，规避已知缺陷的下一代翻墙协议。**

[![Go Version](https://img.shields.io/badge/Go-1.21%2B-blue)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

## 设计理念

现有协议的困境：
- **Shadowsocks**：流量指纹明显，AEAD 首包可被识别
- **VMess**：协议复杂，时间戳可被重放
- **Trojan**：认证失败时直接断开，GFW 主动探测可确认代理存在
- **Hysteria2**：依赖 QUIC，UDP QoS 严重时不可用

Nyx 的核心创新：
- **透明回退**：认证失败时自动代理真实目标网站，GFW 主动探测无法区分代理是否存在
- **uTLS 指纹伪装**：14 种浏览器 TLS 指纹随机化，告别固定指纹
- **Pre-Auth 盐化**：握手首帧填充随机盐，阻止 DPI 通过包长度建模
- **XChaCha20-Poly1305 + X25519**：现代密码学，256 位安全强度

## 协议对比

| 特性 | SS AEAD | VMess | Trojan | Hysteria2 | **Nyx** |
|------|---------|-------|--------|-----------|---------|
| 透明回退 | ❌ | ❌ | ❌ | ❌ | ✅ |
| TLS 指纹伪装 | ❌ | 固定 | 固定 | QUIC特有 | ✅ 14指纹池 |
| 握手盐化 | ❌ | ❌ | ❌ | ✅ | ✅ |
| 密码学 | AES-256-GCM | AES-128-GCM | TLS | TLS 1.3 | XChaCha20-Poly1305 |
| 多路复用 | ❌ | ❌ | ❌ | ✅ | ✅ yamux |
| 传输层 | TCP | TCP | TCP | QUIC/UDP | TCP |

## 架构

```
Client ──TLS(uTLS指纹)──▶ Server
  │                          │
  ├─ NyxAuthFrame ──────────▶│  X25519 ECDH + HMAC
  │                          │
  ├─ AEAD Tunnel ◀──────────▶│  XChaCha20-Poly1305
  │                          │
  ├─ yamux Streams ◀────────▶│  多路复用
  │                          │
  └─ SOCKS5 ◀───────────────▶│  Target
```

## 快速开始

### 一键安装 (推荐)

```bash
bash <(curl -sL https://raw.githubusercontent.com/kakuhan/nyx/main/install.sh)
```

### 手动安装

```bash
# 1. 克隆仓库
git clone https://github.com/kakuhan/nyx.git
cd nyx

# 2. 编译服务端
cd cmd/server
CGO_ENABLED=0 go build -o nyx-server .

# 3. 编译客户端
cd ../client
CGO_ENABLED=0 go build -o nyx-client .
```

### 配置

服务端 `server.json`:
```json
{
    "listen": ":8443",
    "target_domain": "www.bilibili.com",
    "psk": "<32字节预共享密钥>",
    "short_ids": {
        "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6": true
    }
}
```

客户端 `client.json`:
```json
{
    "server": "your-server.com:8443",
    "short_id": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
    "psk": "<与服务器一致的PSK>",
    "sni": "www.bilibili.com",
    "socks5": ":1080"
}
```

### 运行

```bash
# 服务端
./nyx-server -config server.json

# 客户端
./nyx-client -config client.json
```

## 项目结构

```
nyx/
├── cmd/
│   ├── server/      # 服务端入口
│   └── client/      # 客户端入口
├── internal/
│   ├── protocol/    # 协议核心 (握手/AEAD/认证)
│   ├── mux/         # yamux 多路复用
│   ├── tls/         # uTLS 指纹伪装
│   ├── socks5/      # SOCKS5 代理
│   └── clientapp/   # 客户端应用逻辑
├── install.sh       # 一键安装脚本
├── nyx.sh           # 管理脚本
└── src/             # 脚本模块
```

## 客户端支持

- [x] Linux CLI (nyx-client)
- [x] macOS CLI
- [x] Windows (exe + PowerShell launcher)
- [x] Android (FlClash 集成 APK)
- [ ] iOS (计划中)

## 文档

- [完整协议说明](NYX-COMPLETE-GUIDE.md)
- [安全审计报告](AUDIT-REPORT-2026-05-17.md)

## 致谢

Nyx 从以下项目中汲取灵感：
- [Shadowsocks](https://github.com/shadowsocks)
- [V2Ray](https://github.com/v2fly/v2ray-core) / [233boy/v2ray](https://github.com/233boy/v2ray)
- [Trojan](https://github.com/trojan-gfw/trojan)
- [Hysteria2](https://github.com/apernet/hysteria)
- [REALITY](https://github.com/XTLS/REALITY)
- [uTLS](https://github.com/refraction-networking/utls)

## License

[MIT](LICENSE)
