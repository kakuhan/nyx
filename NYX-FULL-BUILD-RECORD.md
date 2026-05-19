# Nyx 翻墙协议 — 完整构建实录

> 记录时间: 2026-05-17
> 涵盖: 协议设计哲学 | Linux 服务端 | Windows 客户端 | Android APK (FlClashNyx)
> 核心理念: 借鉴现有协议优点，规避其缺点

---

## 〇、协议设计哲学

### 现有协议优缺点分析

| 协议 | 借鉴（优点） | 规避（缺点） | Nyx 的做法 |
|------|-------------|-------------|-----------|
| **Shadowsocks** | AEAD 加密简洁高效 | 无伪装，GFW 通过熵+时序识别 | 套 TLS 1.3，流量看起来就是 HTTPS |
| **VMess** | 多路复用 mux.cool | UUID 固定，随机数可重放，无 PFS | ECDH X25519 每次连接新密钥，时间戳+PubKey 防重放 |
| **VLESS** | REALITY 伪装 + mux | 无加密层（裸 TLS 内直接传数据）| 双层加密：TLS 外 + Nyx 内 |
| **Trojan** | HTTP 头部伪装 | 密码明文在 TLS 内，无多路复用 | ShortID + ECDH 认证，yamux 多路复用 |
| **Hysteria2** | QUIC 多路复用优秀 | UDP 在中国极易被 QoS 限速 | TCP + TLS 1.3，在国内更稳定 |
| **Xray REALITY** | 证书克隆 + uTLS | 无独立的加密层 | 克隆证书 + uTLS 指纹 + Nyx AEAD 隧道 |

### Nyx 核心安全特性

1. **双重加密** — GFW 必须先破解 TLS 才能看到 Nyx 帧
2. **完美前向保密** — 每次连接 ECDH X25519 生成新密钥对
3. **透明回退** — 认证失败时转发到真实目标（bilibili），与正常 HTTPS 行为无法区分
4. **帧级随机填充** — 每帧 0-127 字节随机填充 + 心跳帧随机大小
5. **非单调 nonce** — data nonce 和 keystream nonce 分离，零碰撞风险
6. **HTTP Preamble 首位** — 第一个字节始终是 'G'（可打印 ASCII），满足 GFW SET-bit 豁免

### 协议栈架构

```
┌──────────┐     Nyx Tunnel (TLS 1.3 + HTTP伪装)      ┌──────────────┐
│  Client  │ ──────────────────────────────────────→  │   Server     │
│ SOCKS5   │  X25519 ECDH → XChaCha20-Poly1305 AEAD  │   → Internet │
└──────────┘     yamux Stream Multiplexing            └──────────────┘

Wire: [HTTP_preamble:200-768B][random_pad:16-64B]["NYXK":4B]
      [version:1B][shortID:8B][preambleLen:2B][timestamp:8B][clientPub:32B][HMAC:32B]
Auth: [nonce:24B][serverPub:32B][encrypted{version,status}:18B]
Data: [encrypted_len:2B][AEAD_ciphertext:var]  — SS AEAD-style framing
```

---

## 一、项目代码结构

### 独立 Nyx 协议实现 (`~/projects/nyx/`)

```
nyx/
├── cmd/
│   ├── server/main.go          # 服务端入口 v2.4
│   ├── client/main.go          # 客户端入口 v2.4
│   ├── apk/main.go             # Android NativeActivity 入口 (已弃用)
│   └── build-apk/main.go       # APK 构建器 (已弃用)
├── internal/
│   ├── protocol/
│   │   ├── auth.go             # X25519 握手 + HMAC 认证
│   │   ├── tunnel.go           # XChaCha20-Poly1305 AEAD 隧道
│   │   ├── auth_test.go        # 认证层测试
│   │   ├── tunnel_test.go      # 隧道层测试
│   │   └── cross_validate_test.go  # 跨层交叉验证
│   ├── mux/mux.go              # yamux 流多路复用
│   ├── socks5/server.go        # 本地 SOCKS5 代理
│   ├── tls/fingerprint.go      # TLS 浏览器指纹伪装 (uTLS)
│   ├── reality/cert.go         # REALITY 证书克隆
│   └── clientapp/client.go     # 客户端应用逻辑
└── dist/                       # 编译产物
    ├── nyx-server-linux            # Linux 服务端
    ├── nyx-client-linux            # Linux 客户端
    ├── nyx-client-linux-arm64      # Linux 客户端 (arm64)
    ├── nyx-client-win/             # Windows 分发包
    │   ├── nyx-client.exe
    │   ├── nyx-client.json
    │   ├── nyx-launcher.ps1
    │   └── README.txt
    └── nyx-v24.apk                 # 独立 APK (已弃用)
```

### FlClash Nyx 集成 (`~/projects/flclash-nyx/`)

```
flclash-nyx/
├── core/
│   ├── main.go                 # Go 核心入口 (编译为 FlClashCore.exe / libclash.so)
│   ├── common.go               # 公共定义
│   └── Clash.Meta/
│       ├── adapter/
│       │   ├── parser.go       # 添加 "nyx" 协议解析
│       │   ├── constant/adapters.go  # 注册 Nyx 类型 (iota)
│       │   └── outbound/
│       │       ├── nyx.go          # Nyx 出站适配器 (核心)
│       │       ├── base.go         # Base 出站 (被 Nyx 嵌入)
│       │       └── util.go         # 出站工具函数
│       └── transport/nyx/
│           └── protocol.go     # Nyx 协议实现 (848行)
│                                # 包含: 帧加密/解密/心跳/填充/多路复用
├── nyx-profile.yaml            # 单节点 Nyx 配置
└── nyx-clash.yaml              # 完整分流配置 (国内直连 + 国外 Nyx)
```

---

## 二、Linux 服务端 — 完整构建

### 编译

```bash
cd ~/projects/nyx

# Go 环境 (本地编译)
export PATH=$HOME/go-local/go/bin:$PATH
export TMPDIR=$HOME/tmp

# 编译 x86_64 Linux 服务端 (静态链接)
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
  go build -ldflags="-s -w" -o dist/nyx-server-linux ./cmd/server/
```

输出: `dist/nyx-server-linux` (~5.4MB, 纯静态 x86_64 ELF)

### 部署到远程 VPS

目标主机: `usuk.4160365.xyz` (SSH 27082, root / 359062gp, x86_64)

```bash
# 上传二进制
sshpass -p '359062gp' scp -P 27082 \
  ~/projects/nyx/dist/nyx-server-linux \
  root@usuk.4160365.xyz:/root/nyx-server

# 重启服务端
sshpass -p '359062gp' ssh -p 27082 root@usuk.4160365.xyz \
  'bash -c "killall nyx-server 2>/dev/null; nohup /root/nyx-server &>/root/nyx.log &"'
```

### 服务端行为 (全部硬编码，无需配置文件)

| 参数 | 值 |
|------|-----|
| 监听端口 | 8443 |
| TLS 证书 | 自签 ECDSA P-256 |
| 速率限制 | 5 次/30秒窗口 |
| 最大并发 | 256 连接 |
| 短期 ID | `a1b2c3d4e5f6a7b8` |
| 目标伪装站点 | `www.bilibili.com:443` |
| 透明回退 | 所有认证失败路径 → 转发到 bilibili |

### 运行状态

```
PID: 17209
运行时间: 持续运行，零崩溃
累计统计: 152 成功隧道 / 27 认证失败 / 0 穿透
```

---

## 三、Windows 客户端 — 完整构建

### 编译

```bash
cd ~/projects/nyx
export PATH=$HOME/go-local/go/bin:$PATH
export TMPDIR=$HOME/tmp

# Windows amd64 (纯静态，无 DLL 依赖)
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
  go build -ldflags="-s -w" -o dist/nyx-client-win/nyx-client.exe ./cmd/client/
```

输出: `dist/nyx-client-win/nyx-client.exe` (PE32+ x86-64)

### 分发 (4 文件)

1. **nyx-client.exe** — 二进制主程序
2. **nyx-client.json** — 配置文件
3. **nyx-launcher.ps1** — 一键启动 (阻塞式)
4. **README.txt** — 使用说明

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

### FlClash Core (Windows)

FlClash 的 Go 核心单独编译为 `FlClashCore.exe`，由 Flutter 主程序作为子进程调用:

```bash
cd ~/projects/flclash-nyx/core
export GOTMPDIR=~/tmp/go-build
export GOCACHE=~/tmp/go-cache
export TMPDIR=~/tmp

# ⚠️ Docker sandbox 中 /tmp 只读，必须设置 GOTMPDIR/GOCACHE
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
  go build -tags with_gvisor -o FlClashCore.exe ./
```

放置方式: 将 `FlClashCore.exe` 放在 `FlClash.exe` 同目录，Flutter 通过 `executableDirPath/FlClashCore.exe` 自动发现。

---

## 四、Android APK — FlClashNyx 完整构建

### 整体思路

不自己写 Android 应用，而是利用成熟的 Clash Android 客户端 FlClash，
将其代理核心（`libclash.so`）替换为包含 Nyx 协议的版本。

```
FlClash App (Flutter/Dart) → JNI → libclash.so (Go CGO shared library)
                                       ├── invokeAction()
                                       ├── startTUN()
                                       ├── quickSetup()
                                       ├── stopTun()
                                       └── getTraffic()
```

### Step 1: 整合 Nyx 协议到 FlClash 源码

在 `~/projects/flclash-nyx/core/Clash.Meta/` 中做了三处改动:

**a) 注册协议类型** (`constant/adapters.go`):
```go
const (
    // ... 原有类型 ...
    Nyx   // ← 新增
)
```

**b) 协议解析** (`adapter/parser.go`):
```go
case "nyx":
    return outbound.NewNyx(option)
```

**c) 出站适配器** (`adapter/outbound/nyx.go`):
```go
type Nyx struct {
    *Base              // 嵌入 Base (复用连接管理)
    server   string
    port     int
    sni      string
    shortID  string
}

func (n *Nyx) StreamConnContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (net.Conn, error) {
    // 1. DialTCP 连接服务端
    // 2. uTLS TLS 握手 → 流量看起来像 Chrome HTTPS
    // 3. Nyx 协议握手 (X25519 ECDH + HMAC 认证)
    // 4. 派生双向密钥 (XChaCha20-Poly1305)
    // 5. 启动 yamux 多路复用
    // 6. 启动心跳协程
}
```

**d) 协议实现** (`transport/nyx/protocol.go`, 848行):
```
包含: 帧加密/解密 | 首帧自动加盐/脱盐 | 心跳帧 | 随机填充
     | 非单调 nonce (data + keystream 双计数器分离)
```

### Step 2: 编译 libclash.so

**⚠️ 铁律: `CGO_ENABLED=1` + `-buildmode=c-shared`**

用 `CGO_ENABLED=0` 会排除 `lib.go`（带 `//go:build cgo` 标签），
导致 FlClash 找不到 `invokeAction`/`startTUN` 等 FFI 入口函数 → "core 断开"。

```bash
export PATH=$HOME/go-local/go/bin:$PATH
export TMPDIR=$HOME/tmp
cd ~/projects/flclash-nyx/core

# arm64-v8a (64位，目标硬件大部分)
CGO_ENABLED=1 GOOS=android GOARCH=arm64 \
  CC=$HOME/android-sdk/ndk/28.2.13676358/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang \
  go build -buildmode=c-shared -tags with_gvisor \
  -ldflags="-s -w" -o ~/tmp/libclash-arm64.so .

# armeabi-v7a (32位兼容)
CGO_ENABLED=1 GOOS=android GOARCH=arm GOARM=7 \
  CC=$HOME/android-sdk/ndk/28.2.13676358/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi21-clang \
  go build -buildmode=c-shared -tags with_gvisor \
  -ldflags="-s -w" -o ~/tmp/libclash-armv7a.so .
```

验证导出:
```bash
readelf -s ~/tmp/libclash-arm64.so | grep -E "invokeAction|startTUN|quickSetup|stopTun|getTraffic"
# 必须看到 5 个函数符号
```

输出大小: arm64 ~36MB, armv7a ~32MB

### Step 3: 重打包 APK

使用官方 FlClash APK 作为基础，替换 libclash.so:

```bash
OFFICIAL=~/tmp/FlClash-0.8.92-arm64-v8a.apk
WORKDIR=~/tmp/flclash-repack
mkdir -p $WORKDIR && cd $WORKDIR && rm -rf *

# ① 解压官方 APK
unzip -o "$OFFICIAL"

# ② 替换核心库
cp ~/tmp/libclash-arm64.so lib/arm64-v8a/libclash.so
cp ~/tmp/libclash-armv7a.so lib/armeabi-v7a/libclash.so

# ③ 删除签名文件 (只删 RSA/SF/MF，保留 META-INF 其他所有文件!)
rm -f META-INF/*.RSA META-INF/*.SF META-INF/MANIFEST.MF
# 验证: ls META-INF/ 应仍有 74 个文件

# ④ 重新打包
# 关键: .arsc 和 .prof/.profm 必须 STORE (不压缩)，其余 DEFLATE
# 必须一枪完成，不能分两次 zip
rm -f ~/nyx-flclash.apk
zip -r -X -0 ~/nyx-flclash.apk resources.arsc \
  'assets/dexopt/baseline.prof' 'assets/dexopt/baseline.profm'
zip -r -X ~/nyx-flclash.apk AndroidManifest.xml classes.dex \
  assets/ lib/ META-INF/ res/

# ⑤ 4字节对齐
~/android-sdk/build-tools/34.0.0/zipalign -p -f 4 \
  ~/nyx-flclash.apk ~/nyx-flclash-aligned.apk

# ⑥ 签名 (v1+v2+v3)
~/android-sdk/build-tools/34.0.0/apksigner sign \
  --ks ~/tmp/nyx-v2.keystore \
  --ks-pass pass:nyx2024 \
  --ks-key-alias nyx \
  --v1-signing-enabled true \
  --v2-signing-enabled true \
  --v3-signing-enabled true \
  --out ~/nyx-flclash-signed.apk \
  ~/nyx-flclash-aligned.apk

# ⑦ 验证
~/android-sdk/build-tools/34.0.0/apksigner verify --verbose ~/nyx-flclash-signed.apk
# 必须显示: V1: true, V2: true, V3: true
```

### Step 4: 配置文件

客户端导入的 Clash 配置:

**单节点配置** (`nyx-profile.yaml`):
```yaml
proxies:
  - name: nyx
    type: nyx
    server: usuk.4160365.xyz
    port: 8443
    sni: www.bilibili.com
    short-id: a1b2c3d4e5f6a7b8
    fingerprint: chrome
```

**完整分流配置** (`nyx-clash.yaml`):
```yaml
# 国内直连 + 国外 Nyx 代理
# 使用 Loyalsoldier 规则集自动分流
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - nyx
      - DIRECT
  - name: 国内直连
    type: select
    proxies:
      - DIRECT

rules:
  - GEOIP,CN,国内直连
  - MATCH,PROXY
```

---

## 五、密钥与证书

### 签名密钥
```
位置: ~/tmp/nyx-v2.keystore
密码: nyx2024
别名: nyx (密钥密码同)
算法: RSA 2048
```

### 环境依赖

| 工具 | 路径 | 用途 |
|------|------|------|
| Go | `~/go-local/go/bin/go` (go1.24.3 linux/arm64) | 协议/核心编译 |
| Android SDK | `~/android-sdk/` | APK 工具链 |
| Android NDK | `~/android-sdk/ndk/28.2.13676358/` | CGO 交叉编译 |
| Build Tools | `~/android-sdk/build-tools/34.0.0/` | zipalign, apksigner |
| SSH | `sshpass` + `scp` | 远程部署 |
| Docker Sandbox | `/tmp` 只读! | `GOTMPDIR`/`GOCACHE` 必须重定向 |

---

## 六、七大陷阱与解法

### 陷阱 1: CGO_ENABLED=0 导致 FFI 缺失
**症状**: FlClash 显示 "core 断开"，无法连接
**原因**: `lib.go` 带 `//go:build cgo` 标签，CGO_ENABLED=0 时被排除，
   FlClash 找不到 `invokeAction`/`startTUN` 等 FFI 入口
**解法**: 必须 `CGO_ENABLED=1 -buildmode=c-shared`

### 陷阱 2: -buildmode=pie 只导出 main.main
**症状**: FlClash 找不到 FFI 符号
**原因**: PIE executable 只导出 `main.main`，不导出 cgo 函数
**解法**: 必须 `-buildmode=c-shared` (shared library)

### 陷阱 3: zip -u 原地修改 APK
**症状**: 安装时提示「安装包已损坏」
**原因**: 原地修改破坏 ZIP 目录结构和 CRC
**解法**: 完整解压 → 替换文件 → 重新打包 → zipalign → 签名

### 陷阱 4: .arsc/.prof 压缩
**症状**: Android PackageManager 拒绝安装
**原因**: Android 直接 mmap 这些文件，压缩后 mmap 不可用
**解法**: `zip -0` (STORE) 这些文件，其余 DEFLATE

### 陷阱 5: 删除全部 META-INF
**症状**: 签名验证失败
**原因**: META-INF 中有 V2/V3 签名方案的 version/SPI 分块元数据文件
**解法**: 只删 RSA/SF/MF，保留所有 .version 和 services/ 文件

### 陷阱 6: Docker /tmp 只读
**症状**: `go build` 报 "read-only filesystem"
**原因**: Docker sandbox 限制
**解法**: 设置 `GOTMPDIR=~/tmp/go-build` `GOCACHE=~/tmp/go-cache`

### 陷阱 7: 分两次 zip 写入 APK
**症状**: APK 结构异常
**原因**: 每次 zip 独立写中心目录，两次写入产生双中心目录
**解法**: 一枪完成所有文件，用 `-0` 逐个指定 STORE 文件

---

## 七、调试铁律

**遇到问题 → 先查上次成功的版本/方案 → 对比差异 → 定位根因 → 再动手**

不要盲目试各种修改。APK 构建出问题时，正确的排查顺序:
1. 确认上次成功安装的 APK 版本
2. 对比编译参数差异 (`CGO_ENABLED` / `-buildmode`)
3. 对比压缩方式差异 (STORE vs DEFLATE)
4. 对比签名差异 (v1/v2/v3)
5. 验证导出符号 (`readelf -s`)

---

## 八、服务端运维

### 健康检查
```bash
sshpass -p '359062gp' ssh -p 27082 root@usuk.4160365.xyz \
  'ps aux | grep nyx-server | grep -v grep'
```

### 快速统计
```bash
sshpass -p '359062gp' ssh -p 27082 root@usuk.4160365.xyz \
  'echo "success:$(grep -c 'tunnel established' /root/nyx.log) fail:$(grep -c 'auth failure\|auth read' /root/nyx.log)"'
```

### 定时安全审计
- **日审计**: cron job `nyx-daily-log-audit`，每天 01:00 运行
- **周汇总**: cron job `nyx-weekly-summary`，每周五 10:00 推送到 Telegram

---

## 九、成果总结

| 产物 | 平台 | 文件 | 大小 |
|------|------|------|------|
| 服务端 | Linux x86_64 | `nyx-server-linux` | 5.4MB |
| 命令行客户端 | Windows | `nyx-client.exe` + 配置 | ~10MB |
| 命令行客户端 | Linux | `nyx-client-linux` | ~10MB |
| FlClash 核心 | Windows | `FlClashCore.exe` | 42MB |
| FlClashNyx APK | Android arm64+v7a | `nyx-flclash-signed.apk` | ~45MB |

**服务端运行数据**: PID 17209, 连续运行零崩溃, 152 成功隧道, 27 认证失败(同 IP 已拦截), 0 穿透。

---

*记录完毕。重启 session 后，从这里就能恢复全部上下文。*
