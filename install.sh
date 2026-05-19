#!/bin/bash
#=============================================================================
# NYX 一键安装脚本
# 借鉴 233boy/v2ray 设计，适配 Nyx 协议特点
#=============================================================================
author=kakuhan
repo=https://github.com/${author}/nyx

# bash colors
red='\e[31m'
yellow='\e[33m'
gray='\e[90m'
green='\e[92m'
blue='\e[94m'
cyan='\e[96m'
none='\e[0m'

_red() { echo -e ${red}$@${none}; }
_blue() { echo -e ${blue}$@${none}; }
_cyan() { echo -e ${cyan}$@${none}; }
_green() { echo -e ${green}$@${none}; }
_yellow() { echo -e ${yellow}$@${none}; }

is_err=$(_red "[错误]")
is_warn=$(_yellow "[警告]")
is_ok=$(_green "[OK]")

err() { echo -e "\n$is_err $@\n" && exit 1; }
warn() { echo -e "\n$is_warn $@\n"; }
ok() { echo -e "${green}$(date +'%T')${none}) $@"; }

# ---- 系统检测 ----
# 必须 root
[[ $EUID != 0 ]] && err "请使用 root 用户运行此脚本"

# 包管理器
if type -P apt-get &>/dev/null; then
    PKG_MGR="apt-get"
elif type -P yum &>/dev/null; then
    PKG_MGR="yum"
elif type -P dnf &>/dev/null; then
    PKG_MGR="dnf"
elif type -P apk &>/dev/null; then
    PKG_MGR="apk"
else
    err "不支持的系统，需要 apt-get / yum / dnf / apk"
fi

# systemd
[[ ! $(type -P systemctl) && ! $(type -P rc-service) ]] && {
    err "此系统缺少 systemd 或 openrc，无法管理服务"
}

# 架构检测
case $(uname -m) in
    amd64|x86_64)   NYX_ARCH="amd64" ;;
    aarch64|armv8*)  NYX_ARCH="arm64" ;;
    armv7l)          NYX_ARCH="armv7" ;;
    *)              err "仅支持 amd64/arm64/armv7 架构" ;;
esac

# ---- 变量 ----
NYX_DIR=/etc/nyx
NYX_BIN=${NYX_DIR}/bin/nyx-server
NYX_CONF=${NYX_DIR}/server.json
NYX_SH_DIR=${NYX_DIR}/sh
NYX_SH_BIN=/usr/local/bin/nyx
NYX_LOG=/var/log/nyx

nyx_ver="latest"

# ---- 工具函数 ----
download() {
    local url="$1" dst="$2" name="$3"
    ok "下载 ${name}..."
    if type -P wget &>/dev/null; then
        wget --no-check-certificate -q --show-progress -O "$dst" "$url" || err "下载失败: $url"
    elif type -P curl &>/dev/null; then
        curl -#fSL -o "$dst" "$url" || err "下载失败: $url"
    else
        err "需要 wget 或 curl 才能下载"
    fi
}

# 获取服务器 IP
get_ip() {
    local ip4 ip6
    ip4=$(curl -4 -s --max-time 3 https://1.1.1.1/cdn-cgi/trace 2>/dev/null | grep ip= | cut -d= -f2)
    ip6=$(curl -6 -s --max-time 3 https://1.1.1.1/cdn-cgi/trace 2>/dev/null | grep ip= | cut -d= -f2)
    SERVER_IP="${ip4:-$ip6}"
    [[ -z $SERVER_IP ]] && SERVER_IP=$(curl -s --max-time 3 https://api.ipify.org 2>/dev/null)
    [[ -z $SERVER_IP ]] && err "无法获取服务器 IP"
    ok "服务器 IP: $SERVER_IP"
}

# 生成随机字符串
random_str() {
    local len=${1:-32}
    openssl rand -hex $len 2>/dev/null || cat /dev/urandom | tr -dc 'a-f0-9' | head -c $((len*2))
}

# ---- 安装依赖 ----
install_deps() {
    ok "安装依赖包..."
    local deps="wget curl openssl"
    case $PKG_MGR in
        apt-get) apt-get update -qq && apt-get install -y -qq $deps ;;
        yum)     yum install -y -q $deps ;;
        dnf)     dnf install -y -q $deps ;;
        apk)     apk add --no-cache $deps ;;
    esac
}

# ---- 下载 Nyx ----
install_nyx() {
    ok "下载 Nyx 服务端..."
    _mkdir -p ${NYX_DIR}/bin ${NYX_SH_DIR}/src ${NYX_LOG}

    # 下载 nyx-server
    local dl_url="${repo}/releases/${nyx_ver}/download/nyx-server-linux-${NYX_ARCH}"
    download "$dl_url" "$NYX_BIN" "nyx-server"
    chmod +x "$NYX_BIN"

    # 下载管理脚本
    download "${repo}/raw/main/nyx.sh" "${NYX_SH_DIR}/nyx.sh" "管理脚本"
    download "${repo}/raw/main/src/init.sh" "${NYX_SH_DIR}/src/init.sh" "初始化模块"
    download "${repo}/raw/main/src/core.sh" "${NYX_SH_DIR}/src/core.sh" "核心模块"
    download "${repo}/raw/main/src/download.sh" "${NYX_SH_DIR}/src/download.sh" "下载模块"
    download "${repo}/raw/main/src/systemd.sh" "${NYX_SH_DIR}/src/systemd.sh" "服务模块"

    chmod +x ${NYX_SH_DIR}/nyx.sh
    ln -sf ${NYX_SH_DIR}/nyx.sh /usr/local/bin/nyx

    ok "Nyx 安装完成！"
}

# ---- 生成配置 ----
gen_config() {
    local port=${1:-8443}
    local sni=${2:-www.bilibili.com}
    local psk=$(random_str 32)
    local shortid=$(random_str 16)

    cat > $NYX_CONF <<EOF
{
    "listen": ":${port}",
    "target_domain": "${sni}",
    "psk": "${psk}",
    "short_ids": {
        "${shortid}": true
    },
    "tls_fingerprints": [
        "chrome_124", "chrome_120", "chrome_116",
        "firefox_125", "firefox_121", "firefox_117",
        "safari_17", "safari_16", "safari_15",
        "edge_124", "edge_120",
        "ios_17", "ios_16",
        "android_14"
    ],
    "mux": {
        "max_streams": 256
    }
}
EOF

    # 保存客户端配置
    cat > ${NYX_DIR}/client.json <<EOF
{
    "server": "${SERVER_IP}:${port}",
    "short_id": "${shortid}",
    "psk": "${psk}",
    "sni": "${sni}",
    "socks5": ":1080",
    "fingerprints": [
        "chrome_124", "chrome_120", "firefox_125",
        "safari_17", "edge_124", "ios_17", "android_14"
    ]
}
EOF

    ok "配置文件已生成"
}

# ---- 安装系统服务 ----
install_service() {
    cat > /etc/systemd/system/nyx.service <<EOF
[Unit]
Description=Nyx Transparent Proxy
After=network.target

[Service]
Type=simple
ExecStart=${NYX_BIN} -config ${NYX_CONF}
Restart=on-failure
RestartSec=5s
StandardOutput=append:${NYX_LOG}/server.log
StandardError=append:${NYX_LOG}/server.log

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable nyx
    ok "系统服务已安装"
}

# ---- 启动 ----
start_nyx() {
    systemctl start nyx
    sleep 1
    if pgrep -f nyx-server >/dev/null 2>&1; then
        _green "\n========================================"
        _green "  Nyx 代理服务安装完成！"
        _green "========================================\n"
        echo ""
        _cyan "  管理命令: nyx [选项]"
        echo ""
        _yellow "  服务端配置: ${NYX_CONF}"
        _yellow "  客户端配置: ${NYX_DIR}/client.json"
        echo ""
        _cyan "  快捷操作:"
        echo "    nyx start     - 启动服务"
        echo "    nyx stop      - 停止服务"
        echo "    nyx restart   - 重启服务"
        echo "    nyx status    - 查看状态"
        echo "    nyx info      - 查看配置"
        echo "    nyx log       - 查看日志"
        echo "    nyx update    - 更新核心"
        echo ""
        _green "  客户端连接信息:"
        _cyan "    服务器: ${SERVER_IP}:${1:-8443}"
        _cyan "    PSK:    ${psk:-<见配置>}"
        _cyan "    SNI:    ${2:-www.bilibili.com}"
        echo ""
    else
        err "服务启动失败，请检查日志: ${NYX_LOG}/server.log"
    fi
}

# ---- 参数解析 ----
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -p|--port)
                NYX_PORT="$2"; shift 2 ;;
            -s|--sni)
                NYX_SNI="$2"; shift 2 ;;
            -v|--version)
                nyx_ver="$2"; shift 2 ;;
            -h|--help)
                show_help; exit 0 ;;
            *)
                warn "未知参数: $1"; shift ;;
        esac
    done
}

show_help() {
    echo "Nyx 一键安装脚本"
    echo "用法: $0 [-p 端口] [-s SNI域名] [-v 版本]"
    echo ""
    echo "  -p, --port      服务端口 (默认: 8443)"
    echo "  -s, --sni       SNI 伪装域名 (默认: www.bilibili.com)"
    echo "  -v, --version   指定版本 (默认: latest)"
    echo "  -h, --help      显示帮助"
}

# ---- 前置检查 ----
pre_check() {
    # 检查是否已安装
    if [[ -f $NYX_CONF ]] && [[ -f $NYX_BIN ]]; then
        warn "检测到 Nyx 已安装"
        read -p "是否重新安装? [y/N]: " yn
        [[ ! $yn =~ ^[Yy] ]] && exit 0
        systemctl stop nyx 2>/dev/null
    fi

    # 检查端口
    if ss -tlnp | grep -q ":${NYX_PORT:-8443} "; then
        warn "端口 ${NYX_PORT:-8443} 已被占用"
        read -p "强制继续? [y/N]: " yn
        [[ ! $yn =~ ^[Yy] ]] && exit 1
    fi
}

# ---- Main ----
main() {
    clear
    _cyan ""
    _cyan "  ╔═══════════════════════════════════╗"
    _cyan "  ║     Nyx 透明代理 一键安装脚本     ║"
    _cyan "  ╚═══════════════════════════════════╝"
    echo ""

    parse_args "$@"
    NYX_PORT=${NYX_PORT:-8443}
    NYX_SNI=${NYX_SNI:-www.bilibili.com}

    pre_check
    install_deps
    get_ip
    install_nyx
    gen_config "$NYX_PORT" "$NYX_SNI"
    install_service
    start_nyx "$NYX_PORT" "$NYX_SNI"
}

# 防止 wget/curl 未安装时无法开始
type -P curl &>/dev/null || type -P wget &>/dev/null || {
    echo "请先安装 curl 或 wget"
    exit 1
}

main "$@"
