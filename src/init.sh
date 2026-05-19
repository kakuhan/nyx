#!/bin/bash
#=============================================================================
# Nyx 管理脚本 - 初始化模块 (init.sh)
# 参照 233boy/v2ray/src/init.sh 设计
#=============================================================================

author=kakuhan
repo=https://github.com/${author}/nyx

# ---- 终端颜色 ----
red='\e[31m'
yellow='\e[33m'
gray='\e[90m'
green='\e[92m'
blue='\e[94m'
magenta='\e[95m'
cyan='\e[96m'
none='\e[0m'

_red()      { echo -e ${red}$@${none}; }
_blue()     { echo -e ${blue}$@${none}; }
_cyan()     { echo -e ${cyan}$@${none}; }
_green()    { echo -e ${green}$@${none}; }
_yellow()   { echo -e ${yellow}$@${none}; }
_magenta()  { echo -e ${magenta}$@${none}; }
_red_bg()   { echo -e "\e[41m$@${none}"; }

is_err=$(_red_bg "[错误]")
is_warn=$(_yellow "[警告]")

err() {
    echo -e "\n$is_err $@\n"
    [[ $is_dont_auto_exit ]] && return
    exit 1
}
warn() { echo -e "\n$is_warn $@\n"; }

# ---- 文件操作快捷方式 ----
_rm()    { rm -rf "$@"; }
_cp()    { cp -rf "$@"; }
_sed()   { sed -i "$@"; }
_mkdir() { mkdir -p "$@"; }

# ---- 加载模块 ----
load() {
    . ${nyx_sh_dir}/src/$1
}

# ---- 下载函数 ----
_wget() {
    wget --no-check-certificate "$@"
}

# ---- 系统检测 ----
# 包管理器
if type -P apt-get &>/dev/null; then
    cmd="apt-get"
elif type -P yum &>/dev/null; then
    cmd="yum"
elif type -P dnf &>/dev/null; then
    cmd="dnf"
elif type -P apk &>/dev/null; then
    cmd="apk"
fi

# 架构
case $(uname -m) in
    amd64|x86_64)   nyx_core_arch="amd64" ;;
    aarch64|armv8*)  nyx_core_arch="arm64" ;;
    armv7l)          nyx_core_arch="armv7" ;;
    *)              err "不支持的架构: $(uname -m)" ;;
esac

# ---- Nyx 路径定义 ----
nyx_core=nyx
nyx_core_name="Nyx"
nyx_core_dir=/etc/${nyx_core}
nyx_core_bin=${nyx_core_dir}/bin/nyx-server
nyx_core_repo=${author}/${nyx_core}
nyx_conf_dir=${nyx_core_dir}
nyx_server_conf=${nyx_core_dir}/server.json
nyx_client_conf=${nyx_core_dir}/client.json
nyx_log_dir=/var/log/${nyx_core}
nyx_sh_bin=/usr/local/bin/${nyx_core}
nyx_sh_dir=${nyx_core_dir}/sh
nyx_sh_repo=${author}/${nyx_core}

# ---- 服务状态 ----
nyx_core_ver=$($nyx_core_bin -version 2>/dev/null || echo "未知")
if pgrep -f nyx-server &>/dev/null; then
    nyx_core_status=$(_green "运行中")
else
    nyx_core_status=$(_red "已停止")
    nyx_core_stop=1
fi
