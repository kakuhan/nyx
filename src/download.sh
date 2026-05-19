#!/bin/bash
#=============================================================================
# Nyx 管理脚本 - 下载模块 (download.sh)
#=============================================================================

# 从 GitHub Releases 下载指定版本的 nyx-server
download_nyx() {
    local ver="${1:-latest}"
    local arch="$nyx_core_arch"
    local url

    if [[ $ver == "latest" ]]; then
        url="https://github.com/${nyx_core_repo}/releases/latest/download/nyx-server-linux-${arch}"
    else
        url="https://github.com/${nyx_core_repo}/releases/download/${ver}/nyx-server-linux-${arch}"
    fi

    _yellow "下载 Nyx 核心 ${ver} ..."
    _wget -q --show-progress -O "${nyx_core_bin}.dl" "$url"

    if [[ $? -eq 0 ]] && [[ -s "${nyx_core_bin}.dl" ]]; then
        chmod +x "${nyx_core_bin}.dl"
        mv "${nyx_core_bin}.dl" "$nyx_core_bin"
        _green "Nyx 核心下载完成"
        return 0
    else
        _rm "${nyx_core_bin}.dl"
        return 1
    fi
}
