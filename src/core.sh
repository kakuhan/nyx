#!/bin/bash
#=============================================================================
# Nyx 管理脚本 - 核心模块 (core.sh)
# 管理功能: status, info, start, stop, restart, log, update, uninstall
#=============================================================================

# ---- 随机字符串 ----
random_str() {
    local len=${1:-32}
    openssl rand -hex $len 2>/dev/null || cat /dev/urandom | tr -dc 'a-f0-9' | head -c $((len*2))
}

# ---- 获取服务器 IP ----
get_ip() {
    # 优先取公网 IPv4，其次 IPv6，辅助 ipify
    local ip4 ip6
    ip4=$(curl -4 -s --max-time 3 https://1.1.1.1/cdn-cgi/trace 2>/dev/null | grep ip= | cut -d= -f2)
    ip6=$(curl -6 -s --max-time 3 https://1.1.1.1/cdn-cgi/trace 2>/dev/null | grep ip= | cut -d= -f2)
    echo "${ip4:-$ip6}"
}

# ---- 查看状态 ----
view_status() {
    echo
    _cyan "  Nyx 服务状态"
    _cyan "  ────────────"
    echo "  状态: $nyx_core_status"
    echo "  版本: $nyx_core_ver"
    echo "  路径: $nyx_core_bin"
    echo "  配置: $nyx_server_conf"
    if [[ ! $nyx_core_stop ]]; then
        local port=$(grep -oP '"\d+"' "$nyx_server_conf" 2>/dev/null | head -1 | tr -d '"' || echo "?")
        echo "  端口: $port"
    fi
    echo
}

# ---- 查看配置（含客户端信息） ----
view_info() {
    if [[ ! -f $nyx_server_conf ]]; then
        err "配置文件不存在: $nyx_server_conf"
    fi

    local port=$(grep -oP '"(:\d+|"[^"]*:\d+)"' "$nyx_server_conf" 2>/dev/null | grep -oP '\d+' | head -1 || echo "?")
    local sni=$(grep -oP '"target_domain"\s*:\s*"[^"]*"' "$nyx_server_conf" 2>/dev/null | cut -d'"' -f4 || echo "?")
    local shortid=$(grep -oP 'short_ids.*?\"([a-f0-9]{16,})\"' "$nyx_server_conf" 2>/dev/null | grep -oP '[a-f0-9]{16,}' | head -1 || echo "?")
    local ip=$(get_ip)

    echo
    _cyan "  ╔═══════════════════════════════════╗"
    _cyan "  ║       Nyx 代理配置信息           ║"
    _cyan "  ╚═══════════════════════════════════╝"
    echo
    _yellow "  ── 服务端 ──"
    echo "  监听端口: ${port}"
    echo "  伪装域名: ${sni}"
    echo
    _yellow "  ── 客户端 (Clash Meta / v2rayN / Nekoray) ──"
    echo "  服务器:   ${ip}:${port}"
    echo "  Short ID: ${shortid}"
    echo "  SNI:      ${sni}"
    echo "  协议:     nyx"
    echo
    _yellow "  ── Clash Meta 配置片段 ──"
    echo
    echo "  proxies:"
    echo "    - name: nyx"
    echo "      type: nyx"
    echo "      server: ${ip}"
    echo "      port: ${port}"
    echo "      short-id: ${shortid}"
    echo "      sni: ${sni}"
    echo
    _yellow "  ── 客户端 JSON ──"
    if [[ -f $nyx_client_conf ]]; then
        _cyan "$(cat $nyx_client_conf | sed 's/^/  /')"
    fi
    echo
}

# ---- 添加/生成配置 ----
add_config() {
    local port=${1:-8443}
    local sni=${2:-www.bilibili.com}
    local shortid=$(random_str 16)

    # 备份旧配置
    [[ -f $nyx_server_conf ]] && _cp $nyx_server_conf ${nyx_server_conf}.bak

    cat > $nyx_server_conf <<EOF
{
    "listen": ":${port}",
    "short_ids": ["${shortid}"],
    "target_domain": "${sni}",
    "target_addr": "${sni}:443",
    "cert_path": "${nyx_core_dir}/nyx-cert.pem",
    "key_path": "${nyx_core_dir}/nyx-key.pem",
    "max_conns_per_window": 10,
    "rate_limit_window": 30,
    "replay_window": 90,
    "idle_timeout": 300,
    "max_concurrent_conns": 256
}
EOF

    local server_ip=$(get_ip)
    cat > $nyx_client_conf <<EOF
{
    "server": "${server_ip}:${port}",
    "short_id": "${shortid}",
    "sni": "${sni}",
    "socks5": ":1080"
}
EOF

    _green "配置已生成!"
    echo ""
    view_info "no_ip"
}

# ---- 修改配置参数 ----
change_config() {
    local opt="$1" val="$2"
    [[ ! $opt ]] && { err "用法: nyx change <option> <value>\n  option: port, sni, shortid"; }
    [[ ! -f $nyx_server_conf ]] && err "配置文件不存在，请先 nyx add"

    case $opt in
        port)
            [[ ! $val ]] && err "请指定端口，如: nyx change port 443"
            _sed "s/\"listen\": \"[^\"]*\"/\"listen\": \":${val}\"/" $nyx_server_conf
            _green "端口已修改为: $val"
            warn "需要重启服务生效: nyx restart"
            ;;
        sni)
            [[ ! $val ]] && err "请指定域名，如: nyx change sni www.google.com"
            _sed "s/\"target_domain\": \"[^\"]*\"/\"target_domain\": \"${val}\"/" $nyx_server_conf
            _sed "s/\"target_addr\": \"[^\"]*\"/\"target_addr\": \"${val}:443\"/" $nyx_server_conf
            _sed "s/\"sni\": \"[^\"]*\"/\"sni\": \"${val}\"/" $nyx_client_conf
            _green "SNI 伪装域名已修改为: $val"
            warn "需要重启服务生效: nyx restart"
            ;;
        shortid)
            [[ ! $val ]] && val=$(random_str 16)
            _sed "s/\"short_ids\": \[\"[^\"]*\"\]/\"short_ids\": \[\""${val}"\"\]/" $nyx_server_conf
            _sed "s/\"short_id\": \"[^\"]*\"/\"short_id\": \"${val}\"/" $nyx_client_conf
            _green "Short ID 已更新: $val"
            warn "需要重启服务生效: nyx restart"
            ;;
        *)
            err "未知配置项: $opt\n  支持: port, sni, shortid"
            ;;
    esac
}

# ---- 服务控制 ----
nyx_start() {
    if [[ $nyx_core_stop ]]; then
        systemctl start nyx
        sleep 1
        if pgrep -f nyx-server &>/dev/null; then
            _green "Nyx 服务已启动"
        else
            err "启动失败，请查看日志: nyx log"
        fi
    else
        _yellow "Nyx 服务已在运行中"
    fi
}

nyx_stop() {
    if [[ $nyx_core_stop ]]; then
        _yellow "Nyx 服务未在运行"
    else
        systemctl stop nyx
        sleep 1
        _green "Nyx 服务已停止"
    fi
}

nyx_restart() {
    systemctl restart nyx
    sleep 1
    if pgrep -f nyx-server &>/dev/null; then
        _green "Nyx 服务已重启"
    else
        err "重启失败，请查看日志: nyx log"
    fi
}

# ---- 查看日志 ----
view_log() {
    if [[ -f ${nyx_log_dir}/server.log ]]; then
        tail -n 50 ${nyx_log_dir}/server.log
    else
        # 系统日志回退
        journalctl -u nyx --no-pager -n 50
    fi
}

view_logerr() {
    if [[ -f ${nyx_log_dir}/server.log ]]; then
        grep -i -E 'error|fail|warn|panic|fatal' ${nyx_log_dir}/server.log | tail -n 50
    else
        journalctl -u nyx --no-pager -p err -n 50
    fi
}

# ---- 更新核心 ----
update_core() {
    _yellow "正在更新 Nyx 核心..."
    systemctl stop nyx 2>/dev/null

    local dl_url="https://github.com/${nyx_core_repo}/releases/latest/download/nyx-server-linux-${nyx_core_arch}"
    _wget -q --show-progress -O ${nyx_core_bin}.new "$dl_url"
    if [[ $? -eq 0 ]] && [[ -s ${nyx_core_bin}.new ]]; then
        chmod +x ${nyx_core_bin}.new
        mv ${nyx_core_bin}.new $nyx_core_bin
        _green "核心更新成功!"
        systemctl start nyx
    else
        _rm ${nyx_core_bin}.new
        err "核心更新失败"
        systemctl start nyx
    fi
}

# ---- 更新管理脚本 ----
update_script() {
    _yellow "正在更新管理脚本..."
    local dl_url="https://github.com/${nyx_sh_repo}/raw/main/nyx.sh"
    _wget -q -O ${nyx_sh_dir}/nyx.sh.new "$dl_url"
    if [[ $? -eq 0 ]]; then
        mv ${nyx_sh_dir}/nyx.sh.new ${nyx_sh_dir}/nyx.sh
        chmod +x ${nyx_sh_dir}/nyx.sh
        _green "管理脚本更新成功! 版本: $(grep nyx_sh_ver ${nyx_sh_dir}/nyx.sh | head -1)"
    else
        _rm ${nyx_sh_dir}/nyx.sh.new
        err "管理脚本更新失败"
    fi
}

# ---- 卸载 ----
uninstall_nyx() {
    _red_bg " 警告: 即将卸载 Nyx  "
    echo
    read -p "确认卸载? 输入 YES 继续: " confirm
    [[ "$confirm" != "YES" ]] && { _yellow "已取消"; return; }

    systemctl stop nyx 2>/dev/null
    systemctl disable nyx 2>/dev/null
    _rm /etc/systemd/system/nyx.service
    systemctl daemon-reload
    _rm $nyx_core_dir
    _rm $nyx_log_dir
    _rm /usr/local/bin/nyx
    _green "Nyx 已完全卸载"
}

# ---- 帮助 ----
show_help() {
    echo
    _cyan "  Nyx 管理脚本 v${nyx_sh_ver}"
    echo
    echo "  用法: nyx [命令] [参数...]"
    echo
    _yellow "  基本操作:"
    echo "    status             查看运行状态"
    echo "    info               查看配置信息 (含客户端连接参数)"
    echo "    log                查看最近日志"
    echo "    logerr             查看错误日志"
    echo
    _yellow "  配置管理:"
    echo "    add [端口] [SNI]   添加/重新生成配置"
    echo "    change <项> <值>   修改配置 (port/sni/shortid)"
    echo
    _yellow "  服务控制:"
    echo "    start              启动服务"
    echo "    stop               停止服务"
    echo "    restart            重启服务"
    echo
    _yellow "  维护:"
    echo "    update [core|sh]   更新核心 或 管理脚本"
    echo "    uninstall          卸载 Nyx"
    echo "    help               显示此帮助"
    echo
}

# ---- 主分发函数 ----
main() {
    case $1 in
        main|"")
            _cyan "  Nyx 管理脚本 v${nyx_sh_ver}"
            _cyan "  输入 'nyx help' 查看帮助"
            view_status
            ;;
        s|status)       view_status ;;
        i|info)         view_info ;;
        a|add)          add_config "$2" "$3" ;;
        c|change)       change_config "$2" "$3" ;;
        start)          nyx_start ;;
        stop)           nyx_stop ;;
        restart)        nyx_restart ;;
        log)            view_log ;;
        logerr)         view_logerr ;;
        u|update)
            case $2 in
                core)   update_core ;;
                sh)     update_script ;;
                *)      update_core && update_script ;;
            esac
            ;;
        un|uninstall)   uninstall_nyx ;;
        version|v)      echo "Nyx 管理脚本 v${nyx_sh_ver}" ;;
        h|help|*)       show_help ;;
    esac
}
