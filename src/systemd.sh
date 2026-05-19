#!/bin/bash
#=============================================================================
# Nyx 管理脚本 - Systemd 服务模块 (systemd.sh)
#=============================================================================

install_nyx_service() {
    cat > /etc/systemd/system/nyx.service <<EOF
[Unit]
Description=Nyx Transparent Proxy
After=network.target

[Service]
Type=simple
ExecStart=${nyx_core_bin} -config ${nyx_server_conf}
Restart=on-failure
RestartSec=5s
StandardOutput=append:${nyx_log_dir}/server.log
StandardError=append:${nyx_log_dir}/server.log

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable nyx
    _green "Nyx 系统服务已配置"
}
