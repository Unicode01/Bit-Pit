#!/bin/bash
set -e

SERVICE_NAME="bitpit"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
INSTALL_DIR="/etc/bitpit"

echo "==== 卸载 Bit-Pit 开始 ===="

# 停止并禁用服务（如果存在）
if systemctl list-unit-files | grep -q "^${SERVICE_NAME}.service"; then
    echo "停止并禁用服务: ${SERVICE_NAME}"
    sudo systemctl stop ${SERVICE_NAME}
    sudo systemctl disable ${SERVICE_NAME}
else
    echo "未检测到 ${SERVICE_NAME} 服务，跳过停止/禁用步骤。"
fi

# 删除 systemd 服务文件
if [ -f "${SERVICE_FILE}" ]; then
    echo "删除服务文件: ${SERVICE_FILE}"
    sudo rm -f "${SERVICE_FILE}"
else
    echo "未找到服务文件: ${SERVICE_FILE}"
fi

# 重新加载 systemd 配置
sudo systemctl daemon-reload

# 删除安装目录
if [ -d "${INSTALL_DIR}" ]; then
    echo "删除安装目录: ${INSTALL_DIR}"
    sudo rm -rf "${INSTALL_DIR}"
else
    echo "未找到安装目录: ${INSTALL_DIR}"
fi

# 删除可能存在的旧版本二进制文件（如复制到了 /root）
if [ -f "/root/Bit-Pit" ]; then
    echo "删除旧版二进制文件 /root/Bit-Pit"
    sudo rm -f /root/Bit-Pit
fi

echo "==== Bit-Pit 卸载完成 ===="

# 检查是否完全清除
if systemctl status ${SERVICE_NAME} >/dev/null 2>&1; then
    echo "⚠️  警告：服务仍在 systemd 中注册，请检查残留项。"
else
    echo "✅ Bit-Pit 服务已成功移除。"
fi
