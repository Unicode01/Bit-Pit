#!/bin/bash
set -e

SERVICE_NAME="bitpit"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
INSTALL_DIR="/etc/bitpit"
BIN_FILE="${INSTALL_DIR}/Bit-Pit"

echo "==== 开始更新 Bit-Pit ===="

# 检查是否已安装
if [ ! -f "${BIN_FILE}" ]; then
    echo "❌ 未检测到 Bit-Pit 安装文件，请先安装。"
    exit 1
fi

# 读取当前运行参数
if [ ! -f "${SERVICE_FILE}" ]; then
    echo "❌ 未检测到 systemd 服务文件，无法更新。"
    exit 1
fi

echo "正在提取原运行参数..."
EXEC_LINE=$(grep ExecStart "${SERVICE_FILE}")
OLD_PARAMS=$(echo "${EXEC_LINE}" | sed -e "s|ExecStart=${BIN_FILE}||g" | xargs)

echo "当前运行参数: ${OLD_PARAMS}"

# 停止服务
echo "停止服务 ${SERVICE_NAME}..."
sudo systemctl stop ${SERVICE_NAME}

# 检测架构
ARCH=$(uname -m)
DOWNLOAD_FILE=""
case "${ARCH}" in
    i386|i686)
        DOWNLOAD_FILE="Bit-Pit_linux_386.zip"
        ;;
    x86_64)
        DOWNLOAD_FILE="Bit-Pit_linux_amd64.zip"
        ;;
    armv7l)
        DOWNLOAD_FILE="Bit-Pit_linux_arm.zip"
        ;;
    aarch64|arm64)
        DOWNLOAD_FILE="Bit-Pit_linux_arm64.zip"
        ;;
    *)
        echo "未知架构: ${ARCH}"
        exit 1
        ;;
esac

DOWNLOAD_URL="https://github.com/Unicode01/Bit-Pit/releases/latest/download/${DOWNLOAD_FILE}"
TMP_ZIP="/tmp/${DOWNLOAD_FILE}"

echo "下载最新版本: ${DOWNLOAD_URL}"
curl -L -o "${TMP_ZIP}" "${DOWNLOAD_URL}"

# 解压替换
echo "解压并替换旧文件..."
sudo unzip -o "${TMP_ZIP}" -d "${INSTALL_DIR}"
sudo chmod +x "${BIN_FILE}"

# 重启服务
echo "重新启动服务..."
sudo systemctl restart ${SERVICE_NAME}
sleep 3

# 检查服务状态
STATUS=$(systemctl is-active ${SERVICE_NAME})
echo ""
echo "服务状态: ${STATUS}"
sudo journalctl -u ${SERVICE_NAME} -n 5 --no-pager

if [ "${STATUS}" == "active" ]; then
    echo "✅ Bit-Pit 更新并成功重启！"
else
    echo "⚠️ Bit-Pit 更新失败，请检查日志！"
fi
