#!/bin/bash
set -e

# ===============================================================
# 1. 自动检测并安装依赖（curl, unzip, systemctl）
# ===============================================================
echo "检测并安装依赖..."

# 判断包管理器 (此示例支持 apt 和 yum，可根据实际情况增加其他支持)
if command -v apt-get >/dev/null 2>&1; then
    PACKAGE_MANAGER="apt-get"
    UPDATE_CMD="apt-get update"
    INSTALL_CMD="apt-get install -y"
elif command -v yum >/dev/null 2>&1; then
    PACKAGE_MANAGER="yum"
    UPDATE_CMD="yum makecache"
    INSTALL_CMD="yum install -y"
else
    echo "未找到 apt-get 或 yum，请自行安装 curl 与 unzip。"
    exit 1
fi

echo "使用包管理器: $PACKAGE_MANAGER"
sudo ${UPDATE_CMD}
sudo ${INSTALL_CMD} curl unzip

# 检查 systemctl 是否存在
if ! command -v systemctl >/dev/null 2>&1; then
    echo "未检测到 systemctl，系统可能不支持 systemd，请检查后再试！"
    exit 1
fi

# ===============================================================
# 2. 根据系统架构下载对应的 Bit-Pit 版本，并解压到 /etc/bitpit/
# ===============================================================
echo "检测系统架构..."
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
        echo "未知的架构: ${ARCH}"
        exit 1
        ;;
esac

DOWNLOAD_URL="https://github.com/Unicode01/Bit-Pit/releases/latest/download/${DOWNLOAD_FILE}"
echo "下载文件: ${DOWNLOAD_URL}"
TMP_ZIP="/tmp/${DOWNLOAD_FILE}"
curl -L -o "${TMP_ZIP}" "${DOWNLOAD_URL}"

# 创建目录，并解压到 /etc/bitpit/
INSTALL_DIR="/etc/bitpit"
echo "创建目录 ${INSTALL_DIR} 并解压文件..."
sudo mkdir -p "${INSTALL_DIR}"
sudo unzip -o "${TMP_ZIP}" -d "${INSTALL_DIR}"
sudo chmod +x "${INSTALL_DIR}/Bit-Pit"  # 确保可执行

# ===============================================================
# 3. 交互式询问客户选项
# ===============================================================
echo ""
echo "请根据提示输入相应选项："
read -p "是否为根节点 (yes/no, 默认 no)？ " IS_ROOT
IS_ROOT=${IS_ROOT:-no}

# 初始化参数变量
PARAMS=""

if [ "${IS_ROOT}" == "yes" ] || [ "${IS_ROOT}" == "Yes" ] || [ "${IS_ROOT}" == "y" ] || [ "${IS_ROOT}" == "Y" ]; then
    # 根节点，增加 -Root 参数
    PARAMS="${PARAMS} -Root"


    read -p "请输入本地监听地址 (默认：::): " LOCAL_ADDR
    LOCAL_ADDR=${LOCAL_ADDR:-::}
    read -p "请输入本地监听端口 (默认：10888): " LOCAL_PORT
    LOCAL_PORT=${LOCAL_PORT:-10888}
    PARAMS="${PARAMS} -l ${LOCAL_ADDR} -p ${LOCAL_PORT}"


    read -p "请输入 token 值: " TOKEN
    PARAMS="${PARAMS} -t ${TOKEN}"


    read -p "是否启用 TLS (yes/no, 默认 no)? " ENABLE_TLS
    if [ "${ENABLE_TLS}" == "yes" ] || [ "${ENABLE_TLS}" == "Yes" ]  || [ "${ENABLE_TLS}" == "y" ] || [ "${ENABLE_TLS}" == "Y" ]; then
        PARAMS="${PARAMS} -T"
    fi
    
    read -p "请输入内网IPv6 CIDR (默认：fd00::/64): " IPv6_CIDR
    IPv6_CIDR=${IPv6_CIDR:-fd00::/64}
    PARAMS="${PARAMS} -6 ${IPv6_CIDR}"

else

    read -p "请输入远程地址（host）: " REMOTE_HOST
    read -p "请输入远程端口 (port): " REMOTE_PORT
    PARAMS="${PARAMS} -H ${REMOTE_HOST} -P ${REMOTE_PORT}"


    read -p "请输入本地监听地址 (默认：::): " LOCAL_ADDR
    LOCAL_ADDR=${LOCAL_ADDR:-::}
    read -p "请输入本地监听端口 (默认：10888): " LOCAL_PORT
    LOCAL_PORT=${LOCAL_PORT:-10888}
    PARAMS="${PARAMS} -l ${LOCAL_ADDR} -p ${LOCAL_PORT}"


    read -p "请输入 token 值: " TOKEN
    PARAMS="${PARAMS} -t ${TOKEN}"


    read -p "是否启用 TLS (yes/no, 默认 no)? " ENABLE_TLS
    if [ "${ENABLE_TLS}" == "yes" ] || [ "${ENABLE_TLS}" == "Yes" ] || [ "${ENABLE_TLS}" == "y" ] || [ "${ENABLE_TLS}" == "Y" ]; then
        PARAMS="${PARAMS} -T"
    fi

    read -p "请输入内网IPv6 CIDR (默认：fd00::/64): " IPv6_CIDR
    IPv6_CIDR=${IPv6_CIDR:-fd00::/64}
    PARAMS="${PARAMS} -6 ${IPv6_CIDR}"

fi

echo "运行参数: ${PARAMS}"

# ===============================================================
# 4. 创建 systemd 服务文件
# ===============================================================
echo "正在创建 systemd 服务文件..."

SERVICE_FILE="/etc/systemd/system/bitpit.service"
# 注意：将 WorkingDirectory 与 ExecStart 中的路径更新为 /etc/bitpit,
# 以符合之前的解压目录，也可根据需求修改
sudo bash -c "cat > ${SERVICE_FILE}" <<EOF
[Unit]
Description=Bit-Pit Service
After=network.target nss-lookup.target
Wants=network.target

[Service]
User=root
Group=root
Type=simple
LimitAS=infinity
LimitRSS=infinity
LimitCORE=infinity
LimitNOFILE=999999
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/Bit-Pit${PARAMS}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

echo "服务文件已创建在 ${SERVICE_FILE}"

# ===============================================================
# 5. 启用并设置开机自启服务
# ===============================================================
echo "重新加载 systemd 配置..."
sudo systemctl daemon-reload

echo "启动并启用 Bit-Pit 服务..."
sudo systemctl enable bitpit.service
sudo systemctl restart bitpit.service

# ===============================================================
# 6. 检查服务状态并输出日志末5行
# ===============================================================
sleep 3  # 等待服务启动
SERVICE_STATUS=$(systemctl is-active bitpit.service)
echo ""
echo "服务状态: ${SERVICE_STATUS}"

echo "服务日志（末5行）："
sudo journalctl -u bitpit.service -n 5 --no-pager

echo ""
if [ "${SERVICE_STATUS}" == "active" ]; then
    echo "Bit-Pit 服务已成功启动！"
else
    echo "Bit-Pit 服务启动失败，请检查日志获取详细错误信息。"
fi
