# Bit-Pit
中文 | [English](https://github.com/Unicode01/Bit-Pit/blob/main/README.md)  
一款轻量级私有路由组网工具  
# 功能
* 将所有服务器连接为树状拓扑结构，自动创建私有IPv6网络实现节点间通信  
* 支持IPv4 IPv6双栈网络环境  
* 可选TLS加密传输通道  
* 提供路由可视化监控界面（开发中）  

# 原理
### 通信架构:
系统需要至少两个节点构成基础服务链：  
1. 上游节点(Upstream)：作为连接枢纽，负责分发子节点信息
2. 下游节点(Downstream)：主动连接上游并同步网络拓扑数据
每个上游节点生成时会分配8字节唯一ID，该ID用于：  
1. 标识节点在拓扑树中的位置  
2. 控制子节点ID分配权限  

#### 建立连接流程:
1. 下游节点发送连接请求，完成Token验证后获取会话凭证(Session)
2. 下游从上游同步子节点ID资源池（含ID范围和掩码信息）
3. 建立反向连接通道
4. 支持多线程连接（通过`-th`参数配置）
*注：根节点的ID由其自身生成，非根节点ID由上级节点分配*

#### 路由机制:
1. 数据路由
    * 发送数据时自动判断目标节点位置：
    * 若目标位于上游或同级：通过上行链路转发
    * 若目标位于下游：直接通过下行链路投递
    * 支持无响应模式(`noneedresp`)，降低通信延迟

2. 广播通信（Channel ID 0x0000）：
    * 全网节点强制接收
    * 不要求响应确认
    * 适用于网络探活等场景

#### 内网通信:
* 私有网段：`fd00::/64`
* IPv6地址生成规则：`fd00::` + LocalID
示例：
  * LocalID 0x01 → `fd00::0100:0:0:0`
  * LocalID 0x01cc → `fd00::01cc:0:0:0`
* 所有通信数据通过BPTUN虚拟接口进行ID封装和路由分发
* 如果配置了AliasIPv6 (`-aliasipv6` 参数) ,则会修改TUN接口的IPv6地址为该参数值,同时启用程序的数据包checksum重写功能,会消耗部分算力  

#### 安全传输
* 采用TLS 1.3加密传输
* 可选使用自定义证书或自签证书

# 监控系统（完成度10%）
* 默认监控端口：监听端口+1
* 当前功能：
  * 实时显示网络拓扑
  * 节点状态监控
* 暂不支持Web配置

# 待完善功能
* 完善路由可视化  
* 自定义证书 [√]  
* 零拷贝传输实现 [-] *由于性能和稳定性，这不会在短时间内实现* 
* 完善自动重连功能 [√]  
* 数据统计 [+]  
* 架构优化与性能提升  
* 智能路由优化  
* NodeTree模块解耦  
* 完善技术文档  

# 命令行参数
```
Usage of ./Bit-Pit:
  -H string
        remote host (default "127.0.0.1")
  -P int
        remote port (default 18808)
  -Root
        root node
  -T    use TLS
  -aliasipv6 string
        alias ipv6 for root node(*this will change TUN interface ipv6 address)
  -cert string
        TLS cert file
  -certkey string
        TLS cert key file
  -debug
        debug mode
  -disabledatacollect
        disable data collect
  -dws
        disable web server
  -l string
        local host (default "::")
  -p int
        local port (default 18808)
  -subnet string
        subnet for root node (default "fd00::/64")
  -t string
        token
  -th int
        Threads for connection (default 1)
  -webtoken string
        web visit token
```

# 示例
## 根节点
```bash
./Bit-Pit -Root -t 123456 -l :: -p 10888
``` 
这条命令会将本节点创建为根节点(Token=123456),并开放本机::10888端口用于接收其他节点的连接请求
运行完成之后会输出本节点的LocalID和在私网内的IPv6地址
### 子节点
```bash
./Bit-Pit -H 100.0.0.0 -P 10888 -t 123456 -l :: -p 10888
``` 
这条命令会将本机连接至 `100.0.0.0:10888` ,并作为次节点的子节点,同时开放本机 `::10888` 端口用于接收其他节点的连接请求(仅在Able2AddChildNode=true时有效)
运行完成之后会输出本节点的LocalID和在私网内的IPv6地址
### 自动安装
```bash
bash <(curl -s https://raw.githubusercontent.com/Unicode01/Bit-Pit/main/scripts/install.sh)
```
### 自动更新
```bash
bash <(curl -s https://raw.githubusercontent.com/Unicode01/Bit-Pit/main/scripts/update.sh)
```
### 自动卸载
```bash
bash <(curl -s https://raw.githubusercontent.com/Unicode01/Bit-Pit/main/scripts/uninstall.sh)
```

# F&Q
* 能提供Windows版本吗?
  * 由于Golang库的限制,目前仅提供Linux版本,若以后更换底层库或移植到Windows,可能会有所改动

* 内网网卡的PPS太低怎么办
  * 建议创建子节点时适当增加线程数,由于基础协议是TCP基础上的,所以并发量不会很高,不适用于pps太高的场景,会导致网络拥塞

* 如何查看路由信息
  * 目前仅支持可视化,可通过浏览器访问 `http://<IP>:<ListenPort+1>` 查看路由信息

* 日志输出了很多连接错误,需要管吗?
  * 正常来说不需要管,连接出错会自动重连,但如果频繁出现连接错误,可以考虑检查下网络环境或防火墙设置
  
* 如果我有这样的一个路由:   
```
         ServerR  
        /       \  
ServerC1      ServerC2  
```
我需要大量使用ServerC1访问ServerC1就需要经过ServerR,那么会增加ServerR的压力同时会增加响应时间,该怎么办  
  * 建议将ServerC2连接上ServerC1,作为ServerC1的子节点,这样ServerC1就不需要经过ServerR,同时ServerC2也会收到ServerC1的响应数据,减少响应时间

# 鸣谢
## 服务器提供商
**[Alice Networks](https://app.alice.ws/)**  
**[云曦幻镜](https://cloud.bffyun.com/)**  
**[Bage Networks](https://www.bagevm.com/)**  