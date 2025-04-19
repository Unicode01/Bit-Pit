package utils

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/songgao/water"
	"golang.org/x/net/ipv6"
)

var (
	EnableTrafficAddrAlias bool
	InterFace              *water.Interface
	AliasIPv6              net.IP // using to send traffic to local
	Subnet                 *net.IPNet
)

func onPacket(n *NodeTree, data []byte) error {
	// 解析 IPv6 头部
	iheader, err := ipv6.ParseHeader(data)
	if err != nil {
		return err
	}
	srcIP := iheader.Src
	dstIP := iheader.Dst
	// change local to Tree
	// 将本地化的IPv6地址转换为树的IPv6地址
	if EnableTrafficAddrAlias {
		if net.IP.Equal(srcIP, AliasIPv6) { // from AliasIPv6
			// change src IPv6 to local IPv6
			srcIP = n.LocalIPv6
			// change data src IP
			copy(data[8:24], srcIP)
		}
		// err := FillIPv6Checksum(data)
		// if err != nil {
		// 	fmt.Println(err.Error())
		// }
	}
	// 过滤目标子网流量
	if !Subnet.Contains(srcIP) || !Subnet.Contains(dstIP) {
		ThrowError(fmt.Errorf("ignore non-subnet traffic: src: %s -> dst: %s", srcIP, dstIP))
		return fmt.Errorf("ignore non-subnet traffic: src: %s -> dst: %s", srcIP, dstIP)
	}
	// end checking
	// 结束检查 - 此处得到的数据包的srcIP和dstIP已经转换为树的IPv6地址

	// check local settings
	// 开始将树设备的IPv6地址转换为本地IPv6地址(AliasIPv6)
	if EnableTrafficAddrAlias {
		if net.IP.Equal(dstIP, n.LocalIPv6) { // send to local IPv6
			// change dst IPv6 to AliasIPv6
			dstIP = AliasIPv6
			copy(data[24:40], dstIP)
		}
		err := FillIPv6Checksum(data)
		if err != nil {
			fmt.Println(err.Error())
		}
	}
	// end local settings
	// 结束转换 - 此处得到的数据包的srcIP和dstIP已经转换为本地IPv6地址(AliasIPv6)
	// 此处的srcIP必是树IP
	if net.IP.Equal(srcIP, n.LocalIPv6) { // from local node
		InterfaceInfo.DataSent += uint64(len(data))
		InterfaceInfo.PacketSent++
		// transfer this packet to remote node
		// get remote ID
		remoteip := dstIP.To16()
		var remoteID [IDlenth]byte
		copy(remoteID[:], remoteip[8:16])
		err := n.SendTo(remoteID, [2]byte{0xFF, 0xFF}, data)
		if err != nil {
			if isclosedconn(err) {
				return err
			}
			return err
		}
	} else if net.IP.Equal(dstIP, n.LocalIPv6) || net.IP.Equal(dstIP, AliasIPv6) { // from remote node
		// 此处的dstIP有两种情况
		// 1. 目标是本地节点，直接转发
		// 2. 有别名设置,dstIP为AliasIPv6，将数据包转发到本地节点
		InterfaceInfo.DataReceived += uint64(len(data))
		InterfaceInfo.PacketReceived++
		_, err := InterFace.Write(data)
		if err != nil {
			ThrowError(err)
			return err
		}
	}

	return nil
}

// FillIPv6Checksum takes a raw IPv6 packet (header + payload), detects the NextHeader field,
// computes the appropriate transport-layer checksum (TCP, UDP, ICMPv6), and fills it in.
// Supported protocols: TCP (6), UDP (17), ICMPv6 (58).
func FillIPv6Checksum(packet []byte) error {
	const ipv6HeaderLen = 40
	if len(packet) < ipv6HeaderLen {
		return errors.New("packet too short for IPv6 header")
	}

	// 解析基础IPv6头部
	nextHdr := packet[6]
	payloadLen := binary.BigEndian.Uint16(packet[4:6])
	protoStart := ipv6HeaderLen
	extHdrLen := 0

	// 遍历扩展头
Loop:
	for {
		switch nextHdr {
		case 0: // Hop-by-Hop Options
		case 43: // Routing Header
		case 44: // Fragment Header
		case 60: // Destination Options
		case 51: // AH
		case 50: // ESP
			// 处理扩展头
			if protoStart+8 > len(packet) {
				return errors.New("packet too short for extension header")
			}
			// extHdrType := nextHdr
			extHdrDataLen := int(packet[protoStart+1]) * 8 // 扩展头长度单位
			if protoStart+extHdrDataLen > len(packet) {
				return errors.New("extension header exceeds packet length")
			}
			extHdrLen += extHdrDataLen
			nextHdr = packet[protoStart]
			protoStart += extHdrDataLen
		case 6, 17, 58: // 支持传输层协议
			break Loop
		default:
			return fmt.Errorf("unsupported NextHeader: %d", nextHdr)
		}
	}

	// 计算实际传输层长度（减去扩展头长度）
	transportLen := int(payloadLen) - extHdrLen
	if transportLen < 0 {
		return errors.New("invalid transport layer length")
	}

	// 构建伪头部
	sum := checksumIPv6PseudoHeader(
		packet[8:24],  // src
		packet[24:40], // dst
		uint32(transportLen),
		nextHdr,
	)

	// 处理各传输层协议
	switch nextHdr {
	case 6: // TCP
		if protoStart+20 > len(packet) {
			return errors.New("packet too short for TCP header")
		}
		packet[protoStart+16] = 0 // Zero checksum
		packet[protoStart+17] = 0
		sum += checksumBytes(packet[protoStart : protoStart+transportLen])
		csum := finalizeChecksum(sum)
		binary.BigEndian.PutUint16(packet[protoStart+16:protoStart+18], csum)

	case 17: // UDP
		if protoStart+8 > len(packet) {
			return errors.New("packet too short for UDP header")
		}
		udpLen := binary.BigEndian.Uint16(packet[protoStart+4 : protoStart+6])
		if int(udpLen) != transportLen {
			return fmt.Errorf("udp length mismatch: %d vs %d", udpLen, transportLen)
		}
		packet[protoStart+6] = 0 // Zero checksum
		packet[protoStart+7] = 0
		sum += checksumBytes(packet[protoStart : protoStart+transportLen])
		csum := finalizeChecksum(sum)
		if csum == 0 {
			csum = 0xFFFF
		}
		binary.BigEndian.PutUint16(packet[protoStart+6:protoStart+8], csum)

	case 58: // ICMPv6
		if protoStart+4 > len(packet) {
			return errors.New("packet too short for ICMPv6 header")
		}
		packet[protoStart+2] = 0 // Zero checksum
		packet[protoStart+3] = 0
		sum += checksumBytes(packet[protoStart : protoStart+transportLen])
		csum := finalizeChecksum(sum)
		binary.BigEndian.PutUint16(packet[protoStart+2:protoStart+4], csum)

	default:
		return fmt.Errorf("unsupported transport protocol: %d", nextHdr)
	}
	return nil
}

// checksumIPv6PseudoHeader computes the checksum for the IPv6 pseudo-header
func checksumIPv6PseudoHeader(src, dst []byte, length uint32, nextHdr byte) uint32 {
	var sum uint32
	sum += checksumBytes(src)
	sum += checksumBytes(dst)
	// length is 32-bit
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, length)
	sum += checksumBytes(b)
	// 3 bytes zero + NextHeader
	sum += uint32(nextHdr)
	return sum
}

// checksumBytes sums up 16-bit words in b (padding with zero if odd length)
func checksumBytes(b []byte) uint32 {
	var sum uint32
	l := len(b)
	for i := 0; i+1 < l; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if l%2 == 1 {
		sum += uint32(b[l-1]) << 8
	}
	return sum
}

// finalizeChecksum folds 32-bit sum to 16 bits and returns one's complement
func finalizeChecksum(sum uint32) uint16 {
	for (sum >> 16) != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// Build Local Interface for receive local data then transfer to remote node
func BuildInterface(n *NodeTree, subnet string, ctx context.Context, AliasIP string) error {
	ip, CIDR, err := net.ParseCIDR(subnet)
	if err != nil {
		return err
	}
	Subnet = CIDR
	iface, err := buildLocalInterface(fmt.Sprintf("BPTUN-%x", CIDR.IP.To16()))
	n.localInterface = iface
	InterFace = iface
	if err != nil {
		return err
	}
	localIpv6, err := buildLocalIpv6Addr(ip, n.LocalUniqueId)
	if err != nil {
		return err
	}
	n.LocalIPv6 = net.ParseIP(localIpv6)
	if AliasIP != "" {
		EnableTrafficAddrAlias = true
		AliasIPv6 = net.ParseIP(AliasIP)
	}
	_, err = setupInterface(iface, n.LocalIPv6.To16().String(), CIDR,
		func(data []byte) {
			onPacket(n, data)
		},
		AliasIP)
	if err != nil {
		return err
	}

	// Done Init local Interface

	// enter 0xFF 0xFF channel message loop
	go ffffchannelLoop(n, ctx)
	go InterfaceSpeedCalcThread(ctx)
	return nil
}

func ffffchannelLoop(n *NodeTree, ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			data := <-n.LocalInitPoint.dataReadChannel[0xFFFF]
			go onPacket(n, data.Data)
		}
	}
}

func InterfaceSpeedCalcThread(context context.Context) {
	lastSentBytes := InterfaceInfo.DataSent
	lastReceivedBytes := InterfaceInfo.DataReceived
	lastSentPackets := InterfaceInfo.PacketSent
	lastReceivedPackets := InterfaceInfo.PacketReceived
	for {
		time.Sleep(time.Second * 1)
		select {
		case <-context.Done():
			return
		default:
			nowSentBytes := InterfaceInfo.DataSent
			nowReceivedBytes := InterfaceInfo.DataReceived
			nowSentPackets := InterfaceInfo.PacketSent
			nowReceivedPackets := InterfaceInfo.PacketReceived
			durationSecSent := nowSentBytes - lastSentBytes
			durationSecReceived := nowReceivedBytes - lastReceivedBytes
			durationSecSentPackets := nowSentPackets - lastSentPackets
			durationSecReceivedPackets := nowReceivedPackets - lastReceivedPackets
			InterfaceInfo.SendPPS = durationSecSentPackets
			InterfaceInfo.RecvPPS = durationSecReceivedPackets
			InterfaceInfo.SendSpeed = BytesToStr(durationSecSent) + "/s"
			InterfaceInfo.RecvSpeed = BytesToStr(durationSecReceived) + "/s"
			lastSentBytes = nowSentBytes
			lastReceivedBytes = nowReceivedBytes
			lastSentPackets = nowSentPackets
			lastReceivedPackets = nowReceivedPackets
		}
	}
}
