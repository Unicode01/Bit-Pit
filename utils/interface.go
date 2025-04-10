package utils

import (
	"fmt"
	"net"

	"github.com/songgao/water"
	"golang.org/x/net/ipv6"
)

var (
	InterFace *water.Interface

	Subnet *net.IPNet
)

func onPacket(n *NodeTree, data []byte) error {
	// 解析 IPv6 头部
	iheader, err := ipv6.ParseHeader(data)
	if err != nil {
		return err
	}
	localIP := n.LocalIPv6
	srcIP := iheader.Src
	dstIP := iheader.Dst
	// 过滤目标子网流量
	if !Subnet.Contains(iheader.Src) || !Subnet.Contains(iheader.Dst) {
		return fmt.Errorf("ignore non-subnet traffic: src: %s -> dst: %s", iheader.Src, iheader.Dst)
	}

	if net.IP.Equal(srcIP, localIP) { // from local node
		InterfaceInfo.DataSent += uint64(len(data))
		InterfaceInfo.PacketSent++
		// transfer this packet to remote node
		// get remote ID
		remoteip := dstIP.To16()
		var remoteID [IDlenth]byte
		copy(remoteID[:], remoteip[8:16])
		err := n.SendTo(remoteID, [2]byte{0xFF, 0xFF}, data)
		if err != nil {
			if err == ErrInvalidSession {
				n.RefreshUpstreamSession()
			} else if isclosedconn(err) {
				return err
			}
			return err
		}
	} else if net.IP.Equal(dstIP, localIP) { // from remote node
		InterfaceInfo.DataReceived += uint64(len(data))
		InterfaceInfo.PacketReceived++
		InterFace.Write(data)
	}

	return nil
}
