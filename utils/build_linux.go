//go:build linux
// +build linux

package utils

import (
	"context"
	"fmt"
	"net"

	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

func buildLocalInterface(interfaceName string) (*water.Interface, error) {
	ifce, err := water.New(water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name:    interfaceName, // 自定义接口名称
			Persist: false,         // 关闭持久化

		},
	})
	return ifce, err
}

func setupInterface(iface *water.Interface, ip string, CIDR *net.IPNet, funcOnReceive func(data []byte), AliasIP string) (cancle context.CancelFunc, err error) {
	link, err := netlink.LinkByName(iface.Name())
	if err != nil {
		return nil, fmt.Errorf("error getting link:%s", err)
	}
	// set IPv6 address

	if AliasIP != "" {
		addr, err := netlink.ParseAddr(AliasIP + "/128")
		if err != nil {
			return nil, fmt.Errorf("error parsing IP address:%s", err)
		}
		err = netlink.AddrAdd(link, addr)
		if err != nil {
			return nil, fmt.Errorf("error parsing IP address:%s", err)
		}
	} else {
		addr, err := netlink.ParseAddr(ip + "/64")
		if err != nil {
			return nil, fmt.Errorf("error parsing IP address:%s", err)
		}
		err = netlink.AddrAdd(link, addr)
		if err != nil {
			return nil, fmt.Errorf("error adding IP address:%s", err)
		}
	}
	// start up the interface
	err = netlink.LinkSetUp(link)
	if err != nil {
		return nil, fmt.Errorf("error setting up interface:%s", err)
	}

	// set IPv6 route
	route := &netlink.Route{
		Dst:       CIDR,
		LinkIndex: link.Attrs().Index,
	}
	if err = netlink.RouteAdd(route); err != nil {
		return nil, fmt.Errorf("error adding route:%s", err)
	}

	// Set MTU
	err = netlink.LinkSetMTU(link, 9000)
	if err != nil {
		return nil, fmt.Errorf("error setting MTU:%s", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go handlePackets(ctx, iface, funcOnReceive)
	return cancel, nil
}
