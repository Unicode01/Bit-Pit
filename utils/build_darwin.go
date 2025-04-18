//go:build darwin
// +build darwin

package utils

import (
	"context"
	"fmt"
	"net"
	"os/exec"

	"github.com/songgao/water"
)

func buildLocalInterface(interfaceName string) (*water.Interface, error) {
	ifce, err := water.New(water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: interfaceName, // 自定义接口名称

		},
	})
	return ifce, err
}

func setupInterface(iface *water.Interface, ip string, CIDR *net.IPNet, funcOnReceive func(data []byte), AliasIP string) (context.CancelFunc, error) {
	// macOS 通常使用 BSD 风格的网络配置
	ifaceName := iface.Name()

	// 设置 IPv6 地址
	if AliasIP != "" {
		cmd := exec.Command("sudo", "ifconfig", ifaceName, "inet6", "alias", AliasIP+"/128")
		if output, err := cmd.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("error setting IPv6 alias address: %v\noutput: %s", err, string(output))
		}
	} else {
		cmd := exec.Command("sudo", "ifconfig", ifaceName, "inet6", "add", ip+"/64")
		if output, err := cmd.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("error setting IPv6 address: %v\noutput: %s", err, string(output))
		}
	}

	// 启用接口
	cmd := exec.Command("sudo", "ifconfig", ifaceName, "up")
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("error enabling interface: %v\noutput: %s", err, string(output))
	}

	// 添加 IPv6 路由
	cmd = exec.Command("sudo", "route", "-n", "add", "-inet6", CIDR.String(), "-interface", ifaceName)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("error adding route: %v\noutput: %s", err, string(output))
	}

	// 设置 MTU
	cmd = exec.Command("sudo", "ifconfig", ifaceName, "mtu", "9000")
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("error setting MTU: %v\noutput: %s", err, string(output))
	}

	ctx, cancel := context.WithCancel(context.Background())
	go handlePackets(ctx, iface, funcOnReceive)

	return func() {
		cancel()
		// 清理配置
		exec.Command("sudo", "ifconfig", ifaceName, "inet6", "remove", ip+"/64").Run()
		exec.Command("sudo", "route", "-n", "delete", "-inet6", CIDR.String()).Run()
	}, nil
}
