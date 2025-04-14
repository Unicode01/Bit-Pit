//go:build windows
// +build windows

package utils

import (
	"github.com/songgao/water"
)

func buildLocalInterface(interfaceName string) (*water.Interface, error) {
	ifce, err := water.New(water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			InterfaceName: interfaceName, // 自定义接口名称
		},
	})
	return ifce, err
}
