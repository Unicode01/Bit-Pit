//go:build linux
// +build linux

package utils

import "github.com/songgao/water"

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
