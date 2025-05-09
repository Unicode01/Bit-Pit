package utils

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

func GenerateId() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		fmt.Println(err)
	}
	return strings.ToUpper(fmt.Sprintf("%x", b))
}

func GenerateSelfSignedCert() (certPEM string, keyPEM string, err error) {
	// 1. 生成密钥对
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}

	// 2. 生成证书模板
	serialNumber, _ := rand.Int(rand.Reader, big.NewInt(1<<60)) // 简化序列号生成
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "s1.bp.pool", // 可改为你的域名
		},
		DNSNames:    []string{"s1.bp.pool"}, // 需要匹配的域名
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0), // 1年有效期
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// 3. 自签名证书（同时是颁发者和使用者）
	derBytes, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,              // 自签名
		&privateKey.PublicKey, // 使用自己的公钥
		privateKey,            // 使用自己的私钥签名
	)
	if err != nil {
		return "", "", err
	}

	// 4. PEM编码
	certPEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}))

	keyBytes, _ := x509.MarshalECPrivateKey(privateKey)
	keyPEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	}))

	return certPEM, keyPEM, nil
}

func buildLocalIpv6Addr(IPPrefox net.IP, LocalID [IDlenth]byte) (string, error) {
	// 解析输入的IPv6前缀
	if IPPrefox == nil {
		return "", fmt.Errorf("invalid IPv6 prefix format")
	}

	// 确保是IPv6地址且不是IPv4映射地址
	if IPPrefox.To4() != nil {
		return "", fmt.Errorf("prefix is an IPv4 address")
	}

	ipv6 := IPPrefox.To16()
	if ipv6 == nil {
		return "", fmt.Errorf("prefix is not a valid IPv6 address")
	}

	// 创建新的16字节IPv6地址
	var newAddr [16]byte

	// 前8字节使用Prefix的前8字节
	copy(newAddr[:8], ipv6[:8])

	// 后8字节使用LocalID
	copy(newAddr[8:], LocalID[:])

	// 转换为net.IP类型并格式化为字符串
	return net.IP(newAddr[:]).String(), nil
}

func handlePackets(ctx context.Context, ifce *water.Interface, funcOnReceive func(data []byte)) {
	packet := make([]byte, 9000)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			n, err := ifce.Read(packet)
			if err != nil {
				log.Fatal(err)
			}
			funcOnReceive(packet[:n])
		}
	}
}

func cleanupInterface(ifce *water.Interface) error {

	// 关闭TUN设备
	ifce.Close()

	// 删除网络接口（可能需要重试）
	retries := 3
	for i := 0; i < retries; i++ {
		ifc, err := netlink.LinkByName(ifce.Name())
		if err != nil {
			continue
		}
		err = netlink.LinkDel(ifc)
		if err == nil {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("failed to delete interface after retries")
}

func BytesToStr(n uint64) string {
	units := []struct {
		suffix string
		size   uint64
	}{
		{"EB", 1 << 60},
		{"PB", 1 << 50},
		{"TB", 1 << 40},
		{"GB", 1 << 30},
		{"MB", 1 << 20},
		{"KB", 1 << 10},
		{"B", 1},
	}

	for _, unit := range units {
		if n >= unit.size {
			if unit.suffix == "B" {
				return fmt.Sprintf("%d B", n)
			}
			value := float64(n) / float64(unit.size)
			s := fmt.Sprintf("%.1f", value)
			s = strings.TrimSuffix(s, ".0")
			return fmt.Sprintf("%s %s", s, unit.suffix)
		}
	}

	return "0 B"
}
