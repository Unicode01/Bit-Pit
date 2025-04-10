package server

import (
	"Bit-Pit/utils"
	"Bit-Pit/web"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

type NTree struct {
	Name     string            `json:"name"`
	children map[string]*NTree `json:"-"`        // 实际存储子节点的映射
	Children []*NTree          `json:"children"` // JSON序列化专用字段
}

// 自定义JSON序列化方法
func (n *NTree) MarshalJSON() ([]byte, error) {
	// 将映射转换为有序切片
	n.prepareForMarshal()
	type Alias NTree
	return json.Marshal(&struct {
		*Alias
	}{
		Alias: (*Alias)(n),
	})
}

// 自定义JSON反序列化方法
func (n *NTree) UnmarshalJSON(data []byte) error {
	type Alias NTree
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(n),
	}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	// 重建映射关系
	n.children = make(map[string]*NTree)
	for _, child := range n.Children {
		n.children[child.Name] = child
	}
	return nil
}

// 序列化前准备：转换映射到切片并排序
func (n *NTree) prepareForMarshal() {
	n.Children = make([]*NTree, 0, len(n.children))

	// 获取有序键列表（按字母顺序排序）
	keys := make([]string, 0, len(n.children))
	for k := range n.children {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// 按排序后的顺序填充切片
	for _, k := range keys {
		child := n.children[k]
		child.prepareForMarshal() // 递归处理子节点
		n.Children = append(n.Children, child)
	}
}

var Tree = &NTree{
	Name:     "root",
	children: make(map[string]*NTree),
}

func FillID(id [8]byte, value string, info string) {
	current := Tree
	for i := 0; i < 8; i++ {
		byteStr := fmt.Sprintf("%02x", id[i])
		nextByteStr := "00"
		if i+1 < len(id) {
			nextByteStr = fmt.Sprintf("%02x", id[i+1])
		}
		if byteStr == "00" {
			break
		}

		// 构造当前节点的Name
		parentPrefix := current.Name[:i*2]           // 父节点的前缀长度为i*2
		newName := parentPrefix + byteStr            // 拼接当前byteStr
		remaining := 16 - len(newName)               // 计算剩余需要填充的长度
		newName += strings.Repeat("00", remaining/2) // 用"00"填充剩余部分

		if child, exists := current.children[byteStr]; exists {
			current = child
		} else {
			if nextByteStr == "00" { // last byte
				newNode := &NTree{
					Name:     newName,
					children: make(map[string]*NTree),
				}
				current.children[byteStr] = newNode
				current = newNode
			} else {
				newNode := &NTree{
					Name:     newName,
					children: make(map[string]*NTree),
				}
				current.children[byteStr] = newNode
				current = newNode
			}
		}
	}
}

func InitAsRoot(Host string, Port int, Token string, RootID [8]byte, TLS bool) {
	NodeTree := utils.NewNodeTree()
	NodeTree.LocalInitPoint.IpAddr = Host
	NodeTree.LocalInitPoint.Port = Port
	NodeTree.LocalInitPoint.NetWork = "tcp"
	NodeTree.LocalInitPoint.Token = Token
	NodeTree.LocalUniqueId = RootID
	NodeTree.LocalIdMask = 8
	NodeTree.ChildIDEndMask = 16
	NodeTree.LocalInitPoint.SetTLSConfig(TLS, "", "", &tls.Config{})
	_, err := NodeTree.InitLocalServerNode()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Success to init local server node\n")
	utils.NodeID = NodeTree.LocalUniqueId
	err = NodeTree.BuildInterface()
	fmt.Printf("Added local interface, ip: %s\n", NodeTree.LocalIPv6.String())
	if err != nil {
		panic(err)
	}
	// Load Web UI
	go handleBroadcast(NodeTree)
	go handleChannelMessage(NodeTree, [2]byte{0x00, 0x58})
	FillID(RootID, NodeTree.LocalIPv6.String(), string(utils.Marshal()))
	go func() {
		for {
			SendGetInfoBroadcast(NodeTree)
			time.Sleep(10 * time.Second)
		}
	}()
	web.InitWebServer(Port+1, Token)
}

func InitAsChild(Host string, LocalHost string, Port int, Token string, TLS bool, threads int) {
	NodeTreeB := utils.NewNodeTree()
	Remote := utils.NewServerInitPoint()
	Remote.IpAddr = Host
	Remote.Port = Port
	Remote.NetWork = "tcp"
	Remote.Token = Token
	Remote.SetTLSConfig(TLS, "", "", &tls.Config{InsecureSkipVerify: true})
	err := NodeTreeB.AppendToNode(Remote, threads)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Local Unique ID: %x\n", NodeTreeB.LocalUniqueId)
	utils.NodeID = NodeTreeB.LocalUniqueId
	err = NodeTreeB.BuildInterface()
	fmt.Printf("Added local interface, ip: %s\n", NodeTreeB.LocalIPv6.String())
	if err != nil {
		panic(err)
	}
	if NodeTreeB.Able2AddChildNode {
		NodeTreeB.LocalInitPoint.IpAddr = LocalHost
		NodeTreeB.LocalInitPoint.Port = Remote.Port
		NodeTreeB.LocalInitPoint.NetWork = "tcp"
		NodeTreeB.LocalInitPoint.Token = Token
		NodeTreeB.LocalInitPoint.SetTLSConfig(TLS, "", "", &tls.Config{InsecureSkipVerify: true})
		NodeTreeB.InitLocalServerNode()
	}
	go handleBroadcast(NodeTreeB)
	go handleChannelMessage(NodeTreeB, [2]byte{0x00, 0x58})
	FillID(NodeTreeB.LocalUniqueId, NodeTreeB.LocalIPv6.String(), string(utils.Marshal()))
	go func() {
		for {
			SendGetInfoBroadcast(NodeTreeB)
			time.Sleep(10 * time.Second)
		}
	}()
	web.InitWebServer(Port+1, Token)
	// if err != nil {
	// 	panic(err)
	// }
}

func SendGetInfoBroadcast(n *utils.NodeTree) {
	// send get info broadcast
	psend := buildMessage(1, []byte{})
	n.SendTo([8]byte{}, [2]byte{}, psend)
}

func handleBroadcast(n *utils.NodeTree) {
	for {
		messagetype, data, srcID := n.ReadFrom([2]byte{})
		if messagetype == utils.MessageTypeBroadcast {
			// process broadcast message
			method, _ := processMessage(data)
			if method == 1 { //get info
				psend := buildMessage(2, utils.Marshal())
				n.SendTo(srcID, [2]byte{0x00, 0x58}, psend)
			}
		}
	}
}

func handleChannelMessage(n *utils.NodeTree, channelID [2]byte) {
	for {
		messagetype, data, srcID := n.ReadFrom(channelID)
		if messagetype == utils.MessageTypeUnicast {
			// process channel message
			method, _ := processMessage(data)
			if method == 2 { // receive info
				FillID(srcID, "", string(data))
				jsonData, err := Tree.MarshalJSON()
				if err != nil {
					jsonData = []byte("{}")
				}
				web.Data = jsonData
			}
		}
	}
}

func processMessage(data []byte) (method int, params []byte) {
	// data structure:
	// 1st byte: method
	// other bytes: parameter
	method = int(data[0])
	params = data[1:]
	return method, params
}

func buildMessage(method int, params []byte) []byte {
	// data structure:
	// 1st byte: method
	// other bytes: parameter
	data := make([]byte, 1+len(params))
	data[0] = byte(method)
	copy(data[1:], params)
	return data
}
