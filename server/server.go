package server

import (
	"Bit-Pit/utils"
	"Bit-Pit/web"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"sort"
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

var Tree = &NTree{}

func FillID(id [8]byte, imIHere bool) {
	current := Tree
	for i := 0; i < 8; i++ {
		byteStr := fmt.Sprintf("%02x", id[i])
		if byteStr == "00" {
			continue
		}

		if child, exists := current.children[byteStr]; exists {
			current = child
		} else {
			if imIHere {
				newNode := &NTree{
					Name:     byteStr + " - Im here",
					children: make(map[string]*NTree),
				}
				current.children[byteStr] = newNode
				current = newNode
			} else {
				newNode := &NTree{
					Name:     byteStr,
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
	err = NodeTree.BuildInterface()
	fmt.Printf("Added local interface, ip: %s\n", NodeTree.LocalIPv6.String())
	if err != nil {
		panic(err)
	}
	// Load Web UI
	go handleBroadcast(NodeTree)
	go handleChannelMessage(NodeTree, [2]byte{0x00, 0x58})
	FillID(RootID, true)
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
	FillID(NodeTreeB.LocalUniqueId, true)
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
				psend := buildMessage(2, []byte("hello"))
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
				FillID(srcID, false)
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
