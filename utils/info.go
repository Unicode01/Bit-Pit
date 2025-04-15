package utils

import (
	"encoding/json"
	"fmt"
)

var (
	InterfaceInfo interfaceDataInfo
	TreeInfo      treeDataInfo
	NodeID        [IDlenth]byte
)

type interfaceDataInfo struct {
	DataReceived   uint64 `json:"dataReceived"`
	DataSent       uint64 `json:"dataSent"`
	PacketReceived uint64 `json:"packetReceived"`
	PacketSent     uint64 `json:"packetSent"`
	SendSpeed      string `json:"sendSpeed"`
	RecvSpeed      string `json:"recvSpeed"`
	SendPPS        uint64 `json:"sendPPS"`
	RecvPPS        uint64 `json:"recvPPS"`
}

type treeDataInfo struct {
	DataReceived      uint64 `json:"dataReceived"`
	DataSent          uint64 `json:"dataSent"`
	PacketReceived    uint64 `json:"packetReceived"`
	PacketSent        uint64 `json:"packetSent"`
	PacketRecvDropped uint64 `json:"packetRecvDropped"`
	PacketSendDropped uint64 `json:"packetSendDropped"`
	SendSpeed         string `json:"sendSpeed"`
	RecvSpeed         string `json:"recvSpeed"`
	SendPPS           uint64 `json:"sendPPS"`
	RecvPPS           uint64 `json:"recvPPS"`
}

func Marshal() []byte {
	type combinedDataInfo struct {
		NodeID    string            `json:"nodeId"`
		Interface interfaceDataInfo `json:"interfaceInfo"`
		Tree      treeDataInfo      `json:"treeInfo"`
	}
	combined := combinedDataInfo{
		NodeID:    fmt.Sprintf("%x", NodeID[:]),
		Interface: InterfaceInfo,
		Tree:      TreeInfo,
	}
	result, err := json.Marshal(combined)
	if err != nil {
		result = []byte("{}")
	}
	return result
}
