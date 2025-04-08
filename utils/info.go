package utils

var (
	InterfaceInfo interfaceDataInfo
	TreeInfo      treeDataInfo
)

type interfaceDataInfo struct {
	dataReceived   uint64
	dataSent       uint64
	packetReceived uint64
	packetSent     uint64
}

type treeDataInfo struct {
	dataReceived      uint64
	dataSent          uint64
	packetReceived    uint64
	packetSent        uint64
	packetRecvDropped uint64
	packetSendDropped uint64
}
