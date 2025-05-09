package utils

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

const (
	//METHOD CODES(0-999)
	pMethodOK             = uint32(0) // Handle Done
	pMethodVerify         = uint32(1) // Handle Done
	pMethodReverseConn    = uint32(2) // Handle Done
	pMethodPullNodeInfo   = uint32(3)
	pMethodAppendNode     = uint32(4) // Handle Done
	pMethodRemoveNode     = uint32(5) // Handle Done
	pMethodTransferTo     = uint32(6) // Handle Done
	pMethodSessionRefresh = uint32(7)
	pMethodBroadcast      = uint32(255) // Handle Done

	//ERROR CODES(1000-1999)
	pMethodErrorDefault = uint32(1000)

	IDlenth = 8 //Local ID length
)

var (
	//ERROR INFO
	ErrPacketTooShort          = errors.New("packet too short")
	ErrInvalidMethod           = errors.New("invalid method")
	ErrInvalidData             = errors.New("invalid data")
	ErrInvalidSession          = errors.New("invalid session")
	ErrInvalidPacket           = errors.New("invalid packet")
	ErrInvalidToken            = errors.New("invalid token")
	ErrInvalidNodeID           = errors.New("invalid node id")
	ErrSendToSelf              = errors.New("can not send to self")
	ErrDownstreamNoReverseConn = errors.New("downstream no reverse conn")
	ErrUpstreamNoConn          = errors.New("upstream no conn")
	ErrNoUpstream              = errors.New("no upstream")
	ErrDatalenTooLong          = errors.New("data len too long")
	ErrFindingDownstream       = errors.New("no downstream found")
)

func GeneratePacket(method uint32, data []byte) ([]byte, error) {
	p := make([]byte, 4+4+len(data))
	binary.LittleEndian.PutUint32(p[0:4], method)
	lenth := uint32(len(data))
	binary.LittleEndian.PutUint32(p[4:8], lenth)
	copy(p[8:], data)
	return p, nil
}

func ResolvPacket(data []byte) (method uint32, resolvedData []byte, realDataLenth uint32, err error) {
	if len(data) < 8 {
		return 0, nil, 0, ErrPacketTooShort
	}
	method = binary.LittleEndian.Uint32(data[0:4])
	lenth := binary.LittleEndian.Uint32(data[4:8])
	if len(data) < 8+int(lenth) {
		return 0, nil, 0, ErrPacketTooShort
	}
	realDataLenth = lenth + 8
	return method, data[8 : 8+lenth], realDataLenth, nil
}

//
// Packet interface
//

type QueryPacket interface {
	Marshal() ([]byte, error)
	Unmarshal(data []byte) error
}

type RespPacket interface {
	Marshal() ([]byte, error)
	Unmarshal(data []byte) error
}

//
// QVerifyPacket
//

type QVerifyPacket struct {
	Token      string   // input Token(raw)
	Token256   [32]byte // return Token(sha256)
	OldSession [8]byte  // input OldSession(raw) it will be used if Old Session is valid
}

func (p *QVerifyPacket) Marshal() ([]byte, error) {
	p.Token256 = sha256.Sum256([]byte(p.Token))
	verifyP := make([]byte, len(p.Token256)+8)
	copy(verifyP[:32], p.Token256[:])
	p.Token = ""
	copy(verifyP[32:40], p.OldSession[:])
	return GeneratePacket(pMethodVerify, verifyP)
}

func (p *QVerifyPacket) Unmarshal(data []byte) error {
	if len(data) < 32+8 {
		return ErrInvalidData
	}
	copy(p.Token256[:], data[:32])
	copy(p.OldSession[:], data[32:32+8])
	return nil
}

//
// RSessionPacket
//

type RSessionPacket struct {
	SessionID    [8]byte
	TTL          uint32
	TimeoutStamp uint64
}

func (p *RSessionPacket) Marshal() ([]byte, error) {
	sessionP := make([]byte, 8+4+8)
	copy(sessionP[0:8], p.SessionID[:])
	binary.LittleEndian.PutUint32(sessionP[8:12], p.TTL)
	binary.LittleEndian.PutUint64(sessionP[12:20], p.TimeoutStamp)
	return GeneratePacket(pMethodOK, sessionP)
}

func (p *RSessionPacket) Unmarshal(data []byte) error {
	if len(data) < 8+4+8 {
		return ErrInvalidData
	}
	copy(p.SessionID[:], data[0:8])
	p.TTL = binary.LittleEndian.Uint32(data[8:12])
	p.TimeoutStamp = binary.LittleEndian.Uint64(data[12:20])
	return nil
}

//
// QAppendNodePacket
// Query for AppendNodePacket(child node)
//

type QAppendNodePacket struct {
	SessionID [8]byte // Session ID for Query
}

func (p *QAppendNodePacket) Marshal() ([]byte, error) {
	appendP := make([]byte, 8)
	copy(appendP, p.SessionID[:])
	return GeneratePacket(pMethodAppendNode, appendP)
}

func (p *QAppendNodePacket) Unmarshal(data []byte) error {
	if len(data) < 8 {
		return ErrInvalidData
	}
	copy(p.SessionID[:], data[0:8])
	return nil
}

//
// RAppendNodePacket
// Response for QAppendNodePacket(child node)
//

type RAppendNodePacket struct {
	UpstreamUniqueID [IDlenth]byte // Upstream Unique ID
	ChildNodeID      [IDlenth]byte // Child Node ID
	ChildNodeMask    uint32        // Child Node Mask
}

func (p *RAppendNodePacket) Marshal() ([]byte, error) {
	appendP := make([]byte, IDlenth+IDlenth+4)
	copy(appendP[0:IDlenth], p.UpstreamUniqueID[:])
	copy(appendP[IDlenth:IDlenth+IDlenth], p.ChildNodeID[:])
	binary.LittleEndian.PutUint32(appendP[IDlenth+IDlenth:IDlenth+IDlenth+4], p.ChildNodeMask)
	return GeneratePacket(pMethodOK, appendP)
}

func (p *RAppendNodePacket) Unmarshal(data []byte) error {
	if len(data) < IDlenth+4 {
		return ErrInvalidData
	}
	copy(p.UpstreamUniqueID[:], data[0:IDlenth])
	copy(p.ChildNodeID[:], data[IDlenth:IDlenth+IDlenth])
	p.ChildNodeMask = binary.LittleEndian.Uint32(data[IDlenth+IDlenth : IDlenth+IDlenth+4])
	return nil
}

//
// QRemoveNodePacket
// Query for RemoveNodePacket(child node)
//

type QRemoveNodePacket struct {
	SessionID [8]byte // Session ID for Query
	NodeID    [IDlenth]byte
}

func (p *QRemoveNodePacket) Marshal() ([]byte, error) {
	removeP := make([]byte, 8+IDlenth)
	copy(removeP[0:8], p.SessionID[:])
	copy(removeP[8:8+IDlenth], p.NodeID[:])
	return GeneratePacket(pMethodRemoveNode, removeP)
}

func (p *QRemoveNodePacket) Unmarshal(data []byte) error {
	if len(data) < 8+IDlenth {
		return ErrInvalidData
	}
	copy(p.SessionID[:], data[0:8])
	copy(p.NodeID[:], data[8:8+IDlenth])
	return nil
}

//
// RRemoveNodePacket
// Response for QRemoveNodePacket(child node)
//

type RRemoveNodePacket struct {
}

func (p *RRemoveNodePacket) Marshal() ([]byte, error) {
	return GeneratePacket(pMethodOK, nil)
}

func (p *RRemoveNodePacket) Unmarshal(data []byte) error {
	return nil
}

//
// QbroadcastPacket
// Query for broadcastPacket(child node)
//

type QBroadcastPacket struct {
	SessionID [8]byte // Session ID for Query
	Data      []byte
	TTL       uint32
	SrcNodeID [IDlenth]byte // Source Node ID
}

func (p *QBroadcastPacket) Marshal() ([]byte, error) {
	broadcastP := make([]byte, 8+4+4+len(p.Data)+IDlenth)
	copy(broadcastP[0:8], p.SessionID[:])
	binary.LittleEndian.PutUint32(broadcastP[8:12], p.TTL)
	binary.LittleEndian.PutUint32(broadcastP[12:16], uint32(len(p.Data)))
	copy(broadcastP[16:16+len(p.Data)], p.Data)
	copy(broadcastP[16+len(p.Data):], p.SrcNodeID[:])
	return GeneratePacket(pMethodBroadcast, broadcastP)
}

func (p *QBroadcastPacket) Unmarshal(data []byte) error {
	if len(data) < 8+4+4+IDlenth {
		return ErrInvalidData
	}
	copy(p.SessionID[:], data[0:8])
	p.TTL = binary.LittleEndian.Uint32(data[8:12])
	lenth := binary.LittleEndian.Uint32(data[12:16])
	if len(data) < 8+4+4+IDlenth+int(lenth) {
		return ErrInvalidData
	}
	p.Data = data[16 : 16+lenth]
	copy(p.SrcNodeID[:], data[16+lenth:16+lenth+IDlenth])
	return nil
}

//
// QReverseConnPacket
// Query for ReverseConnPacket(child node)
//

type QReverseConnPacket struct {
	Session  [8]byte // Session ID for Query
	UniqueID [IDlenth]byte
}

func (p *QReverseConnPacket) Marshal() ([]byte, error) {
	reverseP := make([]byte, 8+IDlenth)
	copy(reverseP[0:8], p.Session[:])
	copy(reverseP[8:8+IDlenth], p.UniqueID[:])
	return GeneratePacket(pMethodReverseConn, reverseP)
}

func (p *QReverseConnPacket) Unmarshal(data []byte) error {
	if len(data) < 8+IDlenth {
		return ErrInvalidData
	}
	copy(p.Session[:], data[0:8])
	copy(p.UniqueID[:], data[8:8+IDlenth])
	return nil
}

//
// QDataTransferTo
// Query for data transfer
//
// In order to process big data, this methods wouln't use GeneratePacket(Using zero copy),

type QDataTransferTo struct {
	SessionID [8]byte       // Session ID for Query
	SrcNodeID [IDlenth]byte // Source Node ID
	NoResp    bool
	Data      []byte
	DstNodeID [IDlenth]byte           // Destination Node ID
	ChannelID [ChannelIDMaxLenth]byte // like...Port?
	ExtraData []byte                  // Extra data for specific protocol
}

func (p *QDataTransferTo) Marshal() ([]byte, error) {
	// 8 bytes header*
	// 8 bytes session ID
	// 8 bytes src node ID
	// 8 bytes dst node ID
	// 2 bytes channel ID
	// 4 bytes datalen
	// 4 bytes extralen
	// 1 byte noResp
	// data
	// extra data

	// Calculate total length
	totalLen := 4 + 4 //header length
	// 4 bytes method code
	// 4 bytes data length
	totalLen += 8 + IDlenth*2 + ChannelIDMaxLenth + 8 + 1 + len(p.Data) + len(p.ExtraData)
	transferP := make([]byte, totalLen)
	// generate header
	binary.LittleEndian.PutUint32(transferP[0:4], pMethodTransferTo)
	lenth := uint32((8 + IDlenth*2 + ChannelIDMaxLenth + 8 + len(p.Data) + len(p.ExtraData) + 1))
	binary.LittleEndian.PutUint32(transferP[4:8], lenth)

	// Copy fixed-size fields
	offset := 8
	copy(transferP[offset:], p.SessionID[:])
	offset += 8
	copy(transferP[offset:], p.SrcNodeID[:])
	offset += IDlenth
	copy(transferP[offset:], p.DstNodeID[:])
	offset += IDlenth
	copy(transferP[offset:], p.ChannelID[:])
	offset += ChannelIDMaxLenth

	// Write data lengths
	binary.LittleEndian.PutUint32(transferP[offset:], uint32(len(p.Data)))
	offset += 4
	binary.LittleEndian.PutUint32(transferP[offset:], uint32(len(p.ExtraData)))
	offset += 4

	var noRespByte byte
	if p.NoResp {
		noRespByte = 1
	} else {
		noRespByte = 0
	}
	copy(transferP[offset:], []byte{noRespByte})
	offset += 1

	// Copy variable-size fields
	copy(transferP[offset:], p.Data)
	offset += len(p.Data)
	copy(transferP[offset:], p.ExtraData)
	offset += len(p.ExtraData)

	return transferP, nil
}

func (p *QDataTransferTo) Unmarshal(data []byte) error {
	// 8 bytes session ID
	// 8 bytes src node ID
	// 8 bytes dst node ID
	// 2 bytes channel ID
	// 4 bytes datalen
	// 4 bytes extralen
	// 1 byte noResp
	// data
	// extra data

	// Check minimum length
	if len(data) < 8+IDlenth*2+ChannelIDMaxLenth+8+1 {
		return ErrInvalidData
	}

	// Read fixed-size fields
	offset := 0
	copy(p.SessionID[:], data[offset:offset+8]) // 8
	offset += 8
	copy(p.SrcNodeID[:], data[offset:offset+IDlenth]) // 8
	offset += IDlenth
	copy(p.DstNodeID[:], data[offset:offset+IDlenth]) // 8
	offset += IDlenth
	copy(p.ChannelID[:], data[offset:offset+ChannelIDMaxLenth]) // 2
	offset += ChannelIDMaxLenth

	// Read data lengths
	dataLen := binary.LittleEndian.Uint32(data[offset:]) // 4
	offset += 4
	extraDataLen := binary.LittleEndian.Uint32(data[offset:]) // 4
	offset += 4

	p.NoResp = bytes.Equal(data[offset:offset+1], []byte{1})
	offset += 1
	// Check total length
	if len(data) < offset+int(dataLen)+int(extraDataLen) {
		return ErrInvalidData
	}

	// Read variable-size fields
	p.Data = data[offset : offset+int(dataLen)]
	offset += int(dataLen)
	p.ExtraData = data[offset : offset+int(extraDataLen)]
	offset += int(extraDataLen)

	return nil
}

// return total length of packet
func (p *QDataTransferTo) Len() int {
	// 8 bytes header*
	// 8 bytes session ID
	// 8 bytes src node ID
	// 8 bytes dst node ID
	// 2 bytes channel ID
	// 4 bytes datalen
	// 4 bytes extralen
	// 1 byte noResp
	// data
	// extra data
	return 8 + IDlenth*2 + ChannelIDMaxLenth + 8 + 4 + 4 + 1 + len(p.Data) + len(p.ExtraData)
}

func (p *QDataTransferTo) Send(sendFunction func(data []byte) (int, error)) error {
	// 8 bytes header*
	// 8 bytes session ID
	// 8 bytes src node ID
	// 8 bytes dst node ID
	// 2 bytes channel ID
	// 4 bytes datalen
	// 4 bytes extralen
	// 1 byte noResp
	// data
	// extra data
	header := make([]byte, 8+8+IDlenth*2+ChannelIDMaxLenth+4+4+1)
	offset := 0
	// generate header
	binary.LittleEndian.PutUint32(header[0:4], pMethodTransferTo)
	lenth := uint32((8 + IDlenth*2 + ChannelIDMaxLenth + 4 + 4 + 1 + len(p.Data) + len(p.ExtraData)))
	binary.LittleEndian.PutUint32(header[4:8], lenth)
	offset += 8
	// Copy fixed-size fields
	copy(header[offset:], p.SessionID[:])
	offset += 8
	copy(header[offset:], p.SrcNodeID[:])
	offset += IDlenth
	copy(header[offset:], p.DstNodeID[:])
	offset += IDlenth
	copy(header[offset:], p.ChannelID[:])
	offset += ChannelIDMaxLenth
	// Write data lengths
	binary.LittleEndian.PutUint32(header[offset:], uint32(len(p.Data)))
	offset += 4
	binary.LittleEndian.PutUint32(header[offset:], uint32(len(p.ExtraData)))
	offset += 4
	var noRespByte byte
	if p.NoResp {
		noRespByte = 1
	} else {
		noRespByte = 0
	}
	copy(header[offset:], []byte{noRespByte})
	// Done header
	// send header
	sentBytes := 0
	for sentBytes < len(header) {
		n, err := sendFunction(header[sentBytes:])
		if err != nil {
			return err
		}
		sentBytes += n
	}
	// Send data
	sentBytes = 0
	for sentBytes < len(p.Data) {
		n, err := sendFunction(p.Data[sentBytes:])
		if err != nil {
			return err
		}
		sentBytes += n
	}
	// Send extra data
	sentBytes = 0
	for sentBytes < len(p.ExtraData) {
		n, err := sendFunction(p.ExtraData[sentBytes:])
		if err != nil {
			return err
		}
		sentBytes += n
	}
	return nil
}

//
// QSessionRefreshPacket
// Upstream Send this packet to child to notify force refresh upstream session
//

type QSessionRefreshPacket struct {
}

func (p *QSessionRefreshPacket) Marshal() ([]byte, error) {
	return GeneratePacket(pMethodSessionRefresh, nil)
}

func (p *QSessionRefreshPacket) Unmarshal(data []byte) error {
	return nil
}

