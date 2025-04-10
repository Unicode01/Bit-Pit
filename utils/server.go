package utils

//	2025.3.17	Unicode
//		_____________						_____________
//		|			|						|			|
//		|			|						|			|
//		|			|						|			|
//		|			|						|			|
//		|			|						|			|
//		|			|						|			|
//		|			|						|			|
//		|			|						|			|
//		|			|						|			|
//		|___________|						|___________|
//						_______________
//

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"math/big"
	mathrand "math/rand"

	"github.com/songgao/water"
)

const (
	MaskAddNum = 8
	// if your MaskAddNum =8 , IDlenth =8
	// it means the max mask is 8*8 = 64
	// the max layer of the tree is 64/8 = 8
	// means the max depth of root node = 8
	// struct:
	//               R(L1)
	// 	 	      /       \
	//        L2            L2
	//      /   | \       /   |  \
	//     L3   L3  ...  L3   L3  ...
	//     / 	.................
	//	 L4    ................
	//	 /
	// L5
	//	.
	// 	.
	//  .
	// L8  --max
	// NO CHILD CAN BE ADDED AFTER THIS NODE
	// Each node which can add child node has a range of ID which can be used to generate child node
	// if the mask = 16,child mask = 24
	// means this node can generate 2^(24-16)-1 child nodes , -1 (not include self)

	DefaultSessionTTL     = 1000_000_000   //1000 000 000 methods
	DefaultBroadcastTTL   = 32             //32 layers
	DefaultSessionTimeout = 24 * time.Hour //24 hours

	ChannelIDMaxLenth = 2 // 2 bytes

	MessageTypeUnicast   = 0
	MessageTypeBroadcast = 1

	PacketBuffer = 4096 //Byte Max packet size (one time read)

	AutoReconnect     = true // if true, auto reconnect when connection lost
	MaxReconnectRetry = 3    // max retry times when connection lost
)

type Message struct {
	MessageType int
	Data        []byte
	SrcID       [IDlenth]byte
}

type TLSSettings struct {
	Enabled   bool
	Cert      string
	Key       string
	TLSConfig *tls.Config
}

type connection struct {
	connectionType      int // 1 for TCP/UDP,2 for TLS
	rawConn             []net.Conn
	reverseConn         []net.Conn
	currentConn         int
	clientMessageLocker []*sync.Mutex // locker for message to upstream
	reverseWriteLock    []*sync.Mutex
	tlsConn             []*tls.Conn
	currentReverseConn  int
	rawListener         net.Listener
}

type ServerInitPoint struct {
	IpAddr          string
	Port            int
	NetWork         string
	Token           string
	Err             error
	conn            *connection
	tlsSettings     *TLSSettings
	dataReadChannel []chan Message
}

func (s *ServerInitPoint) InitDataChan() {
	// made local read & write channel
	s.dataReadChannel = make([]chan Message, MaxNumbers(ChannelIDMaxLenth).Int64())
	for i := range s.dataReadChannel {
		s.dataReadChannel[i] = make(chan Message, 1)
	}
}

func (s *ServerInitPoint) SetTLSConfig(Enabled bool, Cert, Key string, TLSConfig *tls.Config) {
	s.tlsSettings.Enabled = Enabled
	s.tlsSettings.Cert = Cert
	s.tlsSettings.Key = Key
	s.tlsSettings.TLSConfig = TLSConfig
}

func NewServerInitPoint() *ServerInitPoint {
	sip := &ServerInitPoint{
		IpAddr:      "",
		Port:        0,
		NetWork:     "tcp",
		Token:       "",
		conn:        &connection{},
		tlsSettings: &TLSSettings{Enabled: false},
	}
	sip.InitDataChan()
	return sip
}

func (s *ServerInitPoint) String() string {
	b, err := json.Marshal(s)
	if err != nil {
		s.Err = err
		return ""
	}
	return string(b)
}

func (s *ServerInitPoint) Destroy() error {
	for i := range s.conn.rawConn {
		err := s.conn.rawConn[i].Close()
		if err != nil {
			ThrowError(err)
		}
	}
	for i := range s.conn.reverseConn {
		err := s.conn.reverseConn[i].Close()
		if err != nil {
			ThrowError(err)
		}
	}
	s.conn.tlsConn = nil
	s.conn.rawConn = nil
	s.conn.clientMessageLocker = nil
	s.conn.reverseWriteLock = nil
	s.conn.reverseConn = nil
	s.conn.currentConn = 0
	s.conn.currentReverseConn = 0
	return nil
}

type Session struct {
	SessionID    [8]byte
	UniqueID     [IDlenth]byte
	TTL          uint32
	TimeoutStamp uint64
}

type NodeTree struct {
	LocalInitPoint  *ServerInitPoint
	RemoteInitPoint *ServerInitPoint
	// get on secound packet
	LocalUniqueId [IDlenth]byte //id - used to be the flag and route direction!important
	LocalIdMask   uint32        //mask
	// get on secound packet

	// Generate After secound packet
	ChildIDEndMask uint32 //range
	// mask    -  range
	//   0     -  8*IDlenth
	Able2AddChildNode bool // if true, can add child node
	generateIDLock    sync.Mutex

	// Interface for data transfer
	localInterface *water.Interface
	LocalIPv6      net.IP

	Id4Session        sync.Map // save Unique ID to Session
	SessionMap        sync.Map // save session -> Session(type)
	UpstreamSessionID *Session
	UpstreamUniqueID  [IDlenth]byte //id - used to be the flag and route direction!important
	Downstream        sync.Map      // save ChildID -> ServerInitPoint
	Err               error
}

func NewNodeTree() *NodeTree {
	n := &NodeTree{
		LocalInitPoint:  NewServerInitPoint(),
		RemoteInitPoint: NewServerInitPoint(),
	}
	go n.signalEvent()
	return n
}

// this func is used to build local node server Listener
// return a context.Context object to control the message loop thread
func (n *NodeTree) InitLocalServerNode() (context.Context, error) {
	var err error
	// create local raw server
	n.LocalInitPoint.conn.connectionType = 1 //default is 1 for TCP/UDP
	n.Able2AddChildNode = true
	n.LocalInitPoint.conn.rawListener, err = net.Listen(n.LocalInitPoint.NetWork, net.JoinHostPort(n.LocalInitPoint.IpAddr, fmt.Sprintf("%d", n.LocalInitPoint.Port)))

	if err != nil {
		return nil, err
	}
	// create local TLS settings
	if n.LocalInitPoint.tlsSettings.Enabled {
		if n.LocalInitPoint.tlsSettings.Cert == "" || n.LocalInitPoint.tlsSettings.Key == "" {
			n.LocalInitPoint.tlsSettings.Cert, n.LocalInitPoint.tlsSettings.Key, err = GenerateSelfSignedCert()
			if err != nil {
				return nil, err
			}
		}
		cert, err := tls.X509KeyPair([]byte(n.LocalInitPoint.tlsSettings.Cert), []byte(n.LocalInitPoint.tlsSettings.Key))
		if err != nil {
			return nil, err
		}
		n.LocalInitPoint.tlsSettings.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
	}
	ctx := context.Background()
	// create message loop thread
	go n.serverLoop(ctx)
	return ctx, nil
}

func (n *NodeTree) serverLoop(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("server loop stopped")
		default:
			conn, err := n.LocalInitPoint.conn.rawListener.Accept()
			if err != nil {
				return err
			}
			go n.handleConnection(ctx, conn)
		}
	}
}

func (n *NodeTree) handleConnection(ctx context.Context, conn net.Conn) error {
	keepAlive := false
	defer func() {
		if !keepAlive {
			conn.Close()
		}
	}()
	if n.LocalInitPoint.tlsSettings.Enabled {
		// upgrade to TLS connection
		tlsConn := tls.Server(conn, n.LocalInitPoint.tlsSettings.TLSConfig)
		err := tlsConn.Handshake()
		if err != nil {
			return err
		}
		conn = tlsConn
	}
	// enter message loop
	var packet []byte
	newpacket := make([]byte, PacketBuffer) // buffer
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("message loop stopped")
		default:
			// read packet
			num, err := conn.Read(newpacket)
			// data info log
			TreeInfo.DataReceived += uint64(num)
			TreeInfo.PacketReceived++
			if err != nil {
				ThrowError(err)
				if isclosedconn(err) {
					return err
				}
			}
			packet = append(packet, newpacket[:num]...)
			for {
				method, data, realdatalenth, err := ResolvPacket(packet)
				if err != nil {
					if err == ErrPacketTooShort {
						break
					}
					ThrowError(err)
					break // 其他错误跳出处理循环
				}
				if realdatalenth > 32_000 { // 32KB
					// drop packet
					TreeInfo.PacketRecvDropped += 1
					packet = nil
					break
				}
				packet = packet[realdatalenth:]
				switch method {
				case pMethodVerify:
					// handle verify packet
					go func() {
						err = n.handleVerifyPacket(conn, data)
						if err != nil {
							ThrowError(err)
						}
					}()
				case pMethodAppendNode:
					// handle append node packet
					go func() {
						err = n.handleAppendNodePacket(conn, data)
						if err != nil {
							ThrowError(err)
						}
					}()
				case pMethodBroadcast:
					// handle broadcast packet
					go func() {
						err = n.handleBroadcastPacket(conn, data)
						if err != nil {
							ThrowError(err)
						}
					}()
				case pMethodRemoveNode:
					// handle remove node packet
					go func() {
						err = n.handleRemoveNodePacket(conn, data)
						if err != nil {
							ThrowError(err)
						}
					}()
				case pMethodReverseConn:
					// handle reverse connection packet
					err = n.handleReverseConnPacket(conn, data)
					if err != nil {
						ThrowError(err)
					}
					// enter loop
					// to avoid read message from reverse connection
					keepAlive = true
					return nil
				case pMethodTransferTo:
					// handle transfer to packet
					go func() {
						err = n.handleTransferToPacket(conn, data, false)
						if err != nil {
							ThrowError(err)
						}
					}()
				default:
					// drop packet
					TreeInfo.PacketRecvDropped += 1

				}
			}
		}
	}
}

// Mutiple Handlers
//
//		 ^
//		/|\
//		 |
//		 |
//		 |
//		 |
//		 |
//	    \|/
//		 V
//
// Packet Handlers
func (n *NodeTree) handleVerifyPacket(conn net.Conn, packet []byte) error {
	var verifyP QVerifyPacket
	err := verifyP.Unmarshal(packet)
	if err != nil {
		conn.Close()
		return err
	}
	// verify token( sha256 )
	token256 := sha256.Sum256([]byte(n.LocalInitPoint.Token))
	if verifyP.Token256 != token256 {
		// generate error packet
		RMethodError, err := GeneratePacket(pMethodErrorDefault, []byte("invalid token"))
		if err != nil {
			conn.Close()
			return err
		}
		_, err = conn.Write(RMethodError)
		if err != nil {
			conn.Close()
			return err
		}
		conn.Close()
		return ErrInvalidToken
	}
	// bypassed token check, generate session packet
	newSession, err := n.NewSession([8]byte{}) // empty Unique ID
	if err != nil {
		return err
	}
	RSessionP := &RSessionPacket{
		SessionID:    newSession.SessionID,
		TTL:          newSession.TTL,
		TimeoutStamp: newSession.TimeoutStamp,
	}
	RSessionPraw, err := RSessionP.Marshal()
	if err != nil {
		return err
	}
	_, err = conn.Write(RSessionPraw)
	if err != nil {
		return err
	}
	// save session to local node
	n.SessionMap.Store(newSession.SessionID, newSession)
	return nil
}

// This Method will cost 1 TTL
func (n *NodeTree) handleAppendNodePacket(conn net.Conn, packet []byte) error {
	var appendP QAppendNodePacket
	err := appendP.Unmarshal(packet)
	if err != nil {
		ThrowError(err)
	}
	// check session
	v, ok := n.SessionMap.Load(appendP.SessionID)
	clientSession := v.(*Session)
	if !ok || clientSession.TimeoutStamp < uint64(time.Now().Unix()) || atomic.LoadUint32(&clientSession.TTL) < 1 {
		// generate error packet
		RMethodError, err := GeneratePacket(pMethodErrorDefault, []byte("invalid session"))
		if err != nil {
			ThrowError(err)
		}
		_, err = conn.Write(RMethodError)
		if err != nil {
			ThrowError(err)
		}
		ThrowError(err)
		return ErrInvalidSession
	}
	// session check passed, generate child id
	childID, err := n.GenerateChildID(0)
	if err != nil {
		RMethodError, err := GeneratePacket(pMethodErrorDefault, []byte(err.Error()))
		if err != nil {
			ThrowError(err)
		}
		_, err = conn.Write(RMethodError)
		if err != nil {
			ThrowError(err)
		}
		ThrowError(err)
		return err
	}
	// generate append node packet
	RAppendNodeP := &RAppendNodePacket{
		ChildNodeID:   childID,
		ChildNodeMask: n.ChildIDEndMask,
	}
	RAppendNodePraw, err := RAppendNodeP.Marshal()
	if err != nil {
		ThrowError(err)
		return err
	}
	_, err = conn.Write(RAppendNodePraw)
	if err != nil {
		ThrowError(err)
		return err
	}
	// Done with append node packet
	// save child id to local node
	clientSession.UniqueID = childID
	n.reduceTTL(childID)
	n.SessionMap.Store(clientSession.SessionID, clientSession)
	n.Id4Session.Store(childID, clientSession)
	// add to child
	IP, portStr, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		ThrowError(err)
		return err
	}
	portInt, err := strconv.Atoi(portStr)
	if err != nil {
		ThrowError(err)
		return err
	}
	ChildInitPoint := &ServerInitPoint{
		IpAddr:  IP,
		Port:    portInt,
		NetWork: n.LocalInitPoint.NetWork,
		Token:   "",
		Err:     nil,
		conn: &connection{
			connectionType: n.LocalInitPoint.conn.connectionType,
			rawConn:        make([]net.Conn, 1),
		},
	}
	ChildInitPoint.conn.rawConn[0] = conn
	n.Downstream.Store(childID, ChildInitPoint)
	return nil
}

// This Method will remove the child node from local child storage
// Destroy the connection of the child node include session
func (n *NodeTree) handleRemoveNodePacket(conn net.Conn, packet []byte) error {
	var QRemoveP QRemoveNodePacket
	err := QRemoveP.Unmarshal(packet)
	if err != nil {
		ThrowError(err)
		// generate error packet
		RMethodError, err := GeneratePacket(pMethodErrorDefault, []byte("invalid packet"))
		if err != nil {
		}
		_, err = conn.Write(RMethodError)
		if err != nil {
		}
		return ErrInvalidPacket
	}
	// check session
	v, ok := n.SessionMap.Load(QRemoveP.SessionID)
	clientSession := v.(*Session)
	if !ok || clientSession.TimeoutStamp < uint64(time.Now().Unix()) || atomic.LoadUint32(&clientSession.TTL) < 1 || clientSession.UniqueID != QRemoveP.NodeID {
		// generate error packet
		RMethodError, err := GeneratePacket(pMethodErrorDefault, []byte("invalid session"))
		if err != nil {
			ThrowError(err)
			return err
		}
		_, err = conn.Write(RMethodError)
		if err != nil {
			ThrowError(err)
		}
		ThrowError(err)
		return ErrInvalidSession
	}
	// session check passed, remove child node
	_, ok = n.Downstream.Load(QRemoveP.NodeID)
	if !ok {
		// generate error packet
		RMethodError, err := GeneratePacket(pMethodErrorDefault, []byte("child node not found"))
		if err != nil {
			ThrowError(err)
		}
		_, err = conn.Write(RMethodError)
		if err != nil {
			ThrowError(err)
		}
		ThrowError(err)
		return ErrInvalidNodeID
	}
	// remove child node
	n.Downstream.Delete(QRemoveP.NodeID)
	// remove session
	n.SessionMap.Delete(clientSession.SessionID)
	n.Id4Session.Delete(clientSession.UniqueID)
	// close connection
	err = conn.Close()
	if err != nil {
		ThrowError(err)
	}

	return nil
}

// This Method will cost 1 TTL (from downstream)
// This Method will send the broadcast packet to all Nodes (exclude from && self)
// This Method does not has any respond!
func (n *NodeTree) handleBroadcastPacket(_ net.Conn, packet []byte) error {
	var broadcastP QBroadcastPacket
	var senderID [IDlenth]byte
	err := broadcastP.Unmarshal(packet)
	if err != nil {
		ThrowError(ErrInvalidPacket)
		return ErrInvalidPacket
	}
	// check session
	var flagFromUpstream bool
	if n.UpstreamSessionID != nil && broadcastP.SessionID == n.UpstreamSessionID.SessionID { //from upstream
		flagFromUpstream = true
	} else {
		flagFromUpstream = false
		v, ok := n.SessionMap.Load(broadcastP.SessionID)
		if !ok {
			ThrowError(ErrInvalidSession)
			return ErrInvalidSession
		}
		session := v.(*Session)
		if session.TimeoutStamp < uint64(time.Now().Unix()) || session.TTL < 1 {
			ThrowError(ErrInvalidSession)
			return ErrInvalidSession
		}
		senderID = session.UniqueID
		n.reduceTTL(session.UniqueID)
	}
	// save broadcast message
	n.LocalInitPoint.dataReadChannel[0] <- Message{
		SrcID:       broadcastP.SrcNodeID,
		Data:        broadcastP.Data,
		MessageType: MessageTypeBroadcast,
	}
	// check TTL
	if broadcastP.TTL < 1 {
		return nil
	}

	// session check passed, send broadcast packet to upstream node (exclude from)
	if n.UpstreamSessionID != nil && !flagFromUpstream { // not upstream broadcast
		// generate broadcast packet
		QbroadcastP := &QBroadcastPacket{
			SrcNodeID: broadcastP.SrcNodeID,
			Data:      broadcastP.Data,
			TTL:       broadcastP.TTL - 1,
			SessionID: n.UpstreamSessionID.SessionID,
		}
		QbroadcastPraw, err := QbroadcastP.Marshal()
		if err != nil {
			ThrowError(err)
			return err
		}
		cu := n.RemoteInitPoint.conn.currentConn
		n.RemoteInitPoint.conn.currentConn = (n.RemoteInitPoint.conn.currentConn + 1) % len(n.RemoteInitPoint.conn.rawConn)
		if n.RemoteInitPoint.conn.connectionType == 1 {
			n.RemoteInitPoint.conn.clientMessageLocker[cu].Lock()
			defer n.RemoteInitPoint.conn.clientMessageLocker[cu].Unlock()
			_, err = n.RemoteInitPoint.conn.rawConn[cu].Write(QbroadcastPraw)
		} else {
			n.RemoteInitPoint.conn.clientMessageLocker[cu].Lock()
			defer n.RemoteInitPoint.conn.clientMessageLocker[cu].Unlock()
			_, err = n.RemoteInitPoint.conn.tlsConn[cu].Write(QbroadcastPraw)
		}
		if err != nil {
			ThrowError(err)
		}
		// session TTL -1
		n.UpstreamSessionID.TTL -= 1
	}
	// send broadcast packet to all child nodes (exclude from)
	n.Downstream.Range(func(key, value interface{}) bool {
		UniqueID := key.([IDlenth]byte)
		childInitPoint := value.(*ServerInitPoint)
		v, ok := n.Id4Session.Load(UniqueID)
		if !ok {
			ThrowError(ErrInvalidSession)
			return true
		}
		session := v.(*Session)
		if UniqueID != senderID { // not the sender
			// send broadcast packet
			QbroadcastP := &QBroadcastPacket{
				SrcNodeID: broadcastP.SrcNodeID,
				Data:      broadcastP.Data,
				TTL:       broadcastP.TTL - 1,
				SessionID: session.SessionID,
			}
			QbroadcastPraw, err := QbroadcastP.Marshal()
			if err != nil {
				ThrowError(err)
				return true
			}
			cu := childInitPoint.conn.currentReverseConn
			childInitPoint.conn.currentReverseConn = (childInitPoint.conn.currentReverseConn + 1) % len(childInitPoint.conn.reverseConn)
			childInitPoint.conn.reverseWriteLock[cu].Lock()
			defer childInitPoint.conn.reverseWriteLock[cu].Unlock()
			_, err = childInitPoint.conn.reverseConn[cu].Write(QbroadcastPraw)
			if err != nil {
				ThrowError(err)
				return true
			}
		}

		return true
	})

	// Done with broadcast packet
	return nil
}

// This Method will cost NO TTL
// used to done the downstream reverse connection
func (n *NodeTree) handleReverseConnPacket(conn net.Conn, packet []byte) error {
	var reverseConnP QReverseConnPacket
	err := reverseConnP.Unmarshal(packet)
	if err != nil {
		ThrowError(err)
		// generate error packet
		RMethodError, err := GeneratePacket(pMethodErrorDefault, []byte("invalid packet"))
		if err != nil {
		}
		_, err = conn.Write(RMethodError)
		if err != nil {
		}
		return ErrInvalidPacket
	}
	// check session
	v, ok := n.SessionMap.Load(reverseConnP.Session)
	session := v.(*Session)
	if !ok || session.TimeoutStamp < uint64(time.Now().Unix()) || session.TTL < 1 || session.UniqueID != reverseConnP.UniqueID {
		// generate error packet
		RMethodError, err := GeneratePacket(pMethodErrorDefault, []byte("invalid session"))
		if err != nil {
			ThrowError(err)
		}
		_, err = conn.Write(RMethodError)
		if err != nil {
			ThrowError(err)
		}
		ThrowError(err)
		return ErrInvalidSession
	}
	// session check pass
	// save to reverse connection
	v, ok = n.Downstream.Load(reverseConnP.UniqueID)
	if !ok {
		ThrowError(fmt.Errorf("child node not found"))
		return ErrInvalidNodeID
	}
	childInitPoint := v.(*ServerInitPoint)
	childInitPoint.conn.reverseConn = append(childInitPoint.conn.reverseConn, conn)
	childInitPoint.conn.reverseWriteLock = append(childInitPoint.conn.reverseWriteLock, new(sync.Mutex))
	// generate METHOD OK
	RMethodOK, err := GeneratePacket(pMethodOK, []byte(""))
	if err != nil {
		ThrowError(err)
		return err
	}
	_, err = conn.Write(RMethodOK)
	if err != nil {
		ThrowError(err)
		return err
	}
	return nil
}

// This Method will cost 1 TTL (from downstream)
// used to transfer packet
func (n *NodeTree) handleTransferToPacket(conn net.Conn, packet []byte, fromUpstream bool) error {
	//resolve packet
	var transferP QDataTransferTo
	err := transferP.Unmarshal(packet)
	if err != nil {
		ThrowError(err)
		// generate error packet
		errorP, err := GeneratePacket(pMethodErrorDefault, []byte("invalid packet"))
		if err != nil {
			ThrowError(err)
			return err
		}
		_, err = conn.Write(errorP)
		if err != nil {
			ThrowError(err)
			return err
		}
		return ErrInvalidPacket
	}
	if fromUpstream {
		// check session
		if n.UpstreamSessionID == nil && n.UpstreamSessionID.SessionID != transferP.SessionID {
			ThrowError(ErrInvalidSession)
			// generate error packet
			errorP, err := GeneratePacket(pMethodErrorDefault, []byte("invalid session"))
			if err != nil {
				ThrowError(err)
				return err
			}
			_, err = conn.Write(errorP)
			if err != nil {
				ThrowError(err)
				return err
			}
			return ErrInvalidSession
		}
		// check id
		if transferP.DstNodeID == n.LocalUniqueId {
			// Add to local
			message := Message{
				SrcID:       transferP.SrcNodeID,
				Data:        transferP.Data,
				MessageType: MessageTypeUnicast,
			}
			n.LocalInitPoint.dataReadChannel[ByteToUInt16(transferP.ChannelID)] <- message
			if transferP.NoResp {
				return nil
			}
			// Method OK
			RMethodOK, err := GeneratePacket(pMethodOK, nil)
			if err != nil {
				ThrowError(err)
				return err
			}
			_, err = conn.Write(RMethodOK)
			if err != nil {
				ThrowError(err)
				return err
			}
			return nil
		}
		// session check passed, transfer packet
		err := n.SendTo(transferP.DstNodeID, transferP.ChannelID, transferP.Data, transferP.SrcNodeID)
		if err != nil {
			ThrowError(err)
			// generate error packet
			errorP, err := GeneratePacket(pMethodErrorDefault, []byte(err.Error()))
			if err != nil {
				ThrowError(err)
				return err
			}
			_, err = conn.Write(errorP)
			if err != nil {
				ThrowError(err)
				return err
			}
			return err
		}
		if transferP.NoResp {
			return nil
		}
		// Method OK
		RMethodOK, err := GeneratePacket(pMethodOK, nil)
		if err != nil {
			ThrowError(err)
			return err
		}
		_, err = conn.Write(RMethodOK)
		if err != nil {
			ThrowError(err)
			return err
		}
		return nil
	} else {
		// check session
		v, ok := n.SessionMap.Load(transferP.SessionID)
		session := v.(*Session)
		if !ok || session.TimeoutStamp < uint64(time.Now().Unix()) || session.TTL < 1 {
			ThrowError(ErrInvalidSession)
			// generate error packet
			errorP, err := GeneratePacket(pMethodErrorDefault, []byte("invalid session"))
			if err != nil {
				ThrowError(err)
				return err
			}
			_, err = conn.Write(errorP)
			if err != nil {
				ThrowError(err)
				return err
			}
			return ErrInvalidSession
		}
		// reduce TTL
		n.reduceTTL(session.UniqueID)
		// check id
		if transferP.DstNodeID == n.LocalUniqueId {
			// Add to local
			message := Message{
				SrcID:       transferP.SrcNodeID,
				Data:        transferP.Data,
				MessageType: MessageTypeUnicast,
			}
			n.LocalInitPoint.dataReadChannel[ByteToUInt16(transferP.ChannelID)] <- message
			if transferP.NoResp {
				return nil
			}
			// Method OK
			RMethodOK, err := GeneratePacket(pMethodOK, nil)
			if err != nil {
				ThrowError(err)
				return err
			}
			_, err = conn.Write(RMethodOK)
			if err != nil {
				ThrowError(err)
				return err
			}
			return nil
		}
		// session check passed, transfer packet
		err := n.SendTo(transferP.DstNodeID, transferP.ChannelID, transferP.Data, transferP.SrcNodeID)
		if err != nil {
			ThrowError(err)
			// generate error packet
			errorP, err := GeneratePacket(pMethodErrorDefault, []byte(err.Error()))
			if err != nil {
				ThrowError(err)
				return err
			}
			_, err = conn.Write(errorP)
			if err != nil {
				ThrowError(err)
				return err
			}
			return err
		}
		if transferP.NoResp {
			return nil
		}
		// Method OK
		RMethodOK, err := GeneratePacket(pMethodOK, nil)
		if err != nil {
			ThrowError(err)
			return err
		}
		_, err = conn.Write(RMethodOK)
		if err != nil {
			ThrowError(err)
			return err
		}
		return nil
	}
}

//
// End Packet Handlers
//

// Tool functions

func (n *NodeTree) String() string {
	b, err := json.Marshal(n)
	if err != nil {
		n.Err = err
		return ""
	}
	return string(b)
}

func (n *NodeTree) NewSession(UniqueID [IDlenth]byte) (*Session, error) {
	// generate session id
	newSession := Session{
		SessionID:    [8]byte{},
		UniqueID:     UniqueID,
		TTL:          DefaultSessionTTL,
		TimeoutStamp: uint64(time.Now().Unix()) + uint64(DefaultSessionTimeout.Seconds()),
	}
	_, err := rand.Read(newSession.SessionID[:])
	if err != nil {
		return &Session{}, err
	}
	// check if session id already exists
	_, ok := n.SessionMap.Load(newSession.SessionID)
	if ok {
		return n.NewSession(UniqueID)
	}
	return &newSession, nil
}

func ThrowError(errorinfo error) {
	_, file, lineNo, _ := runtime.Caller(1)
	log.Printf("ERROR: %v on line %d in %s\n", errorinfo, lineNo, file)
}

func isclosedconn(err error) bool {
	if err == io.EOF || strings.Contains(err.Error(), "use of closed network connection") || strings.Contains(err.Error(), "broken pipe") || strings.Contains(err.Error(), "connection reset by peer") {
		return true
	}
	return false
}

func (n *NodeTree) GenerateChildID(retry int) ([IDlenth]byte, error) {
	n.generateIDLock.Lock()
	defer n.generateIDLock.Unlock()

	if !n.Able2AddChildNode {
		return [IDlenth]byte{}, fmt.Errorf("can not add child node")
	}

	if retry > 1<<(n.ChildIDEndMask-n.LocalIdMask-1) {
		return [IDlenth]byte{}, fmt.Errorf("generate child id failed: retry limit exceeded")
	}

	// 参数有效性检查
	if n.ChildIDEndMask > 8*IDlenth || n.LocalIdMask >= n.ChildIDEndMask {
		return [IDlenth]byte{}, fmt.Errorf("invalid mask range")
	}

	// 计算需要随机化的bit数
	bitSize := n.ChildIDEndMask - n.LocalIdMask
	maxValue := uint64(1<<bitSize) - 1

	// 生成随机值
	randValue := uint64(mathrand.Int63n(int64(maxValue)))

	// 将父ID转换为uint64进行位操作
	parentUint := binary.BigEndian.Uint64(n.LocalUniqueId[:])

	// 计算掩码：保留父节点的前 LocalIdMask 位，其余清零
	parentMask := uint64((1<<n.LocalIdMask)-1) << (64 - n.LocalIdMask)
	parentUint &= parentMask // 保留父节点的高 LocalIdMask 位

	// 将随机值写入第 (LocalIdMask) 到 (ChildIDEndMask-1) 位
	randShift := 64 - n.ChildIDEndMask
	randMask := maxValue << randShift
	parentUint &^= randMask              // 清零目标区域
	parentUint |= randValue << randShift // 设置随机值

	// 转换回byte数组
	var childID [IDlenth]byte
	binary.BigEndian.PutUint64(childID[:], parentUint)

	// 测试生成的ID是否有效
	_, ok := n.Id4Session.Load(childID)
	if ok || childID == n.LocalUniqueId {
		return n.GenerateChildID(retry + 1) // 递归生成新的ID
	}
	return childID, nil
}

func MaxNumbers(n int) *big.Int {
	if n <= 0 {
		return new(big.Int) // 返回0（无效输入）
	}

	bits := n * 8
	if bits < 0 {
		return new(big.Int) // 处理整数溢出情况
	}

	base := big.NewInt(2)
	exponent := big.NewInt(int64(bits))
	return new(big.Int).Exp(base, exponent, nil)
}

func ByteToUInt16(b [2]byte) uint16 {
	return binary.BigEndian.Uint16(b[:])
}

func UInt16ToByte(i uint16) [2]byte {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], i)
	return b
}

func GetBits(data []byte, start, end int) []byte {
	maxBit := len(data) * 8
	if start < 0 {
		start = 0
	}
	if end > maxBit {
		end = maxBit
	}
	if start >= end {
		return []byte{}
	}

	length := end - start
	result := make([]byte, (length+7)/8)

	for pos := 0; pos < length; pos++ {
		globalBit := start + pos
		byteIdx := globalBit / 8
		bitIdx := globalBit % 8
		bitValue := (data[byteIdx] >> (7 - bitIdx)) & 1

		resultByteIdx := pos / 8
		resultBitIdx := pos % 8
		result[resultByteIdx] |= bitValue << (7 - resultBitIdx)
	}

	return result
}

func ReplaceBits(original []byte, start, end int, replaceBytes []byte) []byte {
	modified := make([]byte, len(original))
	copy(modified, original)
	original = modified

	replaceBits := end - start
	if replaceBits <= 0 {
		return original
	}

	maxBit := end
	requiredBytes := (maxBit + 7) / 8
	if requiredBytes > len(original) {
		newModified := make([]byte, requiredBytes)
		copy(newModified, original)
		original = newModified
	}

	for i := 0; i < replaceBits; i++ {
		globalBit := start + i
		byteIdx := globalBit / 8
		bitIdx := globalBit % 8

		var bitValue byte
		if replaceByteIdx := i / 8; replaceByteIdx < len(replaceBytes) {
			replaceBitIdx := i % 8
			bitValue = (replaceBytes[replaceByteIdx] >> (7 - replaceBitIdx)) & 1
		} else {
			bitValue = 0
		}

		mask := byte(1 << (7 - bitIdx))
		original[byteIdx] = (original[byteIdx] &^ mask) | (bitValue << (7 - bitIdx))
	}

	return original
}

// return true if the UniqueID is downstream of the local node
// return false if the UniqueID is upstream or same mask
func (n *NodeTree) isUniqueIDDownstream(UniqueID [IDlenth]byte) bool {
	maxBits := len(n.LocalUniqueId) * 8
	mask := n.LocalIdMask
	if mask > uint32(maxBits) {
		mask = uint32(maxBits)
	}
	if mask == 0 {
		return false
	}

	// 创建位掩码数组
	maskBytes := make([]byte, len(n.LocalUniqueId))
	fullBytes := int(mask / 8)
	remainderBits := int(mask % 8)

	// 填充完整字节掩码
	for i := 0; i < fullBytes; i++ {
		maskBytes[i] = 0xFF
	}

	// 处理剩余位的掩码
	if remainderBits > 0 && fullBytes < len(maskBytes) {
		maskBytes[fullBytes] = 0xFF << (8 - remainderBits)
	}

	// 逐字节比较掩码结果
	for i := 0; i < len(n.LocalUniqueId); i++ {
		maskedLocal := n.LocalUniqueId[i] & maskBytes[i]
		maskedTarget := UniqueID[i] & maskBytes[i]
		if maskedLocal != maskedTarget {
			return false
		}
	}
	return true
}

// End Tool functions

// the function done:
// 1. create a new connection object for the initpoint
// 2. build verify packet
// 3. send verify packet to initpoint
// 4. receive verify response from initpoint
// 5. save to local node
// Locker
func (n *NodeTree) connectToInitPoint(initpoint *ServerInitPoint) error {
	conn, err := net.Dial(initpoint.NetWork, net.JoinHostPort(initpoint.IpAddr, fmt.Sprintf("%d", initpoint.Port)))
	if err != nil {
		return err
	}
	// Create a new connection object for the initpoint
	if initpoint.tlsSettings.Enabled {
		tlsConn := tls.Client(conn, initpoint.tlsSettings.TLSConfig)
		err = tlsConn.Handshake()
		if err != nil {
			return err
		}
		initpoint.conn.connectionType = 2
		initpoint.conn.tlsConn = append(initpoint.conn.tlsConn, tlsConn)
		initpoint.conn.rawConn = append(initpoint.conn.rawConn, conn)
		initpoint.conn.clientMessageLocker = append(initpoint.conn.clientMessageLocker, new(sync.Mutex))
	} else {
		initpoint.conn.rawConn = append(initpoint.conn.rawConn, conn)
		initpoint.conn.clientMessageLocker = append(initpoint.conn.clientMessageLocker, new(sync.Mutex))
		initpoint.conn.connectionType = 1
	}
	initpoint.conn.currentConn = 0
	initpoint.conn.currentReverseConn = 0
	// build verify packet
	verifyP := QVerifyPacket{
		Token: initpoint.Token,
	}
	verifyPraw, err := verifyP.Marshal()
	if err != nil {
		return err
	}

	// send verify packet to initpoint
	if initpoint.conn.connectionType == 1 {
		initpoint.conn.clientMessageLocker[initpoint.conn.currentConn].Lock()
		defer initpoint.conn.clientMessageLocker[initpoint.conn.currentConn].Unlock()
		_, err = initpoint.conn.rawConn[initpoint.conn.currentConn].Write(verifyPraw)
	} else if initpoint.conn.connectionType == 2 {
		initpoint.conn.clientMessageLocker[initpoint.conn.currentConn].Lock()
		defer initpoint.conn.clientMessageLocker[initpoint.conn.currentConn].Unlock()
		_, err = initpoint.conn.tlsConn[initpoint.conn.currentConn].Write(verifyPraw)
	}
	if err != nil {
		initpoint.Destroy()
		return err
	}
	// receive verify response from initpoint
	verifyR := make([]byte, PacketBuffer)
	var num int
	if initpoint.conn.connectionType == 1 {
		num, err = initpoint.conn.rawConn[initpoint.conn.currentConn].Read(verifyR)
	} else if initpoint.conn.connectionType == 2 {
		num, err = initpoint.conn.tlsConn[initpoint.conn.currentConn].Read(verifyR)
	}
	initpoint.conn.currentConn = (initpoint.conn.currentConn + 1) % len(initpoint.conn.rawConn)
	if err != nil {
		initpoint.Destroy()
		return err
	}
	verifyR = verifyR[:num]
	method, data, _, err := ResolvPacket(verifyR)
	if err != nil {
		initpoint.Destroy()
		return err
	}
	switch method {
	case pMethodOK:
		// save to local node
		n.RemoteInitPoint = initpoint
		// resolve Rsession packet
		var RsessionP RSessionPacket
		err = RsessionP.Unmarshal(data)
		if err != nil {
			initpoint.Destroy()
			return err
		}
		n.UpstreamSessionID = &Session{
			SessionID:    RsessionP.SessionID,
			TTL:          RsessionP.TTL,
			TimeoutStamp: RsessionP.TimeoutStamp,
		}

		return nil
	case pMethodErrorDefault:
		return fmt.Errorf("failed on verifying: %s", string(data))
	}
	return nil
}

// this func only refresh the session of upstream node
// NOT THE CHILD NODE
// Child Node Session only refresh by itself.Not UPSTREAM
// Locker
func (n *NodeTree) RefreshUpstreamSession() error {
	// build verify packet
	verifyP := QVerifyPacket{
		Token: n.LocalInitPoint.Token,
	}
	verifyPraw, err := verifyP.Marshal()
	if err != nil {
		return err
	}

	// send verify packet to initpoint
	if n.RemoteInitPoint.conn.connectionType == 1 {
		n.RemoteInitPoint.conn.clientMessageLocker[n.RemoteInitPoint.conn.currentConn].Lock()
		defer n.RemoteInitPoint.conn.clientMessageLocker[n.RemoteInitPoint.conn.currentConn].Unlock()
		_, err = n.RemoteInitPoint.conn.rawConn[n.RemoteInitPoint.conn.currentConn].Write(verifyPraw)
	} else if n.RemoteInitPoint.conn.connectionType == 2 {
		n.RemoteInitPoint.conn.clientMessageLocker[n.RemoteInitPoint.conn.currentConn].Lock()
		defer n.RemoteInitPoint.conn.clientMessageLocker[n.RemoteInitPoint.conn.currentConn].Unlock()
		_, err = n.RemoteInitPoint.conn.tlsConn[n.RemoteInitPoint.conn.currentConn].Write(verifyPraw)
	}
	if err != nil {
		n.RemoteInitPoint.Destroy()
		return err
	}

	// receive verify response from initpoint
	verifyR := make([]byte, PacketBuffer)
	var num int
	if n.RemoteInitPoint.conn.connectionType == 1 {
		num, err = n.RemoteInitPoint.conn.rawConn[n.RemoteInitPoint.conn.currentConn].Read(verifyR)
	} else if n.RemoteInitPoint.conn.connectionType == 2 {
		num, err = n.RemoteInitPoint.conn.tlsConn[n.RemoteInitPoint.conn.currentConn].Read(verifyR)
	}
	n.RemoteInitPoint.conn.currentConn = (n.RemoteInitPoint.conn.currentConn + 1) % len(n.RemoteInitPoint.conn.rawConn)
	if err != nil {
		n.RemoteInitPoint.Destroy()
		return err
	}
	verifyR = verifyR[:num]
	method, data, _, err := ResolvPacket(verifyR)
	if err != nil {
		n.RemoteInitPoint.Destroy()
		return err
	}

	switch method {
	case pMethodOK:
		// resolve Respond session packet
		var RsessionP RSessionPacket
		err = RsessionP.Unmarshal(data)
		if err != nil {
			n.RemoteInitPoint.Destroy()
			return err
		}
		n.UpstreamSessionID = &Session{
			SessionID:    RsessionP.SessionID,
			TTL:          RsessionP.TTL,
			TimeoutStamp: RsessionP.TimeoutStamp,
		}
		return nil
	case pMethodErrorDefault:
		return fmt.Errorf("failed on verifying: %s", string(data))
	}
	return nil
}

// Append Self to Node(Connect as a child node)
// no locker
func (n *NodeTree) AppendToNode(initpoint *ServerInitPoint, threads int) error {
	// connect to initpoint
	err := n.connectToInitPoint(initpoint)
	if err != nil {
		return err
	}
	// Get Node Info From Upstream
	err = n.GetIDInfo()
	if err != nil {
		initpoint.Destroy()
		return err
	}
	// Create reverse connection
	err = n.CreateReverseConnection()
	if err != nil {
		initpoint.Destroy()
		return err
	}
	// Done muti-connection
	err = n.doneConnectionsToUpstream(threads - 1)
	if err != nil {
		ThrowError(err)
		return err
	}
	for i := 0; i < threads-1; i++ {
		err = n.CreateReverseConnection()
		if err != nil {
			ThrowError(err)
			return err
		}
	}
	// All connetion is ready
	//
	// The Process of Append:
	// 1. Connect to Upstream Node (initpoint)
	// 2. Send Verify Packet to Upstream Node
	// 3. Receive Verify Response Packet (SessionPacket) from Upstream Node
	// 4. Pull Child Node Info from Upstream Node
	// 5. Create reverse connection to Upstream Node
	// DONE!
	return nil
}

func (n *NodeTree) doneConnectionsToUpstream(thread int) error {
	for i := 0; i < thread; i++ {
		conn, err := net.Dial(n.RemoteInitPoint.NetWork, net.JoinHostPort(n.RemoteInitPoint.IpAddr, fmt.Sprintf("%d", n.RemoteInitPoint.Port)))
		if err != nil {
			return err
		}
		// Create a new connection object for the initpoint
		if n.RemoteInitPoint.tlsSettings.Enabled {
			tlsConn := tls.Client(conn, n.RemoteInitPoint.tlsSettings.TLSConfig)
			err = tlsConn.Handshake()
			if err != nil {
				return err
			}
			n.RemoteInitPoint.conn.tlsConn = append(n.RemoteInitPoint.conn.tlsConn, tlsConn)
			n.RemoteInitPoint.conn.rawConn = append(n.RemoteInitPoint.conn.rawConn, conn)
			n.RemoteInitPoint.conn.clientMessageLocker = append(n.RemoteInitPoint.conn.clientMessageLocker, new(sync.Mutex))
		} else {
			n.RemoteInitPoint.conn.rawConn = append(n.RemoteInitPoint.conn.rawConn, conn)
			n.RemoteInitPoint.conn.clientMessageLocker = append(n.RemoteInitPoint.conn.clientMessageLocker, new(sync.Mutex))
		}
	}
	return nil
}

// NO session TTL reduce
// this method is used to create a reverse connection to the upstream node
// receive Methods from Upstream Node
// no locker
func (n *NodeTree) CreateReverseConnection() error {
	// for i := range n.RemoteInitPoint.conn.reverseConn {
	// 	n.RemoteInitPoint.conn.reverseConn[i].Close()
	// }
	// n.RemoteInitPoint.conn.reverseConn = nil
	// n.RemoteInitPoint.conn.reverseWriteLock = nil
	// create a new connection object for the remote initpoint
	conn, err := net.Dial(n.RemoteInitPoint.NetWork, net.JoinHostPort(n.RemoteInitPoint.IpAddr, fmt.Sprintf("%d", n.RemoteInitPoint.Port)))
	if err != nil {
		return err
	}
	cu := 0
	if n.RemoteInitPoint.tlsSettings.Enabled {
		tlsConn := tls.Client(conn, n.RemoteInitPoint.tlsSettings.TLSConfig)
		err = tlsConn.Handshake()
		if err != nil {
			return err
		}
		n.RemoteInitPoint.conn.reverseConn = append(n.RemoteInitPoint.conn.reverseConn, tlsConn)
		n.RemoteInitPoint.conn.reverseWriteLock = append(n.RemoteInitPoint.conn.reverseWriteLock, new(sync.Mutex))
		cu = len(n.RemoteInitPoint.conn.reverseConn) - 1

	} else {
		n.RemoteInitPoint.conn.reverseConn = append(n.RemoteInitPoint.conn.reverseConn, conn)
		n.RemoteInitPoint.conn.reverseWriteLock = append(n.RemoteInitPoint.conn.reverseWriteLock, new(sync.Mutex))
		cu = len(n.RemoteInitPoint.conn.reverseConn) - 1
	}
	// send reverse conn packet
	QReverseP := &QReverseConnPacket{
		Session:  n.UpstreamSessionID.SessionID,
		UniqueID: n.LocalUniqueId,
	}
	QReversePraw, err := QReverseP.Marshal()
	if err != nil {
		return err
	}
	_, err = n.RemoteInitPoint.conn.reverseConn[cu].Write(QReversePraw)
	if err != nil {
		return err
	}
	// enter message loop
	go n.reverseConnMessageLoop(n.RemoteInitPoint.conn.reverseConn[cu])
	// receive METHOD OK
	reverseR := make([]byte, PacketBuffer)
	num, err := n.RemoteInitPoint.conn.reverseConn[cu].Read(reverseR)
	if err != nil {
		return err
	}
	reverseR = reverseR[:num]
	method, data, _, err := ResolvPacket(reverseR)
	if err != nil {
		return err
	}
	if method != pMethodOK {
		return fmt.Errorf("failed on reverse connection: %s", string(data))
	}
	return nil
}

// Get Local unique ID and mask from Upstream Node
// And Generate Child Mask
// this func will use 1 TTL
// Locker
func (n *NodeTree) GetIDInfo() error {
	// reduce TTL
	if n.UpstreamSessionID.TTL < 1 || n.UpstreamSessionID.TimeoutStamp < uint64(time.Now().Unix()) { //timeout or TTL == 0
		// refresh session
		err := n.RefreshUpstreamSession()
		if err != nil {
			return err
		}
	}
	n.UpstreamSessionID.TTL--
	// Generate Append Packet
	QAppendP := QAppendNodePacket{
		SessionID: n.UpstreamSessionID.SessionID,
	}
	QAppendPraw, err := QAppendP.Marshal()
	if err != nil {
		return err
	}
	// Send Append Packet to Upstream
	cu := n.RemoteInitPoint.conn.currentConn
	n.RemoteInitPoint.conn.currentConn = (n.RemoteInitPoint.conn.currentConn + 1) % len(n.RemoteInitPoint.conn.rawConn)
	if n.RemoteInitPoint.conn.connectionType == 1 {
		n.RemoteInitPoint.conn.clientMessageLocker[cu].Lock()
		defer n.RemoteInitPoint.conn.clientMessageLocker[cu].Unlock()
		_, err = n.RemoteInitPoint.conn.rawConn[cu].Write(QAppendPraw)
	} else if n.RemoteInitPoint.conn.connectionType == 2 {
		n.RemoteInitPoint.conn.clientMessageLocker[cu].Lock()
		defer n.RemoteInitPoint.conn.clientMessageLocker[cu].Unlock()
		_, err = n.RemoteInitPoint.conn.tlsConn[cu].Write(QAppendPraw)
	}
	if err != nil {
		n.RemoteInitPoint.Destroy()
		return err
	}
	// Receive Append Response Packet from Upstream
	appendR := make([]byte, PacketBuffer)
	var num int
	if n.RemoteInitPoint.conn.connectionType == 1 {
		num, err = n.RemoteInitPoint.conn.rawConn[cu].Read(appendR)
	} else if n.RemoteInitPoint.conn.connectionType == 2 {
		num, err = n.RemoteInitPoint.conn.tlsConn[cu].Read(appendR)
	}
	if err != nil {
		n.RemoteInitPoint.Destroy()
		return err
	}
	appendR = appendR[:num]
	method, data, _, err := ResolvPacket(appendR)
	if err != nil {
		n.RemoteInitPoint.Destroy()
		return err
	}
	switch method {
	case pMethodOK:
		// resolve Append Response Packet
		var RAppendP RAppendNodePacket
		err = RAppendP.Unmarshal(data)
		if err != nil {
			n.RemoteInitPoint.Destroy()
			return err
		}
		// save to local node
		n.LocalUniqueId = RAppendP.ChildNodeID
		n.LocalIdMask = RAppendP.ChildNodeMask
		n.UpstreamUniqueID = RAppendP.UpstreamUniqueID
		// generate child mask
		if RAppendP.ChildNodeMask+MaskAddNum > 8*IDlenth {
			// this node is the end node in the tree
			n.Able2AddChildNode = false
			return nil
		}
		n.ChildIDEndMask = RAppendP.ChildNodeMask + MaskAddNum
		n.Able2AddChildNode = true
		return nil
	case pMethodErrorDefault:
		return fmt.Errorf("failed on appending: %s", string(data))
	}
	return nil
}

// this func is used to reduce TTL of session(downstream)
// if session timeout or TTL == 0, it will return error
func (n *NodeTree) reduceTTL(UniqueID [IDlenth]byte) error {
	v, ok := n.Id4Session.Load(UniqueID)
	if !ok {
		return fmt.Errorf("session not found")
	}
	session := v.(*Session)
	if session.TTL < 1 || session.TimeoutStamp < uint64(time.Now().Unix()) { //timeout or TTL == 0
		// remove session
		n.SessionMap.Delete(session.SessionID)
		n.Id4Session.Delete(UniqueID)
		return fmt.Errorf("session out of date")
	}
	atomic.AddUint32(&session.TTL, ^uint32(0))
	n.Id4Session.Store(UniqueID, session)
	return nil
}

// Locker
func (n *NodeTree) RemoveSelfFromUpstream() error {
	// build remove packet
	QRemoveP := QRemoveNodePacket{
		SessionID: n.UpstreamSessionID.SessionID,
		NodeID:    n.LocalUniqueId,
	}
	QRemovePraw, err := QRemoveP.Marshal()
	if err != nil {
		return err
	}
	// send remove packet to initpoint
	cu := n.RemoteInitPoint.conn.currentConn
	n.RemoteInitPoint.conn.currentConn = (n.RemoteInitPoint.conn.currentConn + 1) % len(n.RemoteInitPoint.conn.rawConn)
	if n.RemoteInitPoint.conn.connectionType == 1 {
		n.RemoteInitPoint.conn.clientMessageLocker[cu].Lock()
		defer n.RemoteInitPoint.conn.clientMessageLocker[cu].Unlock()
		_, err = n.RemoteInitPoint.conn.rawConn[cu].Write(QRemovePraw)
	} else if n.RemoteInitPoint.conn.connectionType == 2 {
		n.RemoteInitPoint.conn.clientMessageLocker[cu].Lock()
		defer n.RemoteInitPoint.conn.clientMessageLocker[cu].Unlock()
		_, err = n.RemoteInitPoint.conn.tlsConn[cu].Write(QRemovePraw)
	}
	if err != nil {
		return err
	}
	// receive remove response packet from initpoint
	removeR := make([]byte, PacketBuffer)
	var num int
	if n.RemoteInitPoint.conn.connectionType == 1 {
		num, err = n.RemoteInitPoint.conn.rawConn[cu].Read(removeR)
	} else if n.RemoteInitPoint.conn.connectionType == 2 {
		num, err = n.RemoteInitPoint.conn.tlsConn[cu].Read(removeR)
	}
	if err != nil {
		if isclosedconn(err) {
			// remove session
			n.UpstreamSessionID = nil
			n.RemoteInitPoint.Destroy()
			return nil
		}
		return err
	}
	removeR = removeR[:num]
	method, data, _, err := ResolvPacket(removeR)
	if err != nil {
		n.RemoteInitPoint.Destroy()
		return err
	}
	if method != pMethodOK {
		return fmt.Errorf("failed on removing: %s", string(data))
	}
	// remove session
	n.UpstreamSessionID = nil
	// close connection
	n.RemoteInitPoint.Destroy()
	return nil
}

// Message Loop
// receive commands from upstream
func (n *NodeTree) reverseConnMessageLoop(conn net.Conn) {
	defer conn.Close()
	var RQP []byte
	packet := make([]byte, PacketBuffer) // buffer
	for {
		// receive message from upstream
		num, err := conn.Read(packet)
		// data info log
		TreeInfo.DataReceived += uint64(num)
		TreeInfo.PacketReceived++
		if err != nil {
			ThrowError(err)
			if isclosedconn(err) {
				// connection err, destroy connection
				cu := 0
				for i, c := range n.RemoteInitPoint.conn.reverseConn {
					if c == conn {
						cu = i
					}
				}
				n.RemoteInitPoint.conn.reverseConn = append(n.RemoteInitPoint.conn.reverseConn[:cu], n.RemoteInitPoint.conn.reverseConn[cu+1:]...)
				n.RemoteInitPoint.conn.reverseWriteLock = append(n.RemoteInitPoint.conn.reverseWriteLock[:cu], n.RemoteInitPoint.conn.reverseWriteLock[cu+1:]...)
				if len(n.RemoteInitPoint.conn.reverseConn) < 1 {
					n.RemoteInitPoint.conn.currentReverseConn = 0
					break
				}
				n.RemoteInitPoint.conn.currentReverseConn = (n.RemoteInitPoint.conn.currentReverseConn + 1) % len(n.RemoteInitPoint.conn.reverseConn) // avoid index out of range
				break
			}
		}
		RQP = append(RQP, packet[:num]...)
		for {
			method, data, realLen, err := ResolvPacket(RQP)
			if err != nil {
				if err == ErrPacketTooShort {
					break // 数据不足，等待下次读取
				}
				ThrowError(err)
				break // 其他错误跳出处理循环
			}
			if realLen > 32_000 { // 32KB
				// drop packet
				TreeInfo.PacketRecvDropped += 1
				RQP = nil
				break
			}
			RQP = RQP[realLen:]
			switch method {
			case pMethodBroadcast:
				// handle broadcast packet
				go func() {
					err = n.handleBroadcastPacket(conn, data)
					if err != nil {
						ThrowError(err)
					}
				}()
			case pMethodTransferTo:
				// handle transfer packet
				go func() {
					err = n.handleTransferToPacket(conn, data, true)
					if err != nil {
						ThrowError(err)
					}
				}()
			default:
				// dropped
				TreeInfo.PacketRecvDropped++
			}
		}
	}
}

// this func will use 1 TTL
// No locker
// if ChannelID == 0, it means broadcast packet
func (n *NodeTree) SendTo(ToUniqueID [IDlenth]byte, ChannelID [ChannelIDMaxLenth]byte, data []byte, src_opt ...[IDlenth]byte) error {
	if ChannelID == [ChannelIDMaxLenth]byte{0x00, 0x00} {
		// broadcast packet
		// 获取源ID
		src_id := n.LocalUniqueId
		if len(src_opt) > 0 {
			src_id = src_opt[0]
		}
		// 发送到上游（如果存在且不是根节点）
		if n.RemoteInitPoint != nil && n.UpstreamUniqueID != src_id && n.UpstreamSessionID != nil {
			// 创建广播包结构
			broadcastP := QBroadcastPacket{
				SrcNodeID: src_id,
				Data:      data,
				TTL:       DefaultBroadcastTTL,
				SessionID: n.UpstreamSessionID.SessionID,
			}

			// 序列化广播包
			payload, err := broadcastP.Marshal()
			if err != nil {
				ThrowError(fmt.Errorf("marshal broadcast packet failed: %v", err))
			}
			// 扣除上游TTL
			if n.UpstreamSessionID.TTL < 1 || n.UpstreamSessionID.TimeoutStamp < uint64(time.Now().Unix()) { //timeout or TTL == 0
				// refresh session
				n.RefreshUpstreamSession()
			}
			n.UpstreamSessionID.TTL--
			// data log
			TreeInfo.DataSent += uint64(len(payload))
			TreeInfo.PacketSent++
			// 发送广播包
			cu := n.RemoteInitPoint.conn.currentConn
			n.RemoteInitPoint.conn.currentConn = (n.RemoteInitPoint.conn.currentConn + 1) % len(n.RemoteInitPoint.conn.rawConn)
			if n.RemoteInitPoint.conn.connectionType == 1 {
				_, err = n.RemoteInitPoint.conn.rawConn[cu].Write(payload)
			} else if n.RemoteInitPoint.conn.connectionType == 2 {
				_, err = n.RemoteInitPoint.conn.tlsConn[cu].Write(payload)
			}
			if err != nil {
				ThrowError(fmt.Errorf("upstream broadcast failed: %v", err))
			}
		}
		var sendErrors []error
		n.Downstream.Range(func(key, value interface{}) bool {
			nodeID := key.([IDlenth]byte)
			node := value.(*ServerInitPoint)

			// 跳过广播来源节点
			if nodeID == src_id {
				return true
			}
			// 获取下游会话
			v, ok := n.Id4Session.Load(nodeID)
			if !ok {
				sendErrors = append(sendErrors, fmt.Errorf("session not found for node %x", nodeID))
				return true
			}
			session := v.(*Session)

			// 创建带下游会话的广播包
			downstreamP := QBroadcastPacket{
				SrcNodeID: src_id,
				Data:      data,
				TTL:       DefaultBroadcastTTL - 1,
				SessionID: session.SessionID,
			}

			// 序列化下游专用包
			downstreamPayload, err := downstreamP.Marshal()
			if err != nil {
				sendErrors = append(sendErrors, err)
				return true
			}
			// data log
			TreeInfo.DataSent += uint64(len(downstreamPayload))
			TreeInfo.PacketSent++
			// 发送到下游节点
			cu := node.conn.currentReverseConn
			node.conn.currentReverseConn = (node.conn.currentReverseConn + 1) % len(node.conn.reverseConn)
			_, err = node.conn.reverseConn[cu].Write(downstreamPayload)
			if err != nil {
				sendErrors = append(sendErrors, fmt.Errorf("send to node %x failed: %v", nodeID, err))
			}
			return true
		})

		// 处理发送错误
		if len(sendErrors) > 0 {
			return fmt.Errorf("broadcast completed with %d errors. First error: %v", len(sendErrors), sendErrors[0])
		}

		return nil
	}
	src_id := n.LocalUniqueId
	if len(src_opt) > 0 {
		src_id = src_opt[0]
	}
	// Check UniqueID
	if ToUniqueID == n.LocalUniqueId {
		return ErrSendToSelf
	}
	isDownstream := n.isUniqueIDDownstream(ToUniqueID)
	if isDownstream {
		// send to downstream
		return n.sendToDownstream(ToUniqueID, ChannelID, data, src_id, true)
	} else {
		if n.UpstreamSessionID.TTL < 1 || n.UpstreamSessionID.TimeoutStamp < uint64(time.Now().Unix()) { //timeout or TTL == 0
			// refresh session
			n.RefreshUpstreamSession()
		}
		// reduce TTL
		n.UpstreamSessionID.TTL--
		// send to upstream
		return n.sendToUpstream(ToUniqueID, ChannelID, data, src_id, true)
	}
}

// no locker
func (n *NodeTree) ReadFrom(ChannelID [ChannelIDMaxLenth]byte) (int, []byte, [IDlenth]byte) {
	// n.RemoteInitPoint.conn.clientMessageLocker.Lock()
	// defer n.RemoteInitPoint.conn.clientMessageLocker.Unlock()
	message := <-n.LocalInitPoint.dataReadChannel[ByteToUInt16(ChannelID)]
	return message.MessageType, message.Data, message.SrcID
}

// child of SendTO
// LOCKER
func (n *NodeTree) sendToUpstream(ToUniqueID [IDlenth]byte, ChannelID [ChannelIDMaxLenth]byte, data []byte, srcid [IDlenth]byte, noneedresp bool) error {
	// check session
	if n.UpstreamSessionID.TTL < 1 || n.UpstreamSessionID.TimeoutStamp < uint64(time.Now().Unix()) {
		n.RefreshUpstreamSession()
	}
	n.UpstreamSessionID.TTL--
	// build send packet
	sendP := &QDataTransferTo{
		SessionID: n.UpstreamSessionID.SessionID,
		SrcNodeID: srcid,
		DstNodeID: ToUniqueID,
		ChannelID: ChannelID,
		Data:      data,
		NoResp:    noneedresp,
	}
	sendPraw, err := sendP.Marshal()
	if err != nil {
		// data log
		TreeInfo.PacketSendDropped++
		ThrowError(err)
		return err
	}
	// data log
	TreeInfo.DataSent += uint64(len(sendPraw))
	TreeInfo.PacketSent++
	// send send packet to initpoint
	cu := n.RemoteInitPoint.conn.currentConn
	n.RemoteInitPoint.conn.currentConn = (n.RemoteInitPoint.conn.currentConn + 1) % len(n.RemoteInitPoint.conn.rawConn)
	if !noneedresp {
		n.RemoteInitPoint.conn.clientMessageLocker[cu].Lock()
		defer n.RemoteInitPoint.conn.clientMessageLocker[cu].Unlock()
	}
	if n.RemoteInitPoint.conn.connectionType == 1 {
		sentBytes := 0
		countBytes := 0
		for countBytes < len(sendPraw) {
			countBytes, err = n.RemoteInitPoint.conn.rawConn[cu].Write(sendPraw)
			sentBytes += countBytes
		}
	} else if n.RemoteInitPoint.conn.connectionType == 2 {
		sentBytes := 0
		countBytes := 0
		for countBytes < len(sendPraw) {
			countBytes, err = n.RemoteInitPoint.conn.tlsConn[cu].Write(sendPraw)
			sentBytes += countBytes
		}
	}
	if err != nil {
		if isclosedconn(err) {
			if n.reconnect(cu, false, 0) {
				n.RemoteInitPoint.conn.clientMessageLocker[cu].Unlock()
				return n.sendToUpstream(ToUniqueID, ChannelID, data, srcid, noneedresp) // 重试
			}
		}
		ThrowError(err)
		return err
	}
	if noneedresp {
		return nil
	}
	// receive send response packet from initpoint
	sendR := make([]byte, PacketBuffer)
	var num int
	if n.RemoteInitPoint.conn.connectionType == 1 {
		num, err = n.RemoteInitPoint.conn.rawConn[cu].Read(sendR)
	} else if n.RemoteInitPoint.conn.connectionType == 2 {
		num, err = n.RemoteInitPoint.conn.tlsConn[cu].Read(sendR)
	}
	if err != nil {
		ThrowError(err)
		return err
	}
	sendR = sendR[:num]
	method, data, _, err := ResolvPacket(sendR)
	if err != nil {
		ThrowError(err)
		return err
	}
	if method != pMethodOK {
		return fmt.Errorf("failed on sending: %s", string(data))
	}
	return nil
}

// child of SendTO
// LOCKER
func (n *NodeTree) sendToDownstream(ToUniqueID [IDlenth]byte, ChannelID [ChannelIDMaxLenth]byte, data []byte, srcid [IDlenth]byte, noneedresp bool) error {
	// switch downstream node
	// get downstream node
	var downstreamID [IDlenth]byte
	downstreamIDByte := ReplaceBits(n.LocalUniqueId[:], int(n.LocalIdMask), int(n.ChildIDEndMask), GetBits(ToUniqueID[:], int(n.LocalIdMask), int(n.ChildIDEndMask)))
	copy(downstreamID[:], downstreamIDByte)
	v, ok := n.Downstream.Load(downstreamID)
	if !ok {
		// data log
		TreeInfo.PacketSendDropped++
		return fmt.Errorf("downstream node not found")
	}
	downstream := v.(*ServerInitPoint)
	// get session
	v, ok = n.Id4Session.Load(downstreamID)
	if !ok {
		// data log
		TreeInfo.PacketSendDropped++
		return fmt.Errorf("session not found")
	}
	session := v.(*Session)
	// build send packet
	sendP := &QDataTransferTo{
		SessionID: session.SessionID,
		SrcNodeID: srcid,
		DstNodeID: ToUniqueID,
		ChannelID: ChannelID,
		Data:      data,
		NoResp:    noneedresp,
	}
	sendPraw, err := sendP.Marshal()
	if err != nil {
		// data log
		TreeInfo.PacketSendDropped++
		ThrowError(err)
		return err
	}
	// data log
	TreeInfo.DataSent += uint64(len(sendPraw))
	TreeInfo.PacketSent++
	// send packet to downstream
	cu := downstream.conn.currentReverseConn
	downstream.conn.currentReverseConn = (downstream.conn.currentReverseConn + 1) % len(downstream.conn.reverseConn)
	if !noneedresp {
		downstream.conn.reverseWriteLock[cu].Lock()
		defer downstream.conn.reverseWriteLock[cu].Unlock()
	}
	sentBytes := 0
	countBytes := 0
	for countBytes < len(sendPraw) {
		countBytes, err = downstream.conn.reverseConn[cu].Write(sendPraw)
		sentBytes += countBytes
	}
	if err != nil {
		ThrowError(err)
		return err
	}
	if noneedresp {
		return nil
	}
	// receive send response packet from downstream
	sendR := make([]byte, PacketBuffer)
	// n.RemoteInitPoint.conn.reverseConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var num int
	num, err = downstream.conn.reverseConn[cu].Read(sendR)
	// n.RemoteInitPoint.conn.reverseConn.SetReadDeadline(time.Time{})
	if err != nil {
		ThrowError(err)
		return err
	}
	sendR = sendR[:num]
	method, data, _, err := ResolvPacket(sendR)
	if err != nil {
		ThrowError(err)
		return err
	}
	if method != pMethodOK {
		return fmt.Errorf("failed on sending: %s", string(data))
	}
	return nil
}

// Build Local Interface for receive local data then transfer to remote node
func (n *NodeTree) BuildInterface() error {
	iface, err := buildLocalInterface()
	if err != nil {
		return err
	}
	n.localInterface = iface
	InterFace = iface
	localIpv6, err := buildLocalIpv6Addr("fd00::", n.LocalUniqueId)
	if err != nil {
		return err
	}
	n.LocalIPv6 = net.ParseIP(localIpv6)
	subnet := "fd00::/64"
	_, Subnet, _ = net.ParseCIDR(subnet)
	_, err = setupInterface(iface, n.LocalIPv6.To16().String(), subnet,
		func(data []byte) {
			onPacket(n, data)
		})
	if err != nil {
		return err
	}

	// Done Init local Interface

	// enter 0xFF 0xFF channel message loop
	go n.ffffchannelLoop()
	return nil
}

func (n *NodeTree) ffffchannelLoop() {
	for {
		data := <-n.LocalInitPoint.dataReadChannel[0xFFFF]
		go onPacket(n, data.Data)
	}
}

func (n *NodeTree) signalEvent() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	// wait signal
	<-sigChan
	// fmt.Println("receive exit signal:", sig)
	// clean up environment
	if n.UpstreamSessionID != nil {
		n.RemoveSelfFromUpstream()
	}
	os.Exit(0)
}

// reconnect connection
// if success it will return true, otherwise it will return false
func (n *NodeTree) reconnect(connIndex int, reverseconn bool, retry int) bool {
	if retry > MaxReconnectRetry {
		return false
	}
	if !AutoReconnect || connIndex < 0 {
		return false
	}
	if reverseconn {
		if connIndex >= len(n.RemoteInitPoint.conn.reverseConn) {
			return false
		}
	} else {
		if connIndex >= len(n.RemoteInitPoint.conn.rawConn) {
			return false
		}
	}

	// close old connection
	var conn net.Conn
	if reverseconn {
		conn = n.RemoteInitPoint.conn.reverseConn[connIndex]
	} else {
		conn = n.RemoteInitPoint.conn.rawConn[connIndex]
	}
	conn.Close()

	newconn, err := net.Dial(n.RemoteInitPoint.NetWork, net.JoinHostPort(n.RemoteInitPoint.IpAddr, fmt.Sprintf("%d", n.RemoteInitPoint.Port)))
	if err != nil {
		return n.reconnect(connIndex, reverseconn, retry+1)
	}

	if reverseconn {
		if n.RemoteInitPoint.tlsSettings.Enabled {
			tlsconn := tls.Client(newconn, &tls.Config{InsecureSkipVerify: true})
			if err = tlsconn.Handshake(); err != nil {
				return n.reconnect(connIndex, reverseconn, retry+1)
			}
			// generate QReverseConnPacket
			QReverseP := &QReverseConnPacket{
				Session:  n.UpstreamSessionID.SessionID,
				UniqueID: n.LocalUniqueId,
			}
			QReversePraw, err := QReverseP.Marshal()
			if err != nil {
				return false
			}
			_, err = tlsconn.Write(QReversePraw)
			if err != nil {
				return n.reconnect(connIndex, reverseconn, retry+1)
			}
			reverseR := make([]byte, PacketBuffer)
			num, err := tlsconn.Read(reverseR)
			if err != nil {
				return n.reconnect(connIndex, reverseconn, retry+1)
			}
			reverseR = reverseR[:num]
			method, _, _, err := ResolvPacket(reverseR)
			if err != nil || method != pMethodOK {
				return n.reconnect(connIndex, reverseconn, retry+1)
			}
			// Update connection
			n.RemoteInitPoint.conn.reverseConn[connIndex] = tlsconn
			n.RemoteInitPoint.conn.rawConn[connIndex] = newconn
			// enter message loop
			go n.reverseConnMessageLoop(tlsconn)
			return true
		} else {
			// No TLS
			QReverseP := &QReverseConnPacket{
				Session:  n.UpstreamSessionID.SessionID,
				UniqueID: n.LocalUniqueId,
			}
			QReversePraw, err := QReverseP.Marshal()
			if err != nil {
				return false
			}
			_, err = newconn.Write(QReversePraw)
			if err != nil {
				return n.reconnect(connIndex, reverseconn, retry+1)
			}
			reverseR := make([]byte, PacketBuffer)
			num, err := newconn.Read(reverseR)
			if err != nil {
				return n.reconnect(connIndex, reverseconn, retry+1)
			}
			reverseR = reverseR[:num]
			method, _, _, err := ResolvPacket(reverseR)
			if err != nil || method != pMethodOK {
				return n.reconnect(connIndex, reverseconn, retry+1)
			}
			n.RemoteInitPoint.conn.rawConn[connIndex] = newconn
			go n.reverseConnMessageLoop(newconn)
			return true
		}
	} else {
		if n.RemoteInitPoint.tlsSettings.Enabled {
			tlsconn := tls.Client(newconn, &tls.Config{InsecureSkipVerify: true})
			if err = tlsconn.Handshake(); err != nil {
				return n.reconnect(connIndex, reverseconn, retry+1)
			}
			n.RemoteInitPoint.conn.tlsConn[connIndex] = tlsconn
		}
		n.RemoteInitPoint.conn.rawConn[connIndex] = newconn
		return true
	}
}
