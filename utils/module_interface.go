package utils

import "errors"

var (
	ErrChannelExists = errors.New("channel already exists")
)

func (n *NodeTree) RegisterChannel(channelID [2]byte, callFunction func(Message)) error {
	if n.ChannelEventHandlers[ByteToUInt16(channelID)] != nil { // already registered
		return ErrChannelExists
	}
	n.ChannelEventHandlers[ByteToUInt16(channelID)] = callFunction
	return nil
}

func (n *NodeTree) UnregisterChannel(channelID [2]byte) {
	n.ChannelEventHandlers[ByteToUInt16(channelID)] = nil
}

func (n *NodeTree) RegisterEvent(eventID int, callFunction func(interface{})) bool {
	if eventID < len(n.EventHandlers) || eventID >= 0 {
		n.EventHandlers[eventID] = append(n.EventHandlers[eventID], callFunction)
		return true
	}
	return false
}
