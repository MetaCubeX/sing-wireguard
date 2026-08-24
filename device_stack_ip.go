//go:build with_gvisor

package wireguard

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/waiter"
)

var _ IPPacketStack = (*StackDevice)(nil)

func (w *StackDevice) DialIPPacket(ctx context.Context, network string, source, destination netip.Addr) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var (
		transportProtocol tcpip.TransportProtocolNumber
		networkProtocol   tcpip.NetworkProtocolNumber
	)
	switch network {
	case "ip4:icmp":
		if !source.Is4() || !destination.Is4() {
			return nil, fmt.Errorf("IPv4 ICMP requires IPv4 source and destination")
		}
		transportProtocol = header.ICMPv4ProtocolNumber
		networkProtocol = header.IPv4ProtocolNumber
	case "ip6:ipv6-icmp":
		if !source.Is6() || !destination.Is6() {
			return nil, fmt.Errorf("IPv6 ICMP requires IPv6 source and destination")
		}
		transportProtocol = header.ICMPv6ProtocolNumber
		networkProtocol = header.IPv6ProtocolNumber
	default:
		return nil, fmt.Errorf("unsupported IP packet network: %s", network)
	}

	var wq waiter.Queue
	endpoint, gErr := w.stack.NewRawEndpoint(transportProtocol, networkProtocol, &wq, true)
	if gErr != nil {
		return nil, gonet.TranslateNetstackError(gErr)
	}
	endpoint.SocketOptions().SetHeaderIncluded(true)
	if gErr = endpoint.Bind(tcpip.FullAddress{NIC: defaultNIC, Addr: AddressFromAddr(source)}); gErr != nil {
		endpoint.Close()
		return nil, gonet.TranslateNetstackError(gErr)
	}
	if gErr = endpoint.Connect(tcpip.FullAddress{NIC: defaultNIC, Addr: AddressFromAddr(destination)}); gErr != nil {
		endpoint.Close()
		return nil, gonet.TranslateNetstackError(gErr)
	}
	connectionContext, connectionCancel := context.WithCancel(w.ctx)
	return &ipPacketConn{
		Conn:            gonet.NewTCPConn(&wq, endpoint),
		device:          w,
		ctx:             connectionContext,
		ctxCancel:       connectionCancel,
		networkProtocol: networkProtocol,
		source:          AddressFromAddr(source),
		destination:     AddressFromAddr(destination),
	}, nil
}

type ipPacketConn struct {
	net.Conn
	device          *StackDevice
	ctx             context.Context
	ctxCancel       context.CancelFunc
	networkProtocol tcpip.NetworkProtocolNumber
	source          tcpip.Address
	destination     tcpip.Address
	closeOnce       sync.Once
	closeErr        error
	closed          atomic.Bool
}

func (c *ipPacketConn) Write(packet []byte) (int, error) {
	if c.closed.Load() {
		return 0, os.ErrClosed
	}
	if len(packet) > int(c.device.mtu) {
		return 0, fmt.Errorf("IP packet size %d exceeds MTU %d", len(packet), c.device.mtu)
	}
	if err := c.validatePacket(packet); err != nil {
		return 0, err
	}
	if err := c.device.writeIPPacket(c.ctx, packet); err != nil {
		return 0, err
	}
	return len(packet), nil
}

func (c *ipPacketConn) validatePacket(packet []byte) error {
	switch c.networkProtocol {
	case header.IPv4ProtocolNumber:
		if len(packet) < header.IPv4MinimumSize {
			return fmt.Errorf("invalid IPv4 ICMP packet")
		}
		ipHeader := header.IPv4(packet)
		if !ipHeader.IsValid(len(packet)) || int(ipHeader.TotalLength()) != len(packet) || ipHeader.TransportProtocol() != header.ICMPv4ProtocolNumber || len(ipHeader.Payload()) < header.ICMPv4MinimumSize {
			return fmt.Errorf("invalid IPv4 ICMP packet")
		}
		if ipHeader.SourceAddress() != c.source || ipHeader.DestinationAddress() != c.destination {
			return fmt.Errorf("IPv4 packet endpoints do not match connection")
		}
	case header.IPv6ProtocolNumber:
		if len(packet) < header.IPv6MinimumSize {
			return fmt.Errorf("invalid IPv6 ICMP packet")
		}
		ipHeader := header.IPv6(packet)
		if !ipHeader.IsValid(len(packet)) || header.IPv6MinimumSize+int(ipHeader.PayloadLength()) != len(packet) || ipHeader.TransportProtocol() != header.ICMPv6ProtocolNumber || len(ipHeader.Payload()) < header.ICMPv6MinimumSize {
			return fmt.Errorf("invalid IPv6 ICMP packet")
		}
		if ipHeader.SourceAddress() != c.source || ipHeader.DestinationAddress() != c.destination {
			return fmt.Errorf("IPv6 packet endpoints do not match connection")
		}
	default:
		panic("unexpected IP network protocol")
	}
	return nil
}

func (c *ipPacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.ctxCancel()
		c.closeErr = c.Conn.Close()
	})
	return c.closeErr
}

func (w *StackDevice) writeIPPacket(ctx context.Context, packet []byte) error {
	if err := ctx.Err(); err != nil {
		return os.ErrClosed
	}
	packetBuffer := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(packet),
	})
	select {
	case <-ctx.Done():
		packetBuffer.DecRef()
		return os.ErrClosed
	case w.outbound <- packetBuffer:
		return nil
	}
}

var _ net.Conn = (*ipPacketConn)(nil)
