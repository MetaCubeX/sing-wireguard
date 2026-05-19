//go:build with_gvisor

package wireguard

import (
	"context"
	"math"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/metacubex/sing/common/buf"
	E "github.com/metacubex/sing/common/exceptions"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/checksum"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/udp"
	"github.com/metacubex/gvisor/pkg/waiter"
)

type stackForwarder struct {
	ctx     context.Context
	stack   *stack.Stack
	handler ForwardHandler
}

func (w *StackDevice) RegisterForward(options ForwardOptions) error {
	ctx := w.ctx
	ipStack := w.stack
	handler := options.Handler
	s := &stackForwarder{ctx: ctx, stack: ipStack, handler: handler}
	ipStack.SetSpoofing(defaultNIC, true)        // allow sending any SrcIP
	ipStack.SetPromiscuousMode(defaultNIC, true) // allow receiving any DstIP
	ipStack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcp.NewForwarder(ipStack, 0, 1024, s.tcpForward).HandlePacket)
	ipStack.SetTransportProtocolHandler(udp.ProtocolNumber, s.udpForward)
	return nil
}

func (w *stackForwarder) tcpForward(r *tcp.ForwarderRequest) {
	var wq waiter.Queue
	handshakeCtx, cancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-w.ctx.Done():
			wq.Notify(wq.Events())
		case <-handshakeCtx.Done():
		}
	}()
	endpoint, err := r.CreateEndpoint(&wq)
	cancel()
	if err != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)
	endpoint.SocketOptions().SetKeepAlive(true)
	keepAliveIdle := tcpip.KeepaliveIdleOption(15 * time.Second)
	endpoint.SetSockOpt(&keepAliveIdle)
	keepAliveInterval := tcpip.KeepaliveIntervalOption(15 * time.Second)
	endpoint.SetSockOpt(&keepAliveInterval)
	tcpConn := gonet.NewTCPConn(&wq, endpoint)
	lAddr := tcpConn.RemoteAddr()
	rAddr := tcpConn.LocalAddr()
	if lAddr == nil || rAddr == nil {
		tcpConn.Close()
		return
	}
	go func() {
		var metadata M.Metadata
		metadata.Source = M.SocksaddrFromNet(lAddr)
		metadata.Destination = M.SocksaddrFromNet(rAddr)
		hErr := w.handler.NewConnection(w.ctx, tcpConn, metadata)
		if hErr != nil {
			endpoint.Abort()
		}
	}()
}

func (w *stackForwarder) udpForward(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	var upstreamMetadata M.Metadata
	upstreamMetadata.Source = M.SocksaddrFrom(AddrFromAddress(id.RemoteAddress), id.RemotePort)
	upstreamMetadata.Destination = M.SocksaddrFrom(AddrFromAddress(id.LocalAddress), id.LocalPort)
	proto := header.IPv6ProtocolNumber
	if upstreamMetadata.Source.IsIPv4() {
		proto = header.IPv4ProtocolNumber
	}
	gBuffer := pkt.Data().ToBuffer()
	sBuffer := buf.NewSize(int(gBuffer.Size()))
	gBuffer.Apply(func(view *buffer.View) {
		sBuffer.Write(view.AsSlice())
	})
	w.handler.NewPacket(
		w.ctx,
		upstreamMetadata.Source.AddrPort(),
		sBuffer,
		upstreamMetadata,
		func(natConn N.PacketConn) N.PacketWriter {
			return &udpBackWriter{
				stack:         w.stack,
				source:        id.RemoteAddress,
				sourcePort:    id.RemotePort,
				sourceNetwork: proto,
			}
		},
	)
	return true
}

type udpBackWriter struct {
	access        sync.Mutex
	stack         *stack.Stack
	source        tcpip.Address
	sourcePort    uint16
	sourceNetwork tcpip.NetworkProtocolNumber
}

func (w *udpBackWriter) WritePacket(packetBuffer *buf.Buffer, destination M.Socksaddr) error {
	if !destination.IsIP() {
		return E.Cause(os.ErrInvalid, "invalid destination")
	} else if destination.IsIPv4() && w.sourceNetwork == header.IPv6ProtocolNumber {
		destination = M.SocksaddrFrom(netip.AddrFrom16(destination.Addr.As16()), destination.Port)
	} else if destination.IsIPv6() && (w.sourceNetwork == header.IPv4ProtocolNumber) {
		return E.New("send IPv6 packet to IPv4 connection")
	}

	defer packetBuffer.Release()

	route, err := w.stack.FindRoute(
		defaultNIC,
		AddressFromAddr(destination.Addr),
		w.source,
		w.sourceNetwork,
		false,
	)
	if err != nil {
		return gonet.TranslateNetstackError(err)
	}
	defer route.Release()

	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.UDPMinimumSize + int(route.MaxHeaderLength()),
		Payload:            buffer.MakeWithData(packetBuffer.Bytes()),
	})
	defer packet.DecRef()

	packet.TransportProtocolNumber = header.UDPProtocolNumber
	udpHdr := header.UDP(packet.TransportHeader().Push(header.UDPMinimumSize))
	pLen := uint16(packet.Size())
	udpHdr.Encode(&header.UDPFields{
		SrcPort: destination.Port,
		DstPort: w.sourcePort,
		Length:  pLen,
	})

	if route.RequiresTXTransportChecksum() && w.sourceNetwork == header.IPv6ProtocolNumber {
		xsum := udpHdr.CalculateChecksum(checksum.Combine(
			route.PseudoHeaderChecksum(header.UDPProtocolNumber, pLen),
			packet.Data().Checksum(),
		))
		if xsum != math.MaxUint16 {
			xsum = ^xsum
		}
		udpHdr.SetChecksum(xsum)
	}

	err = route.WritePacket(stack.NetworkHeaderParams{
		Protocol: header.UDPProtocolNumber,
		TTL:      route.DefaultTTL(),
		TOS:      0,
	}, packet)
	if err != nil {
		route.Stats().UDP.PacketSendErrors.Increment()
		return gonet.TranslateNetstackError(err)
	}

	route.Stats().UDP.PacketsSent.Increment()
	return nil
}
