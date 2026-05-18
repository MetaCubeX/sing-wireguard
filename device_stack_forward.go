//go:build with_gvisor

package wireguard

import (
	"context"
	"net/netip"
	"time"

	"github.com/metacubex/sing/common/bufio"
	M "github.com/metacubex/sing/common/metadata"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/udp"
	"github.com/metacubex/gvisor/pkg/waiter"
)

type stackForwarder struct {
	ctx     context.Context
	handler ForwardHandler
}

func registerForwardHandler(ctx context.Context, ipStack *stack.Stack, handler ForwardHandler) {
	s := &stackForwarder{ctx: ctx, handler: handler}
	ipStack.SetSpoofing(defaultNIC, true)        // allow sending any SrcIP
	ipStack.SetPromiscuousMode(defaultNIC, true) // allow receiving any DstIP
	ipStack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcp.NewForwarder(ipStack, 0, 1024, s.tcpForward).HandlePacket)
	ipStack.SetTransportProtocolHandler(udp.ProtocolNumber, udp.NewForwarder(ipStack, s.udpForward).HandlePacket)
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

func (w *stackForwarder) udpForward(r *udp.ForwarderRequest) bool {
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
		return false
	}
	sess := r.ID()
	srcAddr := netip.AddrPortFrom(AddrFromAddress(sess.RemoteAddress), sess.RemotePort)
	dstAddr := netip.AddrPortFrom(AddrFromAddress(sess.LocalAddress), sess.LocalPort)
	udpConn := gonet.NewUDPConn(&wq, endpoint)
	go func() {
		var metadata M.Metadata
		metadata.Source = M.SocksaddrFromNetIP(srcAddr)
		metadata.Destination = M.SocksaddrFromNetIP(dstAddr)
		hErr := w.handler.NewPacketConnection(w.ctx, bufio.NewPacketConn(udpConn), metadata)
		if hErr != nil {
			endpoint.Abort()
		}
	}()
	return true
}
