//go:build with_gvisor

package wireguard

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/waiter"
)

// DialTCPWithBind creates a TCP connection after binding the supplied local
// endpoint. It is retained for compatibility; StackDevice.DialTCP provides
// standard network-name and netip address semantics.
func DialTCPWithBind(ctx context.Context, s *stack.Stack, localAddr, remoteAddr tcpip.FullAddress, network tcpip.NetworkProtocolNumber) (*gonet.TCPConn, error) {
	return dialTCPWithBind(ctx, s, localAddr, remoteAddr, network, false, "tcp")
}

// dialTCPWithBind creates a TCP endpoint with explicit address-family and
// IPv6-only semantics.
func dialTCPWithBind(ctx context.Context, s *stack.Stack, localAddr, remoteAddr tcpip.FullAddress, network tcpip.NetworkProtocolNumber, v6Only bool, networkName string) (_ *gonet.TCPConn, retErr error) {
	// Create TCP endpoint, then connect.
	var wq waiter.Queue
	ep, err := s.NewEndpoint(tcp.ProtocolNumber, network, &wq)
	if err != nil {
		return nil, tcpDialError(networkName, localAddr, remoteAddr, gonet.TranslateNetstackError(err))
	}
	defer func() {
		if retErr != nil {
			ep.Close()
		}
	}()
	ep.SocketOptions().SetV6Only(v6Only)

	// Create wait queue entry that notifies a channel.
	//
	// We do this unconditionally as Connect will always return an error.
	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.WritableEvents)
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)

	select {
	case <-ctx.Done():
		return nil, tcpDialError(networkName, localAddr, remoteAddr, ctx.Err())
	default:
	}

	// Bind before connect if requested.
	if localAddr != (tcpip.FullAddress{}) {
		if err = ep.Bind(localAddr); err != nil {
			return nil, tcpDialError(networkName, localAddr, remoteAddr, gonet.TranslateNetstackError(err))
		}
	}

	err = ep.Connect(remoteAddr)
	if _, ok := err.(*tcpip.ErrConnectStarted); ok {
		select {
		case <-ctx.Done():
			return nil, tcpDialError(networkName, localAddr, remoteAddr, ctx.Err())
		case <-notifyCh:
		}

		err = ep.LastError()
	}
	if err != nil {
		return nil, tcpDialError(networkName, localAddr, remoteAddr, gonet.TranslateNetstackError(err))
	}

	// sing-box added: set keepalive
	ep.SocketOptions().SetKeepAlive(true)
	keepAliveIdle := tcpip.KeepaliveIdleOption(15 * time.Second)
	ep.SetSockOpt(&keepAliveIdle)
	keepAliveInterval := tcpip.KeepaliveIntervalOption(15 * time.Second)
	ep.SetSockOpt(&keepAliveInterval)

	return gonet.NewTCPConn(&wq, ep), nil
}

// tcpDialError returns the standard net.OpError shape for endpoint creation,
// binding, connection, and cancellation failures.
func tcpDialError(network string, localAddr, remoteAddr tcpip.FullAddress, err error) error {
	return &net.OpError{
		Op:     "dial",
		Net:    network,
		Source: tcpAddrFromFullAddress(localAddr),
		Addr:   tcpAddrFromFullAddress(remoteAddr),
		Err:    err,
	}
}

// tcpAddrFromFullAddress converts a gVisor address without assuming that an
// optional local address is present.
func tcpAddrFromFullAddress(address tcpip.FullAddress) net.Addr {
	if address == (tcpip.FullAddress{}) {
		return nil
	}
	converted := &net.TCPAddr{Port: int(address.Port)}
	if address.Addr.Len() == 4 || address.Addr.Len() == 16 {
		ipAddress := AddrFromAddress(address.Addr)
		converted.IP = ipAddress.AsSlice()
	}
	return converted
}

// AddressFromAddr converts a valid IPv4 or IPv6 address to gVisor form.
func AddressFromAddr(destination netip.Addr) tcpip.Address {
	if destination.Is6() {
		return tcpip.AddrFrom16(destination.As16())
	} else {
		return tcpip.AddrFrom4(destination.As4())
	}
}

// AddrFromAddress converts a gVisor IPv4 or IPv6 address to netip form.
func AddrFromAddress(address tcpip.Address) netip.Addr {
	if address.Len() == 16 {
		return netip.AddrFrom16(address.As16())
	} else {
		return netip.AddrFrom4(address.As4())
	}
}
