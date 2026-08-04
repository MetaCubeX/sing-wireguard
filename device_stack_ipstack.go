//go:build with_gvisor

package wireguard

import (
	"context"
	"net"
	"net/netip"
	"syscall"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/udp"
	"github.com/metacubex/gvisor/pkg/waiter"
)

// tcpListenBacklog matches gonet's listener backlog and common Linux
// somaxconn defaults.
const tcpListenBacklog = 4096

// DialTCP establishes an IPv4 or IPv6 TCP connection with an optional local
// address and port. Network must be tcp, tcp4, or tcp6.
func (w *StackDevice) DialTCP(ctx context.Context, network string, source, destination netip.AddrPort) (net.Conn, error) {
	destination = netip.AddrPortFrom(destination.Addr().Unmap(), destination.Port())
	target := net.TCPAddrFromAddrPort(destination)
	wrap := func(source net.Addr, err error) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: network, Source: source, Addr: target, Err: err}
	}
	if err := validateTransportNetwork(network, "tcp", destination.Addr()); err != nil {
		return wrap(nil, err)
	}
	if err := validateRemoteEndpoint(destination); err != nil {
		return wrap(nil, err)
	}
	if err := ctx.Err(); err != nil {
		return wrap(nil, err)
	}
	source = netip.AddrPortFrom(source.Addr().Unmap(), source.Port())
	if err := validateSourceEndpoint(network, source, destination.Addr()); err != nil {
		return wrap(net.TCPAddrFromAddrPort(source), err)
	}
	var local tcpip.FullAddress
	if source.Addr().IsValid() || source.Port() != 0 {
		local = bindFullAddress(source)
	}
	remote := remoteFullAddress(destination)
	connection, err := dialTCPWithBind(ctx, w.stack, local, remote, networkProtocol(destination.Addr()), network == "tcp6", network)
	if err != nil {
		return nil, err
	}
	return connection, nil
}

// ListenTCP creates an IPv4, IPv6, or dual-stack TCP listener. Network must
// be tcp, tcp4, or tcp6, and port zero selects an automatic port.
func (w *StackDevice) ListenTCP(ctx context.Context, network string, local netip.AddrPort) (net.Listener, error) {
	local = netip.AddrPortFrom(local.Addr().Unmap(), local.Port())
	target := net.TCPAddrFromAddrPort(local)
	wrap := func(err error) (net.Listener, error) {
		return nil, &net.OpError{Op: "listen", Net: network, Addr: target, Err: err}
	}
	if err := validateListenAddress(local.Addr()); err != nil {
		return wrap(err)
	}
	if err := ctx.Err(); err != nil {
		return wrap(err)
	}
	protocol, v6Only, err := w.listenProtocol(network, "tcp", local.Addr())
	if err != nil {
		return wrap(err)
	}
	var waitQueue waiter.Queue
	endpoint, tcpipErr := w.stack.NewEndpoint(tcp.ProtocolNumber, protocol, &waitQueue)
	if tcpipErr != nil {
		return wrap(gonet.TranslateNetstackError(tcpipErr))
	}
	endpoint.SocketOptions().SetV6Only(v6Only)
	if tcpipErr = endpoint.Bind(bindFullAddress(local)); tcpipErr != nil {
		endpoint.Close()
		return wrap(gonet.TranslateNetstackError(tcpipErr))
	}
	if tcpipErr = endpoint.Listen(tcpListenBacklog); tcpipErr != nil {
		endpoint.Close()
		return wrap(gonet.TranslateNetstackError(tcpipErr))
	}
	return gonet.NewTCPListener(w.stack, &waitQueue, endpoint), nil
}

// DialUDP creates a connected IPv4 or IPv6 UDP socket with an optional local
// address and port. Network must be udp, udp4, or udp6.
func (w *StackDevice) DialUDP(ctx context.Context, network string, source, destination netip.AddrPort) (net.Conn, error) {
	destination = netip.AddrPortFrom(destination.Addr().Unmap(), destination.Port())
	target := net.UDPAddrFromAddrPort(destination)
	wrap := func(source net.Addr, err error) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: network, Source: source, Addr: target, Err: err}
	}
	if err := validateTransportNetwork(network, "udp", destination.Addr()); err != nil {
		return wrap(nil, err)
	}
	if err := validateRemoteEndpoint(destination); err != nil {
		return wrap(nil, err)
	}
	if err := ctx.Err(); err != nil {
		return wrap(nil, err)
	}
	source = netip.AddrPortFrom(source.Addr().Unmap(), source.Port())
	if err := validateSourceEndpoint(network, source, destination.Addr()); err != nil {
		return wrap(net.UDPAddrFromAddrPort(source), err)
	}
	var waitQueue waiter.Queue
	endpoint, tcpipErr := w.stack.NewEndpoint(udp.ProtocolNumber, networkProtocol(destination.Addr()), &waitQueue)
	if tcpipErr != nil {
		return wrap(nil, gonet.TranslateNetstackError(tcpipErr))
	}
	failed := true
	defer func() {
		if failed {
			endpoint.Close()
		}
	}()
	endpoint.SocketOptions().SetV6Only(network == "udp6")
	if source.Addr().IsValid() || source.Port() != 0 {
		if tcpipErr = endpoint.Bind(bindFullAddress(source)); tcpipErr != nil {
			return wrap(net.UDPAddrFromAddrPort(source), gonet.TranslateNetstackError(tcpipErr))
		}
	}
	if tcpipErr = endpoint.Connect(remoteFullAddress(destination)); tcpipErr != nil {
		return wrap(net.UDPAddrFromAddrPort(source), gonet.TranslateNetstackError(tcpipErr))
	}
	failed = false
	return gonet.NewUDPConn(&waitQueue, endpoint), nil
}

// ListenUDP creates an unconnected IPv4, IPv6, or dual-stack UDP socket.
// Network must be udp, udp4, or udp6, and port zero selects an automatic port.
func (w *StackDevice) ListenUDP(ctx context.Context, network string, local netip.AddrPort) (net.PacketConn, error) {
	local = netip.AddrPortFrom(local.Addr().Unmap(), local.Port())
	target := net.UDPAddrFromAddrPort(local)
	wrap := func(err error) (net.PacketConn, error) {
		return nil, &net.OpError{Op: "listen", Net: network, Addr: target, Err: err}
	}
	if err := validateListenAddress(local.Addr()); err != nil {
		return wrap(err)
	}
	if err := ctx.Err(); err != nil {
		return wrap(err)
	}
	protocol, v6Only, err := w.listenProtocol(network, "udp", local.Addr())
	if err != nil {
		return wrap(err)
	}
	var waitQueue waiter.Queue
	endpoint, tcpipErr := w.stack.NewEndpoint(udp.ProtocolNumber, protocol, &waitQueue)
	if tcpipErr != nil {
		return wrap(gonet.TranslateNetstackError(tcpipErr))
	}
	endpoint.SocketOptions().SetV6Only(v6Only)
	if tcpipErr = endpoint.Bind(bindFullAddress(local)); tcpipErr != nil {
		endpoint.Close()
		return wrap(gonet.TranslateNetstackError(tcpipErr))
	}
	return gonet.NewUDPConn(&waitQueue, endpoint), nil
}

// validateTransportNetwork checks a connected socket's network name and
// explicit destination family.
func validateTransportNetwork(network, protocol string, destination netip.Addr) error {
	switch network {
	case protocol:
		return nil
	case protocol + "4":
		if destination.IsValid() && destination.Is6() {
			return syscall.EAFNOSUPPORT
		}
		return nil
	case protocol + "6":
		if destination.IsValid() && destination.Is4() {
			return syscall.EAFNOSUPPORT
		}
		return nil
	default:
		return net.UnknownNetworkError(network)
	}
}

// validateRemoteEndpoint rejects addresses that cannot identify one unicast
// transport peer.
func validateRemoteEndpoint(destination netip.AddrPort) error {
	address := destination.Addr()
	if !destination.IsValid() || destination.Port() == 0 || address.IsUnspecified() || address.IsMulticast() || address.Zone() != "" {
		return net.InvalidAddrError("invalid remote endpoint")
	}
	return nil
}

// validateSourceEndpoint checks an optional local endpoint before binding.
func validateSourceEndpoint(network string, source netip.AddrPort, remote netip.Addr) error {
	address := source.Addr()
	if !address.IsValid() {
		return nil
	}
	if address.IsMulticast() || address.Zone() != "" {
		return syscall.EINVAL
	}
	if !address.IsUnspecified() && address.Is6() != remote.Is6() {
		return syscall.EAFNOSUPPORT
	}
	if address.IsUnspecified() && (network[len(network)-1] == '4' && address.Is6() || network[len(network)-1] == '6' && address.Is4()) {
		return syscall.EAFNOSUPPORT
	}
	return nil
}

// validateListenAddress rejects multicast and zoned local bindings while
// allowing an invalid or unspecified address to mean wildcard.
func validateListenAddress(address netip.Addr) error {
	if address.IsValid() && (address.IsMulticast() || address.Zone() != "") {
		return net.InvalidAddrError("invalid local endpoint")
	}
	return nil
}

// listenProtocol resolves network and wildcard address semantics to a gVisor
// network protocol and IPV6_V6ONLY setting.
func (w *StackDevice) listenProtocol(network, protocol string, address netip.Addr) (tcpip.NetworkProtocolNumber, bool, error) {
	switch network {
	case protocol + "4":
		if address.IsValid() && address.Is6() {
			return 0, false, syscall.EAFNOSUPPORT
		}
		if w.addr4.Len() == 0 {
			return 0, false, syscall.EADDRNOTAVAIL
		}
		return header.IPv4ProtocolNumber, false, nil
	case protocol + "6":
		if address.IsValid() && address.Is4() {
			return 0, false, syscall.EAFNOSUPPORT
		}
		if w.addr6.Len() == 0 {
			return 0, false, syscall.EADDRNOTAVAIL
		}
		return header.IPv6ProtocolNumber, true, nil
	case protocol:
	default:
		return 0, false, net.UnknownNetworkError(network)
	}
	if address.IsValid() && !address.IsUnspecified() {
		return networkProtocol(address), false, nil
	}
	if w.addr6.Len() != 0 {
		return header.IPv6ProtocolNumber, false, nil
	}
	if w.addr4.Len() != 0 {
		return header.IPv4ProtocolNumber, false, nil
	}
	return 0, false, syscall.EADDRNOTAVAIL
}

// networkProtocol returns gVisor's protocol number for a validated address.
func networkProtocol(address netip.Addr) tcpip.NetworkProtocolNumber {
	if address.Is4() {
		return header.IPv4ProtocolNumber
	}
	return header.IPv6ProtocolNumber
}

// bindFullAddress converts an optional local endpoint. Invalid and
// unspecified addresses become gVisor's wildcard address.
func bindFullAddress(endpoint netip.AddrPort) tcpip.FullAddress {
	address := endpoint.Addr()
	fullAddress := tcpip.FullAddress{NIC: defaultNIC, Port: endpoint.Port()}
	if address.IsValid() && !address.IsUnspecified() {
		fullAddress.Addr = AddressFromAddr(address)
	}
	return fullAddress
}

// remoteFullAddress converts one validated remote endpoint.
func remoteFullAddress(endpoint netip.AddrPort) tcpip.FullAddress {
	return tcpip.FullAddress{NIC: defaultNIC, Addr: AddressFromAddr(endpoint.Addr()), Port: endpoint.Port()}
}
