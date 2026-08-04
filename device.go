package wireguard

import (
	"context"
	"net"
	"net/netip"

	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	"github.com/metacubex/wireguard-go/tun"
)

type Device interface {
	tun.Device
	N.Dialer
	Start() error
	DialTCP(ctx context.Context, network string, source, destination netip.AddrPort) (net.Conn, error)
	ListenTCP(ctx context.Context, network string, local netip.AddrPort) (net.Listener, error)
	DialUDP(ctx context.Context, network string, source, destination netip.AddrPort) (net.Conn, error)
	ListenUDP(ctx context.Context, network string, local netip.AddrPort) (net.PacketConn, error)
	LocalAddresses() []netip.Addr
	Inet4Address() netip.Addr
	Inet6Address() netip.Addr
	// NewEndpoint() (stack.LinkEndpoint, error)
}

type RegisterForward interface {
	RegisterForward(options ForwardOptions) error
}

type ForwardHandler interface {
	N.TCPConnectionHandler
	PacketForwardHandler
}

type PacketForwardHandler interface {
	NewPacket(ctx context.Context, key netip.AddrPort, buffer *buf.Buffer, metadata M.Metadata, init func(natConn N.PacketConn) N.PacketWriter)
}

type ForwardOptions struct {
	Handler ForwardHandler
}
