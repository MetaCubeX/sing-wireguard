package wireguard

import (
	"context"
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
	Inet4Address() netip.Addr
	Inet6Address() netip.Addr
	RegisterForward(options ForwardOptions) error
	// NewEndpoint() (stack.LinkEndpoint, error)
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
