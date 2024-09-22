package wireguard

import (
	"net/netip"

	"github.com/metacubex/wireguard-go/tun"
	N "github.com/sagernet/sing/common/network"
)

type Device interface {
	tun.Device
	N.Dialer
	Start() error
	Inet4Address() netip.Addr
	Inet6Address() netip.Addr
	// NewEndpoint() (stack.LinkEndpoint, error)
}
