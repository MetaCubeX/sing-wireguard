package wireguard

import (
	"net/netip"

	N "github.com/metacubex/sing/common/network"
	"github.com/metacubex/wireguard-go/tun"
)

type Device interface {
	tun.Device
	N.Dialer
	Start() error
	Inet4Address() netip.Addr
	Inet6Address() netip.Addr
	// NewEndpoint() (stack.LinkEndpoint, error)
}
