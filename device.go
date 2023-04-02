package wireguard

import (
	"net/netip"

	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/wireguard-go/tun"
)

type Device interface {
	tun.Device
	N.Dialer
	Start() error
	Inet4Address() netip.Addr
	Inet6Address() netip.Addr
	// NewEndpoint() (stack.LinkEndpoint, error)
}
