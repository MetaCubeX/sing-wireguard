//go:build !with_gvisor

package wireguard

import (
	"net/netip"

	E "github.com/sagernet/sing/common/exceptions"
)

var ErrGVisorNotIncluded = E.New(`gVisor is not included in this build, rebuild with -tags with_gvisor`)

func NewStackDevice(localAddresses []netip.Prefix, mtu uint32) (Device, error) {
	return nil, ErrGVisorNotIncluded
}
