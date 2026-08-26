//go:build with_gvisor

package wireguard

import (
	"bytes"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/waiter"
)

var (
	_ net.Conn       = (*gIPConn)(nil)
	_ net.PacketConn = (*gIPConn)(nil)
)

// Complete-packet IP socket semantics
//
// Read and ReadFrom return one complete IPv4 or IPv6 packet, including its IP
// header. A short buffer receives the packet prefix and consumes the rest of
// that packet; a zero-length buffer also consumes one packet. ReadFrom reports
// the source address carried by the packet.
//
// Write and WriteTo require a complete IP packet. The connected peer or the
// address passed to WriteTo selects the route, while the destination in the
// supplied IP header is emitted on the wire. Writes copy the packet and do not
// modify the caller's buffer. TTL or Hop Limit, Traffic Class, Flow Label, and
// transport checksums are preserved, so callers must provide valid values,
// including the ICMPv6 checksum.
//
// Before transmission, IPv4 total length, an unspecified source address, and
// the IP header checksum are repaired. A zero IPv4 ID is assigned for a
// non-atomic datagram. IPv6 payload length and an unspecified source address
// are repaired. On receive, IPv6 raw protocol dispatch occurs before extension
// header processing, so an extension header in the base Next Header field does
// not reach the final protocol's connection. Header-included ICMPv6 packets are
// delivered without transport-checksum validation.
//
// This differs from net.IPConn backed by a system raw socket, whose exact
// representation is platform-dependent. ReadFrom strips a recognized IPv4
// header, while IPv6 raw reads normally return only the transport payload;
// Read and ReadMsgIP may also differ from ReadFrom. Default raw writes accept a
// transport payload and let the kernel construct the IP header unless a
// platform-specific header-inclusion option is enabled. gIPConn instead uses
// the same complete-packet representation for both address families and for
// every read and write method it implements.

// gIPConn is a connected or unconnected gVisor complete-packet IP socket.
type gIPConn struct {
	endpoint tcpip.Endpoint
	waiter   *waiter.Queue
	network  string
	v6       bool
	local    netip.Addr
	remote   netip.Addr

	readDeadline  ipDeadline
	writeDeadline ipDeadline
	closeOnce     sync.Once
	closed        chan struct{}
}

type ipDeadline struct {
	access  sync.Mutex
	value   time.Time
	changed chan struct{}
}

func newIPDeadline() ipDeadline {
	return ipDeadline{changed: make(chan struct{})}
}

func (d *ipDeadline) set(value time.Time) {
	d.access.Lock()
	d.value = value
	close(d.changed)
	d.changed = make(chan struct{})
	d.access.Unlock()
}

func (d *ipDeadline) snapshot() (time.Time, <-chan struct{}) {
	d.access.Lock()
	value, changed := d.value, d.changed
	d.access.Unlock()
	return value, changed
}

func (d *ipDeadline) expired() bool {
	value, _ := d.snapshot()
	return !value.IsZero() && !time.Now().Before(value)
}

type ipReadMessage struct {
	count  int
	remote tcpip.FullAddress
}

func newIPConn(endpoint tcpip.Endpoint, waitQueue *waiter.Queue, network string, v6 bool, local, remote netip.Addr) *gIPConn {
	return &gIPConn{
		endpoint:      endpoint,
		waiter:        waitQueue,
		network:       network,
		v6:            v6,
		local:         local,
		remote:        remote,
		readDeadline:  newIPDeadline(),
		writeDeadline: newIPDeadline(),
		closed:        make(chan struct{}),
	}
}

// Read implements net.Conn.Read. Reads contain a complete IPv4 or IPv6 packet.
func (c *gIPConn) Read(buffer []byte) (int, error) {
	message, err := c.readMessage(buffer)
	if err != nil {
		return 0, c.operationError("read", nil, err)
	}
	return message.count, nil
}

// ReadFrom implements net.PacketConn.ReadFrom. Reads contain a complete IPv4
// or IPv6 packet.
func (c *gIPConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	message, err := c.readMessage(buffer)
	address := ipAddrFromFullAddress(message.remote)
	if err != nil {
		return 0, address, c.operationError("read", address, err)
	}
	return message.count, address, nil
}

func (c *gIPConn) readMessage(buffer []byte) (ipReadMessage, error) {
	if c.readDeadline.expired() {
		return ipReadMessage{}, os.ErrDeadlineExceeded
	}
	select {
	case <-c.closed:
		return ipReadMessage{}, net.ErrClosed
	default:
	}

	readBuffer := buffer
	var zeroLengthScratch [1]byte
	if len(readBuffer) == 0 {
		readBuffer = zeroLengthScratch[:]
	}
	readOnce := func() (tcpip.ReadResult, tcpip.Error) {
		writer := tcpip.SliceWriter(readBuffer)
		return c.endpoint.Read(&writer, tcpip.ReadOptions{NeedRemoteAddr: true})
	}
	result, tcpipErr := readOnce()
	if _, blocked := tcpipErr.(*tcpip.ErrWouldBlock); blocked {
		entry, notify := waiter.NewChannelEntry(waiter.ReadableEvents)
		c.waiter.EventRegister(&entry)
		defer c.waiter.EventUnregister(&entry)
		for {
			result, tcpipErr = readOnce()
			if _, blocked = tcpipErr.(*tcpip.ErrWouldBlock); !blocked {
				break
			}
			if err := c.wait(notify, &c.readDeadline); err != nil {
				return ipReadMessage{}, err
			}
		}
	}
	if tcpipErr != nil {
		if _, closed := tcpipErr.(*tcpip.ErrClosedForReceive); closed {
			return ipReadMessage{}, net.ErrClosed
		}
		return ipReadMessage{}, gonet.TranslateNetstackError(tcpipErr)
	}
	count := result.Count
	if count > len(buffer) {
		count = len(buffer)
	}
	return ipReadMessage{count: count, remote: result.RemoteAddr}, nil
}

// Write implements net.Conn.Write and requires a connected IP socket. Packet
// must contain a complete IPv4 or IPv6 header.
func (c *gIPConn) Write(packet []byte) (int, error) {
	if !c.remote.IsValid() {
		return 0, c.operationError("write", nil, syscall.EDESTADDRREQ)
	}
	return c.writePacket(packet, c.remote, false)
}

// WriteTo implements net.PacketConn.WriteTo. Packet must contain a complete
// IPv4 or IPv6 header; address selects the route.
func (c *gIPConn) WriteTo(packet []byte, address net.Addr) (int, error) {
	if c.remote.IsValid() {
		return 0, c.operationError("write", address, net.ErrWriteToConnected)
	}
	ipAddress, ok := address.(*net.IPAddr)
	if !ok {
		return 0, c.operationError("write", address, syscall.EINVAL)
	}
	target, err := netipFromIPAddr(ipAddress)
	if err != nil {
		return 0, c.operationError("write", address, err)
	}
	return c.writePacket(packet, target, true)
}

func (c *gIPConn) writePacket(packet []byte, target netip.Addr, withTarget bool) (int, error) {
	address := ipNetAddr(target)
	if !target.IsValid() || target.IsUnspecified() || target.Zone() != "" {
		return 0, c.operationError("write", address, syscall.EINVAL)
	}
	if target.Is6() != c.v6 {
		return 0, c.operationError("write", address, syscall.EAFNOSUPPORT)
	}
	if c.writeDeadline.expired() {
		return 0, c.operationError("write", address, os.ErrDeadlineExceeded)
	}
	select {
	case <-c.closed:
		return 0, c.operationError("write", address, net.ErrClosed)
	default:
	}

	options := tcpip.WriteOptions{Atomic: true}
	if withTarget {
		options.To = &tcpip.FullAddress{NIC: defaultNIC, Addr: AddressFromAddr(target)}
	}
	writeOnce := func() (int64, tcpip.Error) {
		return c.endpoint.Write(bytes.NewReader(packet), options)
	}
	written, tcpipErr := writeOnce()
	if _, blocked := tcpipErr.(*tcpip.ErrWouldBlock); blocked {
		entry, notify := waiter.NewChannelEntry(waiter.WritableEvents)
		c.waiter.EventRegister(&entry)
		defer c.waiter.EventUnregister(&entry)
		for {
			written, tcpipErr = writeOnce()
			if _, blocked = tcpipErr.(*tcpip.ErrWouldBlock); !blocked {
				break
			}
			if err := c.wait(notify, &c.writeDeadline); err != nil {
				return int(written), c.operationError("write", address, err)
			}
		}
	}
	if tcpipErr != nil {
		if _, closed := tcpipErr.(*tcpip.ErrClosedForSend); closed {
			return int(written), c.operationError("write", address, net.ErrClosed)
		}
		return int(written), c.operationError("write", address, gonet.TranslateNetstackError(tcpipErr))
	}
	return int(written), nil
}

func (c *gIPConn) wait(notify <-chan struct{}, deadline *ipDeadline) error {
	for {
		value, changed := deadline.snapshot()
		if value.IsZero() {
			select {
			case <-notify:
				return nil
			case <-changed:
				continue
			case <-c.closed:
				return net.ErrClosed
			}
		}
		remaining := time.Until(value)
		if remaining <= 0 {
			return os.ErrDeadlineExceeded
		}
		timer := time.NewTimer(remaining)
		select {
		case <-notify:
			stopTimer(timer)
			return nil
		case <-changed:
			stopTimer(timer)
			continue
		case <-c.closed:
			stopTimer(timer)
			return net.ErrClosed
		case <-timer.C:
			return os.ErrDeadlineExceeded
		}
	}
}

func stopTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

// Close closes the endpoint and wakes blocked operations.
func (c *gIPConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.endpoint.Close()
	})
	return nil
}

func (c *gIPConn) LocalAddr() net.Addr {
	return ipNetAddr(c.local)
}

func (c *gIPConn) RemoteAddr() net.Addr {
	if !c.remote.IsValid() {
		return nil
	}
	return ipNetAddr(c.remote)
}

func (c *gIPConn) SetDeadline(deadline time.Time) error {
	if c.isClosed() {
		return c.operationError("set", nil, net.ErrClosed)
	}
	c.readDeadline.set(deadline)
	c.writeDeadline.set(deadline)
	return nil
}

func (c *gIPConn) SetReadDeadline(deadline time.Time) error {
	if c.isClosed() {
		return c.operationError("set", nil, net.ErrClosed)
	}
	c.readDeadline.set(deadline)
	return nil
}

func (c *gIPConn) SetWriteDeadline(deadline time.Time) error {
	if c.isClosed() {
		return c.operationError("set", nil, net.ErrClosed)
	}
	c.writeDeadline.set(deadline)
	return nil
}

func (c *gIPConn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

func (c *gIPConn) operationError(operation string, address net.Addr, err error) error {
	return &net.OpError{
		Op:     operation,
		Net:    c.network,
		Source: c.LocalAddr(),
		Addr:   address,
		Err:    err,
	}
}

func ipNetAddr(address netip.Addr) *net.IPAddr {
	if !address.IsValid() {
		return nil
	}
	return &net.IPAddr{IP: net.IP(address.AsSlice()), Zone: address.Zone()}
}

func ipAddrFromFullAddress(address tcpip.FullAddress) *net.IPAddr {
	converted, valid := netipFromTCPIPAddress(address.Addr)
	if !valid {
		return nil
	}
	return ipNetAddr(converted)
}

func netipFromIPAddr(address *net.IPAddr) (netip.Addr, error) {
	if address == nil || address.Zone != "" {
		return netip.Addr{}, syscall.EINVAL
	}
	converted, valid := netip.AddrFromSlice(address.IP)
	if !valid {
		return netip.Addr{}, syscall.EINVAL
	}
	return converted.Unmap(), nil
}

func netipFromTCPIPAddress(address tcpip.Address) (netip.Addr, bool) {
	switch address.Len() {
	case 4:
		return netip.AddrFrom4(address.As4()), true
	case 16:
		return netip.AddrFrom16(address.As16()), true
	default:
		return netip.Addr{}, false
	}
}
