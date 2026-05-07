package wireguard

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/metacubex/sing/common/bufio"
	E "github.com/metacubex/sing/common/exceptions"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	"github.com/metacubex/wireguard-go/conn"
)

var _ conn.Bind = (*ClientBind)(nil)

type ClientBind struct {
	ctx                 context.Context
	bindCtx             context.Context
	bindDone            context.CancelFunc
	errorHandler        E.Handler
	dialer              N.Dialer
	reservedForEndpoint map[netip.AddrPort][3]uint8
	connAccess          sync.Mutex
	conn                *wireConn
	closed              atomic.Bool
	isConnect           bool
	connectAddr         netip.AddrPort
	reserved            [3]uint8
	parseReserved       bool
}

func NewClientBind(ctx context.Context, errorHandler E.Handler, dialer N.Dialer, isConnect bool, connectAddr netip.AddrPort, reserved [3]uint8) *ClientBind {
	return &ClientBind{
		ctx:                 ctx,
		errorHandler:        errorHandler,
		dialer:              dialer,
		reservedForEndpoint: make(map[netip.AddrPort][3]uint8),
		isConnect:           isConnect,
		connectAddr:         connectAddr,
		reserved:            reserved,
		parseReserved:       true,
	}
}

func (c *ClientBind) connect() (*wireConn, error) {
	c.connAccess.Lock()
	defer c.connAccess.Unlock()
	if c.closed.Load() {
		return nil, net.ErrClosed
	}
	serverConn := c.conn
	if serverConn != nil {
		if !serverConn.closed.Load() {
			return serverConn, nil
		}
	}
	var packetConn net.PacketConn
	if c.isConnect {
		udpConn, err := c.dialer.DialContext(c.bindCtx, N.NetworkUDP, M.SocksaddrFromNetIP(c.connectAddr))
		if err != nil {
			return nil, err
		}
		packetConn = bufio.NewUnbindPacketConn(udpConn)
	} else {
		udpConn, err := c.dialer.ListenPacket(c.bindCtx, M.Socksaddr{Addr: netip.IPv4Unspecified()})
		if err != nil {
			return nil, err
		}
		packetConn = udpConn
	}
	serverConn = &wireConn{PacketConn: packetConn}
	c.conn = serverConn
	return serverConn, nil
}

func (c *ClientBind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	c.closed.Store(false)
	c.bindCtx, c.bindDone = context.WithCancel(c.ctx)
	return []conn.ReceiveFunc{c.receive}, 0, nil
}

func (c *ClientBind) receive(packets [][]byte, sizes []int, eps []conn.Endpoint) (count int, err error) {
	udpConn, err := c.connect()
	if err != nil {
		if c.closed.Load() {
			return
		}
		c.errorHandler.NewError(context.Background(), E.Cause(err, "connect to server"))
		err = nil
		//c.pauseManager.WaitActive()
		//time.Sleep(time.Second)
		return
	}
	n, addr, err := udpConn.ReadFrom(packets[0])
	if err != nil {
		_ = udpConn.Close()
		if !c.closed.Load() {
			c.errorHandler.NewError(context.Background(), E.Cause(err, "read packet"))
			err = nil
		}
		return
	}
	sizes[0] = n
	if n > 3 && c.parseReserved {
		b := packets[0]
		b[1] = 0
		b[2] = 0
		b[3] = 0
	}
	eps[0] = Endpoint(M.AddrPortFromNet(addr))
	count = 1
	return
}

func (c *ClientBind) Close() error {
	c.closed.Store(true)
	if c.bindDone != nil {
		c.bindDone()
	}
	c.connAccess.Lock()
	defer c.connAccess.Unlock()
	if serverConn := c.conn; serverConn != nil {
		_ = serverConn.Close()
	}
	c.conn = nil
	return nil
}

func (c *ClientBind) SetMark(mark uint32) error {
	return nil
}

func (c *ClientBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	udpConn, err := c.connect()
	if err != nil {
		//c.pauseManager.WaitActive()
		//time.Sleep(time.Second)
		return err
	}
	destination := netip.AddrPort(ep.(Endpoint))
	for _, b := range bufs {
		if len(b) > 3 && c.parseReserved {
			reserved, loaded := c.reservedForEndpoint[destination]
			if !loaded {
				reserved = c.reserved
			}
			b[1] = reserved[0]
			b[2] = reserved[1]
			b[3] = reserved[2]
		}
		_, err = udpConn.WriteTo(b, net.UDPAddrFromAddrPort(destination))
		if err != nil {
			_ = udpConn.Close()
			return err
		}
	}
	return nil
}

func (c *ClientBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return Endpoint(ap), nil
}

func (c *ClientBind) BatchSize() int {
	return 1
}

func (c *ClientBind) SetConnectAddr(connectAddr netip.AddrPort) {
	c.connAccess.Lock()
	defer c.connAccess.Unlock()
	if connectAddr != c.connectAddr {
		c.connectAddr = connectAddr
		if c.isConnect {
			if serverConn := c.conn; serverConn != nil {
				_ = serverConn.Close()
			}
			c.conn = nil
		}
	}
}

func (c *ClientBind) SetReservedForEndpoint(destination netip.AddrPort, reserved [3]byte) {
	c.reservedForEndpoint[destination] = reserved
}

func (c *ClientBind) ResetReservedForEndpoint() {
	c.reservedForEndpoint = make(map[netip.AddrPort][3]uint8)
}

func (c *ClientBind) SetParseReserved(parseReserved bool) {
	c.parseReserved = parseReserved
}

type wireConn struct {
	net.PacketConn
	closed atomic.Bool
}

func (w *wireConn) Close() error {
	if w.closed.Swap(true) {
		return nil
	}
	return w.PacketConn.Close()
}
