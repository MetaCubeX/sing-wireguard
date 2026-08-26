//go:build with_gvisor

package wireguard_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	wireguard "github.com/metacubex/sing-wireguard"
	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

const forwardTestPayload = "forward-test"

type testForwardEvent struct {
	metadata M.Metadata
	payload  []byte
	err      error
}

type testForwardHandler struct {
	tcp               chan testForwardEvent
	udp               chan testForwardEvent
	noUDPReplySources map[netip.Addr]struct{}
}

func (h *testForwardHandler) NewConnection(_ context.Context, connection net.Conn, metadata M.Metadata) error {
	defer connection.Close()
	payload := make([]byte, len(forwardTestPayload))
	_, err := io.ReadFull(connection, payload)
	if err == nil {
		err = writeTestStream(connection, payload)
	}
	h.tcp <- testForwardEvent{metadata: metadata, payload: payload, err: err}
	return err
}

func (h *testForwardHandler) NewPacket(_ context.Context, _ netip.AddrPort, packet *buf.Buffer, metadata M.Metadata, init func(N.PacketConn) N.PacketWriter) {
	payload := append([]byte(nil), packet.Bytes()...)
	packet.Release()
	var err error
	if _, noReply := h.noUDPReplySources[metadata.Source.Addr]; !noReply {
		writer := init(nil)
		err = writer.WritePacket(buf.As(append([]byte(nil), payload...)), metadata.Destination)
	}
	h.udp <- testForwardEvent{metadata: metadata, payload: payload, err: err}
}

func TestRegisterForwardAllowsPromiscuousSource(t *testing.T) {
	server4 := netip.MustParseAddr("10.0.0.1")
	server6 := netip.MustParseAddr("fd00::1")
	handler := &testForwardHandler{
		tcp: make(chan testForwardEvent, 2),
		udp: make(chan testForwardEvent, 2),
		noUDPReplySources: map[netip.Addr]struct{}{
			server4: {},
			server6: {},
		},
	}
	client, server := newForwardTestDevices(t, handler, server4, server6)

	tests := []struct {
		name       string
		tcpNetwork string
		udpNetwork string
		tcpTarget  netip.AddrPort
		udpTarget  netip.AddrPort
	}{
		{
			name:       "IPv4",
			tcpNetwork: "tcp4",
			udpNetwork: "udp4",
			tcpTarget:  netip.MustParseAddrPort("192.0.2.1:8080"),
			udpTarget:  netip.MustParseAddrPort("192.0.2.1:5353"),
		},
		{
			name:       "IPv6",
			tcpNetwork: "tcp6",
			udpNetwork: "udp6",
			tcpTarget:  netip.MustParseAddrPort("[2001:db8::1]:8080"),
			udpTarget:  netip.MustParseAddrPort("[2001:db8::1]:5353"),
		},
	}

	for _, test := range tests {
		t.Run(test.name+"/TCP", func(t *testing.T) {
			checkTCPForward(t, client, handler.tcp, test.tcpNetwork, test.tcpTarget)
		})
		t.Run(test.name+"/UDP", func(t *testing.T) {
			checkUDPForward(t, client, handler.udp, test.udpNetwork, test.udpTarget)
		})
	}

	checkPermanentSourceRejected(t, server, handler.udp, "udp4", netip.PrefixFrom(server4, 24), netip.MustParseAddrPort("192.0.2.2:5353"))
	checkPermanentSourceRejected(t, server, handler.udp, "udp6", netip.PrefixFrom(server6, 64), netip.MustParseAddrPort("[2001:db8::2]:5353"))
	checkLocalTCP(t, server, "tcp4", server4)
	checkLocalTCP(t, server, "tcp6", server6)
}

func newForwardTestDevices(t *testing.T, handler wireguard.ForwardHandler, server4, server6 netip.Addr) (*wireguard.StackDevice, *wireguard.StackDevice) {
	t.Helper()
	server, err := wireguard.NewStackDevice([]netip.Prefix{
		netip.PrefixFrom(server4, 24),
		netip.PrefixFrom(server6, 64),
	}, 1500)
	if err != nil {
		t.Fatal(err)
	}
	client, err := wireguard.NewStackDevice([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.2/24"),
		netip.MustParsePrefix("fd00::2/64"),
	}, 1500)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	if err = server.RegisterForward(wireguard.ForwardOptions{Handler: handler}); err != nil {
		client.Close()
		server.Close()
		t.Fatal(err)
	}
	connectTestDevices(t, client, server)
	return client, server
}

func connectTestDevices(t *testing.T, left, right *wireguard.StackDevice) {
	t.Helper()
	linkErrors := make(chan error, 2)
	var waitGroup sync.WaitGroup
	pump := func(source, destination *wireguard.StackDevice) {
		defer waitGroup.Done()
		buffer := make([]byte, 65535)
		buffers := [][]byte{buffer}
		sizes := make([]int, 1)
		for {
			count, err := source.Read(buffers, sizes, 0)
			if err != nil {
				if !errors.Is(err, os.ErrClosed) {
					linkErrors <- err
				}
				return
			}
			if count != 1 {
				linkErrors <- fmt.Errorf("device read count = %d, want 1", count)
				return
			}
			count, err = destination.Write([][]byte{buffer[:sizes[0]]}, 0)
			if err != nil {
				if !errors.Is(err, os.ErrClosed) {
					linkErrors <- err
				}
				return
			}
			if count != 1 {
				linkErrors <- fmt.Errorf("device write count = %d, want 1", count)
				return
			}
		}
	}
	waitGroup.Add(2)
	go pump(left, right)
	go pump(right, left)
	t.Cleanup(func() {
		left.Close()
		right.Close()
		waitGroup.Wait()
		close(linkErrors)
		for err := range linkErrors {
			t.Error(err)
		}
	})
}

func checkTCPForward(t *testing.T, client *wireguard.StackDevice, events <-chan testForwardEvent, network string, destination netip.AddrPort) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	connection, err := client.DialTCP(ctx, network, netip.AddrPort{}, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err = connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	source := M.SocksaddrFromNet(connection.LocalAddr()).AddrPort()
	if err = writeTestStream(connection, []byte(forwardTestPayload)); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(forwardTestPayload))
	if _, err = io.ReadFull(connection, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != forwardTestPayload {
		t.Fatalf("response = %q, want %q", response, forwardTestPayload)
	}
	checkForwardEvent(t, events, source, destination)
}

func checkUDPForward(t *testing.T, client *wireguard.StackDevice, events <-chan testForwardEvent, network string, destination netip.AddrPort) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	connection, err := client.DialUDP(ctx, network, netip.AddrPort{}, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err = connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	source := M.SocksaddrFromNet(connection.LocalAddr()).AddrPort()
	if _, err = connection.Write([]byte(forwardTestPayload)); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(forwardTestPayload))
	if _, err = io.ReadFull(connection, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != forwardTestPayload {
		t.Fatalf("response = %q, want %q", response, forwardTestPayload)
	}
	checkForwardEvent(t, events, source, destination)
}

func checkForwardEvent(t *testing.T, events <-chan testForwardEvent, source, destination netip.AddrPort) {
	t.Helper()
	select {
	case event := <-events:
		if event.err != nil {
			t.Fatal(event.err)
		}
		if got := event.metadata.Source.AddrPort(); got != source {
			t.Fatalf("source = %s, want %s", got, source)
		}
		if got := event.metadata.Destination.AddrPort(); got != destination {
			t.Fatalf("destination = %s, want %s", got, destination)
		}
		if string(event.payload) != forwardTestPayload {
			t.Fatalf("payload = %q, want %q", event.payload, forwardTestPayload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("forward handler was not called")
	}
}

func checkPermanentSourceRejected(t *testing.T, server *wireguard.StackDevice, events <-chan testForwardEvent, network string, source netip.Prefix, destination netip.AddrPort) {
	t.Helper()
	client, err := wireguard.NewStackDevice([]netip.Prefix{source}, 1500)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	connection, err := client.DialUDP(ctx, network, netip.AddrPortFrom(source.Addr(), 0), destination)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err = connection.Write([]byte(forwardTestPayload)); err != nil {
		t.Fatal(err)
	}
	relayOneTestDevicePacket(t, client, server)
	select {
	case event := <-events:
		t.Fatalf("forwarded packet with permanent local source %s: %+v", source.Addr(), event)
	case <-time.After(50 * time.Millisecond):
	}
}

func relayOneTestDevicePacket(t *testing.T, source, destination *wireguard.StackDevice) {
	t.Helper()
	results := make(chan error, 1)
	go func() {
		buffer := make([]byte, 65535)
		sizes := make([]int, 1)
		count, err := source.Read([][]byte{buffer}, sizes, 0)
		if err == nil && count != 1 {
			err = fmt.Errorf("device read count = %d, want 1", count)
		}
		if err == nil {
			count, err = destination.Write([][]byte{buffer[:sizes[0]]}, 0)
			if err == nil && count != 1 {
				err = fmt.Errorf("device write count = %d, want 1", count)
			}
		}
		results <- err
	}()
	select {
	case err := <-results:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("device packet was not relayed")
	}
}

func checkLocalTCP(t *testing.T, device *wireguard.StackDevice, network string, localAddress netip.Addr) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	listener, err := device.ListenTCP(ctx, network, netip.AddrPortFrom(localAddress, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	acceptResult := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			err = connection.Close()
		}
		acceptResult <- err
	}()
	local := listener.Addr().(*net.TCPAddr).AddrPort()
	connection, err := device.DialTCP(ctx, network, netip.AddrPort{}, local)
	if err != nil {
		t.Fatal(err)
	}
	connection.Close()
	select {
	case err = <-acceptResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func writeTestStream(writer io.Writer, payload []byte) error {
	_, err := io.Copy(writer, bytes.NewReader(payload))
	return err
}
