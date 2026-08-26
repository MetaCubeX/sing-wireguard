//go:build with_gvisor

package wireguard

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip/header"
)

func TestIPConnReadsCompletePackets(t *testing.T) {
	tests := []struct {
		name         string
		network      string
		local        netip.Addr
		remote       netip.Addr
		hopLimit     uint8
		trafficClass uint8
		v6           bool
	}{
		{name: "IPv4 options", network: "ip4:icmp", local: netip.MustParseAddr("10.0.0.1"), remote: netip.MustParseAddr("192.0.2.1"), hopLimit: 37, trafficClass: 0x2e},
		{name: "IPv6", network: "ip6:ipv6-icmp", local: netip.MustParseAddr("fd00::1"), remote: netip.MustParseAddr("2001:db8::1"), hopLimit: 41, trafficClass: 0x3a, v6: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			device := newIPTestDevice(t)
			packetConnection, err := device.ListenIP(context.Background(), test.network, test.local)
			if err != nil {
				t.Fatal(err)
			}
			defer packetConnection.Close()
			if err = packetConnection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}

			payload := testICMPPayload(test.v6, true, test.remote, test.local, []byte("complete-read"))
			packet := testIPPacket(test.v6, test.remote, test.local, test.hopLimit, test.trafficClass, payload, !test.v6)
			injectIPTestPacket(t, device, packet)

			buffer := make([]byte, len(packet))
			n, source, err := packetConnection.ReadFrom(buffer)
			if err != nil {
				t.Fatal(err)
			}
			if n != len(packet) || !bytes.Equal(buffer[:n], packet) {
				t.Fatalf("ReadFrom packet = %x/%d, want %x/%d", buffer[:n], n, packet, len(packet))
			}
			if sourceAddress := netipFromTestIPAddr(t, source); sourceAddress != test.remote {
				t.Fatalf("ReadFrom source = %v, want %v", sourceAddress, test.remote)
			}
		})
	}
}

func TestIPConnWritesCompletePackets(t *testing.T) {
	tests := []struct {
		name         string
		network      string
		local        netip.Addr
		remote       netip.Addr
		hopLimit     uint8
		trafficClass uint8
		v6           bool
	}{
		{name: "IPv4 options", network: "ip4:1", local: netip.MustParseAddr("10.0.0.1"), remote: netip.MustParseAddr("192.0.2.1"), hopLimit: 29, trafficClass: 0x2e},
		{name: "IPv6", network: "ip6:58", local: netip.MustParseAddr("fd00::1"), remote: netip.MustParseAddr("2001:db8::1"), hopLimit: 31, trafficClass: 0x3a, v6: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			device := newIPTestDevice(t)
			connection, err := device.ListenIP(context.Background(), test.network, netip.Addr{})
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()

			payload := testICMPPayload(test.v6, false, test.local, test.remote, []byte("complete-write"))
			packet := testIPPacket(test.v6, test.local, test.remote, test.hopLimit, test.trafficClass, payload, !test.v6)
			original := append([]byte(nil), packet...)
			n, err := connection.WriteTo(packet, ipNetAddr(test.remote))
			if err != nil {
				t.Fatal(err)
			}
			if n != len(packet) {
				t.Fatalf("WriteTo = %d, want %d", n, len(packet))
			}
			if !bytes.Equal(packet, original) {
				t.Fatal("WriteTo mutated caller packet")
			}
			if emitted := readIPTestPacket(t, device); !bytes.Equal(emitted, original) {
				t.Fatalf("emitted packet differs:\n got %x\nwant %x", emitted, original)
			}
		})
	}
}

func TestIPConnListenAndDialFiltering(t *testing.T) {
	device := newIPTestDevice(t)
	local := netip.MustParseAddr("10.0.0.1")
	connectedRemote := netip.MustParseAddr("192.0.2.1")
	otherRemote := netip.MustParseAddr("192.0.2.2")

	listener, err := device.ListenIP(context.Background(), "ip4:icmp", local)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	connected, err := device.DialIP(context.Background(), "ip4:icmp", netip.Addr{}, connectedRemote)
	if err != nil {
		t.Fatal(err)
	}
	defer connected.Close()

	otherPayload := testICMPPayload(false, true, otherRemote, local, []byte("other-source"))
	otherPacket := testIPPacket(false, otherRemote, local, 50, 0, otherPayload, false)
	injectIPTestPacket(t, device, otherPacket)
	if err = listener.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len(otherPacket))
	n, source, err := listener.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(otherPacket) || !bytes.Equal(buffer[:n], otherPacket) || netipFromTestIPAddr(t, source) != otherRemote {
		t.Fatalf("ListenIP read = %x/%d from %v, want %x from %v", buffer[:n], n, source, otherPacket, otherRemote)
	}

	if err = connected.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err = connected.Read(buffer); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("connected read from unexpected source = %v, want deadline", err)
	}

	connectedPayload := testICMPPayload(false, true, connectedRemote, local, []byte("connected-source"))
	connectedPacket := testIPPacket(false, connectedRemote, local, 51, 0, connectedPayload, false)
	injectIPTestPacket(t, device, connectedPacket)
	if err = connected.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer = make([]byte, len(connectedPacket))
	if n, err = connected.Read(buffer); err != nil || n != len(connectedPacket) || !bytes.Equal(buffer[:n], connectedPacket) {
		t.Fatalf("connected read = %x/%d, %v, want %x", buffer[:n], n, err, connectedPacket)
	}

	requestPayload := testICMPPayload(false, false, local, connectedRemote, []byte("connected-write"))
	requestPacket := testIPPacket(false, local, connectedRemote, 52, 0x20, requestPayload, false)
	if n, err = connected.Write(requestPacket); err != nil || n != len(requestPacket) {
		t.Fatalf("connected write = %d, %v", n, err)
	}
	if emitted := readIPTestPacket(t, device); !bytes.Equal(emitted, requestPacket) {
		t.Fatalf("connected emitted packet differs:\n got %x\nwant %x", emitted, requestPacket)
	}
}

func TestIPConnTruncationDeadlineAndClose(t *testing.T) {
	device := newIPTestDevice(t)
	local := netip.MustParseAddr("10.0.0.1")
	remote := netip.MustParseAddr("192.0.2.1")
	connection, err := device.ListenIP(context.Background(), "ip4:icmp", local)
	if err != nil {
		t.Fatal(err)
	}

	payload := testICMPPayload(false, true, remote, local, bytes.Repeat([]byte{0xa5}, 64))
	packet := testIPPacket(false, remote, local, 44, 0, payload, false)
	injectIPTestPacket(t, device, packet)
	short := make([]byte, 8)
	n, source, err := connection.ReadFrom(short)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(short) || !bytes.Equal(short, packet[:len(short)]) || netipFromTestIPAddr(t, source) != remote {
		t.Fatalf("truncated ReadFrom = %x/%d from %v", short, n, source)
	}
	injectIPTestPacket(t, device, packet)
	if n, source, err = connection.ReadFrom(nil); err != nil || n != 0 || netipFromTestIPAddr(t, source) != remote {
		t.Fatalf("zero-length ReadFrom = %d from %v, %v", n, source, err)
	}

	readResult := make(chan error, 1)
	go func() {
		_, _, readErr := connection.ReadFrom(make([]byte, 128))
		readResult <- readErr
	}()
	time.Sleep(20 * time.Millisecond)
	if err = connection.SetReadDeadline(time.Now().Add(40 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-readResult:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("updated read deadline error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("updated read deadline did not wake read")
	}

	if err = connection.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	go func() {
		_, _, readErr := connection.ReadFrom(make([]byte, 128))
		readResult <- readErr
	}()
	time.Sleep(20 * time.Millisecond)
	if err = connection.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-readResult:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("closed read error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not wake read")
	}
}

func TestIPConnWriteAndNetworkValidation(t *testing.T) {
	device := newIPTestDevice(t)
	local := netip.MustParseAddr("10.0.0.1")
	remote := netip.MustParseAddr("192.0.2.1")
	connection, err := device.ListenIP(context.Background(), "ip4:001", netip.Addr{})
	if err != nil {
		t.Fatalf("ListenIP(ip4:001) = %v", err)
	}
	defer connection.Close()
	payload := testICMPPayload(false, false, local, remote, nil)
	packet := testIPPacket(false, local, remote, 64, 0, payload, false)
	if _, err = connection.(net.Conn).Write(packet); !errors.Is(err, syscall.EDESTADDRREQ) {
		t.Fatalf("unconnected Write = %v, want EDESTADDRREQ", err)
	}
	if _, err = connection.WriteTo(packet, &net.UDPAddr{}); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("WriteTo UDP address = %v, want EINVAL", err)
	}
	if _, err = connection.WriteTo(packet, ipNetAddr(netip.MustParseAddr("2001:db8::1"))); !errors.Is(err, syscall.EAFNOSUPPORT) {
		t.Fatalf("WriteTo IPv6 address = %v, want EAFNOSUPPORT", err)
	}
	if _, err = connection.WriteTo([]byte{0x45}, ipNetAddr(remote)); err == nil {
		t.Fatal("WriteTo short complete packet succeeded")
	}

	if _, err = device.ListenIP(context.Background(), "ip4:99", netip.Addr{}); !errors.Is(err, syscall.EPROTONOSUPPORT) {
		t.Fatalf("ListenIP(ip4:99) = %v, want EPROTONOSUPPORT", err)
	}
	if _, err = device.ListenIP(context.Background(), "ip4:udp", netip.Addr{}); !errors.Is(err, syscall.EPROTONOSUPPORT) {
		t.Fatalf("ListenIP(ip4:udp) = %v, want EPROTONOSUPPORT", err)
	}
	if _, err = device.ListenIP(context.Background(), "ip6:icmp", netip.Addr{}); !errors.Is(err, syscall.EPROTONOSUPPORT) {
		t.Fatalf("ListenIP(ip6:icmp) = %v, want EPROTONOSUPPORT", err)
	}
	if _, err = device.DialIP(context.Background(), "ip4:icmp", netip.Addr{}, netip.MustParseAddr("2001:db8::1")); !errors.Is(err, syscall.EAFNOSUPPORT) {
		t.Fatalf("DialIP IPv4/IPv6 mismatch = %v, want EAFNOSUPPORT", err)
	}
}

func newIPTestDevice(t *testing.T) *StackDevice {
	t.Helper()
	device, err := NewStackDevice([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.1/24"),
		netip.MustParsePrefix("fd00::1/64"),
	}, 1500)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = device.Close() })
	return device
}

func injectIPTestPacket(t *testing.T, device *StackDevice, packet []byte) {
	t.Helper()
	count, err := device.Write([][]byte{packet}, 0)
	if err != nil || count != 1 {
		t.Fatalf("inject packet = %d, %v", count, err)
	}
}

func readIPTestPacket(t *testing.T, device *StackDevice) []byte {
	t.Helper()
	buffer := make([]byte, 2048)
	sizes := make([]int, 1)
	count, err := device.Read([][]byte{buffer}, sizes, 0)
	if err != nil || count != 1 {
		t.Fatalf("read outbound packet = %d, %v", count, err)
	}
	return append([]byte(nil), buffer[:sizes[0]]...)
}

func testICMPPayload(v6, reply bool, source, destination netip.Addr, data []byte) []byte {
	if v6 {
		payload := make(header.ICMPv6, header.ICMPv6MinimumSize+len(data))
		if reply {
			payload.SetType(header.ICMPv6EchoReply)
		} else {
			payload.SetType(header.ICMPv6EchoRequest)
		}
		payload.SetIdent(0x1234)
		payload.SetSequence(7)
		copy(payload[header.ICMPv6MinimumSize:], data)
		payload.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
			Header: payload,
			Src:    AddressFromAddr(source),
			Dst:    AddressFromAddr(destination),
		}))
		return payload
	}
	payload := make(header.ICMPv4, header.ICMPv4MinimumSize+len(data))
	if reply {
		payload.SetType(header.ICMPv4EchoReply)
	} else {
		payload.SetType(header.ICMPv4Echo)
	}
	payload.SetIdent(0x1234)
	payload.SetSequence(7)
	copy(payload[header.ICMPv4MinimumSize:], data)
	payload.SetChecksum(header.ICMPv4Checksum(payload, 0))
	return payload
}

func testIPPacket(v6 bool, source, destination netip.Addr, hopLimit, trafficClass uint8, payload []byte, withIPv4Options bool) []byte {
	if v6 {
		packet := make(header.IPv6, header.IPv6MinimumSize+len(payload))
		packet.Encode(&header.IPv6Fields{
			TrafficClass:      trafficClass,
			FlowLabel:         0xabcde,
			PayloadLength:     uint16(len(payload)),
			TransportProtocol: header.ICMPv6ProtocolNumber,
			HopLimit:          hopLimit,
			SrcAddr:           AddressFromAddr(source),
			DstAddr:           AddressFromAddr(destination),
		})
		copy(packet[header.IPv6MinimumSize:], payload)
		return packet
	}
	headerLength := header.IPv4MinimumSize
	if withIPv4Options {
		headerLength += 4
	}
	packet := make(header.IPv4, headerLength+len(payload))
	packet.Encode(&header.IPv4Fields{
		TOS:         trafficClass,
		TotalLength: uint16(len(packet)),
		ID:          0x1234,
		TTL:         hopLimit,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     AddressFromAddr(source),
		DstAddr:     AddressFromAddr(destination),
	})
	if withIPv4Options {
		packet.SetHeaderLength(uint8(headerLength))
		copy(packet[header.IPv4MinimumSize:headerLength], []byte{1, 1, 0, 0})
	}
	copy(packet[headerLength:], payload)
	packet.SetChecksum(0)
	packet.SetChecksum(^packet.CalculateChecksum())
	return packet
}

func netipFromTestIPAddr(t *testing.T, address net.Addr) netip.Addr {
	t.Helper()
	ipAddress, ok := address.(*net.IPAddr)
	if !ok || ipAddress == nil {
		t.Fatalf("IP address type = %T", address)
	}
	converted, valid := netip.AddrFromSlice(ipAddress.IP)
	if !valid {
		t.Fatalf("invalid IP address %v", address)
	}
	return converted.Unmap()
}
