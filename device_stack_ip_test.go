//go:build with_gvisor

package wireguard

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip/header"
)

func TestStackDeviceDialIPPacketRejectsUnsupportedNetwork(t *testing.T) {
	device, err := NewStackDevice([]netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")}, 1408)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = device.Close() })

	conn, err := device.DialIPPacket(context.Background(), "tcp", netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("1.1.1.1"))
	if err == nil {
		_ = conn.Close()
		t.Fatal("expected unsupported network error")
	}
}

func TestStackDeviceDialIPPacketWritesCompleteIPv6Packets(t *testing.T) {
	const mtu = 1408
	source := netip.MustParseAddr("fd00::2")
	destination := netip.MustParseAddr("2606:4700:4700::1111")
	device, err := NewStackDevice([]netip.Prefix{netip.PrefixFrom(source, source.BitLen())}, mtu)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = device.Close() })

	conn, err := device.DialIPPacket(context.Background(), "ip6:ipv6-icmp", source, destination)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	for _, size := range []int{header.IPv6MinimumSize + header.ICMPv6MinimumSize, mtu} {
		packet := makeIPv6EchoRequest(source, destination, size)
		if n, err := conn.Write(packet); err != nil {
			t.Fatalf("write %d-byte IPv6 packet: %v", size, err)
		} else if n != len(packet) {
			t.Fatalf("wrote %d-byte IPv6 packet, want %d", n, len(packet))
		}
		buffer := make([]byte, mtu)
		sizes := make([]int, 1)
		if _, err := device.Read([][]byte{buffer}, sizes, 0); err != nil {
			t.Fatalf("read %d-byte IPv6 packet: %v", size, err)
		}
		if sizes[0] != size {
			t.Fatalf("emitted IPv6 packet size = %d, want %d", sizes[0], size)
		}
		if !bytes.Equal(buffer[:sizes[0]], packet) {
			t.Fatal("emitted IPv6 packet differs from written packet")
		}
	}
}

func TestStackDeviceDialIPPacketWritesCompleteIPv4Packets(t *testing.T) {
	const mtu = 1408
	source := netip.MustParseAddr("10.0.0.2")
	destination := netip.MustParseAddr("1.1.1.1")
	device, err := NewStackDevice([]netip.Prefix{netip.PrefixFrom(source, source.BitLen())}, mtu)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = device.Close() })

	conn, err := device.DialIPPacket(context.Background(), "ip4:icmp", source, destination)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	for _, size := range []int{header.IPv4MinimumSize + header.ICMPv4MinimumSize, mtu} {
		packet := makeIPv4EchoRequest(source, destination, size)
		if n, err := conn.Write(packet); err != nil {
			t.Fatalf("write %d-byte IPv4 packet: %v", size, err)
		} else if n != len(packet) {
			t.Fatalf("wrote %d-byte IPv4 packet, want %d", n, len(packet))
		}
		buffer := make([]byte, mtu)
		sizes := make([]int, 1)
		if _, err := device.Read([][]byte{buffer}, sizes, 0); err != nil {
			t.Fatalf("read %d-byte IPv4 packet: %v", size, err)
		}
		if sizes[0] != size {
			t.Fatalf("emitted IPv4 packet size = %d, want %d", sizes[0], size)
		}
		if !bytes.Equal(buffer[:sizes[0]], packet) {
			t.Fatal("emitted IPv4 packet differs from written packet")
		}
	}
}

func TestStackDeviceDialIPPacketReadsCompleteIPv6Packets(t *testing.T) {
	source := netip.MustParseAddr("fd00::2")
	destination := netip.MustParseAddr("2606:4700:4700::1111")
	device, err := NewStackDevice([]netip.Prefix{netip.PrefixFrom(source, source.BitLen())}, 1408)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = device.Close() })

	conn, err := device.DialIPPacket(context.Background(), "ip6:ipv6-icmp", source, destination)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	reply := makeIPv6EchoReply(destination, source, header.IPv6MinimumSize+header.ICMPv6MinimumSize)
	if _, err := device.Write([][]byte{reply}, 0); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 1408)
	n, err := conn.Read(packet)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(reply) {
		t.Fatalf("received IPv6 packet size = %d, want %d", n, len(reply))
	}
	if !bytes.Equal(packet[:n], reply) {
		t.Fatal("received IPv6 packet differs from injected packet")
	}
}

func TestStackDeviceDialIPPacketReadsCompleteIPv4Packets(t *testing.T) {
	source := netip.MustParseAddr("10.0.0.2")
	destination := netip.MustParseAddr("1.1.1.1")
	device, err := NewStackDevice([]netip.Prefix{netip.PrefixFrom(source, source.BitLen())}, 1408)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = device.Close() })

	conn, err := device.DialIPPacket(context.Background(), "ip4:icmp", source, destination)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	reply := makeIPv4EchoReply(destination, source, header.IPv4MinimumSize+header.ICMPv4MinimumSize)
	if _, err := device.Write([][]byte{reply}, 0); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 1408)
	n, err := conn.Read(packet)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(reply) {
		t.Fatalf("received IPv4 packet size = %d, want %d", n, len(reply))
	}
	if !bytes.Equal(packet[:n], reply) {
		t.Fatal("received IPv4 packet differs from injected packet")
	}
}

func TestStackDeviceDialIPPacketRejectsInvalidPackets(t *testing.T) {
	const mtu = 128
	source4 := netip.MustParseAddr("10.0.0.2")
	destination4 := netip.MustParseAddr("1.1.1.1")
	source6 := netip.MustParseAddr("fd00::2")
	destination6 := netip.MustParseAddr("2606:4700:4700::1111")
	device, err := NewStackDevice([]netip.Prefix{
		netip.PrefixFrom(source4, source4.BitLen()),
		netip.PrefixFrom(source6, source6.BitLen()),
	}, mtu)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = device.Close() })

	connection4, err := device.DialIPPacket(context.Background(), "ip4:icmp", source4, destination4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection4.Close() })
	connection6, err := device.DialIPPacket(context.Background(), "ip6:ipv6-icmp", source6, destination6)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection6.Close() })

	withoutICMP4 := makeIPv4EchoRequest(source4, destination4, header.IPv4MinimumSize+header.ICMPv4MinimumSize)
	header.IPv4(withoutICMP4).SetTotalLength(header.IPv4MinimumSize)
	withoutICMP4 = withoutICMP4[:header.IPv4MinimumSize]
	wrongProtocol4 := makeIPv4EchoRequest(source4, destination4, header.IPv4MinimumSize+header.ICMPv4MinimumSize)
	wrongProtocol4[9] = uint8(header.TCPProtocolNumber)

	withoutICMP6 := makeIPv6EchoRequest(source6, destination6, header.IPv6MinimumSize+header.ICMPv6MinimumSize)
	header.IPv6(withoutICMP6).SetPayloadLength(0)
	withoutICMP6 = withoutICMP6[:header.IPv6MinimumSize]
	wrongProtocol6 := makeIPv6EchoRequest(source6, destination6, header.IPv6MinimumSize+header.ICMPv6MinimumSize)
	header.IPv6(wrongProtocol6).SetNextHeader(uint8(header.TCPProtocolNumber))

	tests := []struct {
		name       string
		connection net.Conn
		packet     []byte
	}{
		{"short IPv4 header", connection4, []byte{0x45}},
		{"IPv4 without ICMP header", connection4, withoutICMP4},
		{"IPv4 wrong protocol", connection4, wrongProtocol4},
		{"IPv4 wrong source", connection4, makeIPv4EchoRequest(netip.MustParseAddr("10.0.0.3"), destination4, header.IPv4MinimumSize+header.ICMPv4MinimumSize)},
		{"IPv4 wrong destination", connection4, makeIPv4EchoRequest(source4, netip.MustParseAddr("8.8.8.8"), header.IPv4MinimumSize+header.ICMPv4MinimumSize)},
		{"IPv4 over MTU", connection4, makeIPv4EchoRequest(source4, destination4, mtu+1)},
		{"short IPv6 header", connection6, []byte{0x60}},
		{"IPv6 without ICMP header", connection6, withoutICMP6},
		{"IPv6 wrong protocol", connection6, wrongProtocol6},
		{"IPv6 wrong source", connection6, makeIPv6EchoRequest(netip.MustParseAddr("fd00::3"), destination6, header.IPv6MinimumSize+header.ICMPv6MinimumSize)},
		{"IPv6 wrong destination", connection6, makeIPv6EchoRequest(source6, netip.MustParseAddr("2001:4860:4860::8888"), header.IPv6MinimumSize+header.ICMPv6MinimumSize)},
		{"IPv6 over MTU", connection6, makeIPv6EchoRequest(source6, destination6, mtu+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			n, err := test.connection.Write(test.packet)
			if err == nil {
				t.Fatal("expected write error")
			}
			if n != 0 {
				t.Fatalf("rejected write count = %d, want 0", n)
			}
		})
	}
}

func TestStackDeviceDialIPPacketRejectsWriteAfterClose(t *testing.T) {
	source := netip.MustParseAddr("10.0.0.2")
	destination := netip.MustParseAddr("1.1.1.1")
	device, err := NewStackDevice([]netip.Prefix{netip.PrefixFrom(source, source.BitLen())}, 1408)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = device.Close() })

	connection, err := device.DialIPPacket(context.Background(), "ip4:icmp", source, destination)
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}

	packet := makeIPv4EchoRequest(source, destination, header.IPv4MinimumSize+header.ICMPv4MinimumSize)
	n, err := connection.Write(packet)
	if err == nil {
		t.Fatal("expected write error after close")
	}
	if n != 0 {
		t.Fatalf("closed write count = %d, want 0", n)
	}
}

func makeIPv6EchoRequest(source, destination netip.Addr, size int) []byte {
	return makeIPv6Echo(source, destination, size, header.ICMPv6EchoRequest)
}

func makeIPv4EchoRequest(source, destination netip.Addr, size int) []byte {
	return makeIPv4Echo(source, destination, size, header.ICMPv4Echo)
}

func makeIPv4EchoReply(source, destination netip.Addr, size int) []byte {
	return makeIPv4Echo(source, destination, size, header.ICMPv4EchoReply)
}

func makeIPv4Echo(source, destination netip.Addr, size int, messageType header.ICMPv4Type) []byte {
	packet := make([]byte, size)
	ipHeader := header.IPv4(packet)
	ipHeader.Encode(&header.IPv4Fields{
		TOS:         0x2e,
		TotalLength: uint16(size),
		ID:          0x1234,
		Flags:       header.IPv4FlagDontFragment,
		TTL:         37,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     AddressFromAddr(source),
		DstAddr:     AddressFromAddr(destination),
	})
	icmpHeader := header.ICMPv4(ipHeader.Payload())
	icmpHeader.SetType(messageType)
	icmpHeader.SetIdent(7)
	icmpHeader.SetSequence(1)
	icmpHeader.SetChecksum(header.ICMPv4Checksum(icmpHeader, 0))
	ipHeader.SetChecksum(^ipHeader.CalculateChecksum())
	return packet
}

func makeIPv6EchoReply(source, destination netip.Addr, size int) []byte {
	return makeIPv6Echo(source, destination, size, header.ICMPv6EchoReply)
}

func makeIPv6Echo(source, destination netip.Addr, size int, messageType header.ICMPv6Type) []byte {
	packet := make([]byte, size)
	ipHeader := header.IPv6(packet)
	ipHeader.Encode(&header.IPv6Fields{
		TrafficClass:      0x2a,
		FlowLabel:         0xabcde,
		PayloadLength:     uint16(size - header.IPv6MinimumSize),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          37,
		SrcAddr:           AddressFromAddr(source),
		DstAddr:           AddressFromAddr(destination),
	})
	icmpHeader := header.ICMPv6(ipHeader.Payload())
	icmpHeader.SetType(messageType)
	icmpHeader.SetIdent(7)
	icmpHeader.SetSequence(1)
	icmpHeader.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: icmpHeader,
		Src:    ipHeader.SourceAddress(),
		Dst:    ipHeader.DestinationAddress(),
	}))
	return packet
}
