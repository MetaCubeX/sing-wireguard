//go:build with_gvisor

package wireguard

import (
	"errors"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"
)

// ipv4Packet returns a minimal well-formed IPv4 packet header. The version
// nibble (0x4) is all StackDevice.Write inspects to pick a network protocol.
func ipv4Packet() []byte {
	p := make([]byte, 20)
	p[0] = 0x45 // version 4, IHL 5
	return p
}

// TestStackDeviceWriteAfterClose verifies that Write returns os.ErrClosed
// instead of panicking once the device has been closed.
//
// Close tears down the gVisor stack, and stack.Close() detaches the link
// endpoint by calling Attach(nil), which sets the dispatcher to nil. Before
// the guard was added, a Write reaching dispatcher.DeliverNetworkPacket on a
// nil dispatcher crashed the whole process with a SIGSEGV. wireguard-go's
// device.Close() closes the TUN device before stopping its peer goroutines
// (RoutineSequentialReceiver), so such a late Write is expected, not a bug
// in the caller.
func TestStackDeviceWriteAfterClose(t *testing.T) {
	dev, err := NewStackDevice([]netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")}, 1280)
	if err != nil {
		t.Fatalf("NewStackDevice: %v", err)
	}
	if err := dev.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	n, err := dev.Write([][]byte{ipv4Packet()}, 0)
	if !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Write after Close: got (n=%d, err=%v), want (0, os.ErrClosed)", n, err)
	}
	if n != 0 {
		t.Fatalf("Write after Close: got n=%d, want 0", n)
	}
}

// TestStackDeviceWriteCloseRace models the real failure: concurrent writers
// (wireguard-go peer receiver goroutines) racing against Close. Without the
// writeMu/ctx guard this panics intermittently; under `go test -race` it also
// flags the data race on the dispatcher field. With the guard every Write
// either completes before the teardown or returns os.ErrClosed.
func TestStackDeviceWriteCloseRace(t *testing.T) {
	dev, err := NewStackDevice([]netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")}, 1280)
	if err != nil {
		t.Fatalf("NewStackDevice: %v", err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// Must never panic, regardless of Close timing.
				_, _ = dev.Write([][]byte{ipv4Packet()}, 0)
			}
		}()
	}

	time.Sleep(time.Millisecond)
	if err := dev.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	close(stop)
	wg.Wait()
}
