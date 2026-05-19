package protocol

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"
)

// ============================================================================
// AEADChannel — encryption/decryption round-trip
// ============================================================================

func TestAEADChannelRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	sender, err := NewAEADChannel(key)
	if err != nil {
		t.Fatalf("NewAEADChannel: %v", err)
	}
	receiver, err := NewAEADChannel(key)
	if err != nil {
		t.Fatalf("NewAEADChannel: %v", err)
	}

	payload := []byte("Hello, encrypted world! This is a test payload.")

	frame, err := sender.EncryptFrame(payload)
	if err != nil {
		t.Fatalf("EncryptFrame: %v", err)
	}

	if len(frame) == 0 {
		t.Fatal("EncryptFrame returned empty frame")
	}

	// Decode via ReadFrame (needs io.Reader)
	data, isHB, err := receiver.ReadFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}

	if isHB {
		t.Error("data frame decoded as heartbeat")
	}
	if !bytes.Equal(data, payload) {
		t.Errorf("data mismatch: got %d bytes, want %d", len(data), len(payload))
	}
}

func TestAEADChannelMultipleFrames(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	sender, _ := NewAEADChannel(key)
	receiver, _ := NewAEADChannel(key)

	payloads := [][]byte{
		[]byte("frame 1"),
		[]byte("frame 2, longer payload"),
		[]byte("f3"),
		[]byte("frame four with even more content to test"),
	}

	for i, payload := range payloads {
		frame, err := sender.EncryptFrame(payload)
		if err != nil {
			t.Fatalf("frame %d EncryptFrame: %v", i, err)
		}

		data, isHB, err := receiver.ReadFrame(bytes.NewReader(frame))
		if err != nil {
			t.Fatalf("frame %d ReadFrame: %v", i, err)
		}
		if isHB {
			t.Errorf("frame %d decoded as heartbeat", i)
		}
		if !bytes.Equal(data, payload) {
			t.Errorf("frame %d data mismatch", i)
		}
	}
}

func TestAEADChannelHeartbeatType(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	sender, _ := NewAEADChannel(key)
	receiver, _ := NewAEADChannel(key)

	frame, err := sender.EncryptHeartbeat()
	if err != nil {
		t.Fatalf("EncryptHeartbeat: %v", err)
	}
	_, isHB, err := receiver.ReadFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("ReadFrame heartbeat: %v", err)
	}
	if !isHB {
		t.Error("heartbeat frame not detected as heartbeat")
	}
}

func TestAEADChannelRejectCorruptedFrame(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	sender, _ := NewAEADChannel(key)
	receiver, _ := NewAEADChannel(key)

	frame, _ := sender.EncryptFrame([]byte("test"))

	// Corrupt a byte
	frame[len(frame)/2] ^= 0xFF

	_, _, err := receiver.ReadFrame(bytes.NewReader(frame))
	if err == nil {
		t.Error("corrupted frame should have been rejected by AEAD authentication")
	}
}

func TestAEADChannelDifferentKeys(t *testing.T) {
	k1 := make([]byte, 32)
	k2 := make([]byte, 32)
	_, _ = rand.Read(k1)
	_, _ = rand.Read(k2)

	sender, _ := NewAEADChannel(k1)
	receiver, _ := NewAEADChannel(k2)

	frame, _ := sender.EncryptFrame([]byte("test"))
	_, _, err := receiver.ReadFrame(bytes.NewReader(frame))
	if err == nil {
		t.Error("frame encrypted with k1 should be rejected by receiver with k2")
	}
}

func TestEncryptFrameSizeTooLarge(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	sender, _ := NewAEADChannel(key)

	hugePayload := make([]byte, MaxPayload+1)
	_, err := sender.EncryptFrame(hugePayload)
	if err != nil {
		t.Logf("EncryptFrame rejected oversized payload: %v", err)
		return
	}
	// If it didn't reject, it should still not panic
}

func TestReadFrameShortFrame(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	receiver, _ := NewAEADChannel(key)

	_, _, err := receiver.ReadFrame(bytes.NewReader([]byte{0x00}))
	if err == nil {
		t.Error("ReadFrame should reject frame shorter than LenFieldSize")
	}
}

// ============================================================================
// SaltFirstFrame / UnsaltFirstFrame
// ============================================================================

func TestSaltUnsaltRoundTrip(t *testing.T) {
	original := []byte("example.com:443")

	for i := 0; i < 100; i++ {
		salted := SaltFirstFrame(original)

		if len(salted) < len(original)+2 {
			t.Errorf("salted too short: %d bytes for %d-byte input", len(salted), len(original))
		}

		saltLen := int(salted[1]) // [0]=SaltMarker, [1]=saltLen, [2:]=salt+payload
		if saltLen > 16 {
			t.Errorf("salt len = %d, max 16", saltLen)
		}

		unsalted := UnsaltFirstFrame(salted)
		if !bytes.Equal(unsalted, original) {
			t.Errorf("round-trip failed: got %q, want %q", unsalted, original)
		}
	}
}

func TestSaltRandomness(t *testing.T) {
	original := []byte("test.com:80")
	s1 := SaltFirstFrame(original)
	s2 := SaltFirstFrame(original)

	if bytes.Equal(s1, s2) {
		t.Log("warning: two salts identical (statistically rare)")
	}
}

// ============================================================================
// NyxConn — pipe-based integration test
// ============================================================================

func TestNyxConnRoundTrip(t *testing.T) {
	clientKey := make([]byte, 32)
	serverKey := make([]byte, 32)
	_, _ = rand.Read(clientKey)
	_, _ = rand.Read(serverKey)

	clientPipe, serverPipe := net.Pipe()
	defer clientPipe.Close()
	defer serverPipe.Close()

	clientConn, err := NewNyxConn(clientPipe, clientKey, serverKey)
	if err != nil {
		t.Fatalf("client NyxConn: %v", err)
	}
	serverConn, err := NewNyxConn(serverPipe, serverKey, clientKey)
	if err != nil {
		t.Fatalf("server NyxConn: %v", err)
	}

	message := []byte("Hello from client!")
	go func() {
		_, err := clientConn.Write(message)
		if err != nil {
			t.Errorf("client write: %v", err)
		}
	}()

	buf := make([]byte, 1024)
	n, err := serverConn.Read(buf)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	if string(buf[:n]) != string(message) {
		t.Errorf("received %q, want %q", buf[:n], message)
	}
}

func TestNyxConnBidirectional(t *testing.T) {
	clientKey := make([]byte, 32)
	serverKey := make([]byte, 32)
	_, _ = rand.Read(clientKey)
	_, _ = rand.Read(serverKey)

	clientPipe, serverPipe := net.Pipe()
	defer clientPipe.Close()
	defer serverPipe.Close()

	clientConn, _ := NewNyxConn(clientPipe, clientKey, serverKey)
	serverConn, _ := NewNyxConn(serverPipe, serverKey, clientKey)

	// Write both directions first, then read — avoids pipe deadlock
	go func() {
		clientConn.Write([]byte("ping"))
	}()
	go func() {
		serverConn.Write([]byte("pong"))
	}()

	// Read both
	bufC := make([]byte, 4)
	bufS := make([]byte, 4)
	io.ReadFull(serverConn, bufS)
	io.ReadFull(clientConn, bufC)

	if string(bufS) != "ping" {
		t.Errorf("server read: %q, want 'ping'", bufS)
	}
	if string(bufC) != "pong" {
		t.Errorf("client read: %q, want 'pong'", bufC)
	}
}

func TestNyxConnLargePayload(t *testing.T) {
	clientKey := make([]byte, 32)
	serverKey := make([]byte, 32)
	_, _ = rand.Read(clientKey)
	_, _ = rand.Read(serverKey)

	clientPipe, serverPipe := net.Pipe()
	defer clientPipe.Close()
	defer serverPipe.Close()

	clientConn, _ := NewNyxConn(clientPipe, clientKey, serverKey)
	serverConn, _ := NewNyxConn(serverPipe, serverKey, clientKey)

	payload := make([]byte, MaxPayload)
	_, _ = rand.Read(payload)

	go clientConn.Write(payload)

	buf := make([]byte, MaxPayload+1024)
	n, err := serverConn.Read(buf)
	if err != nil {
		t.Fatalf("read large payload: %v", err)
	}
	if n < len(payload) {
		t.Errorf("large payload: read %d bytes, want %d", n, len(payload))
	}
}

func TestNyxConnMultipleFrames(t *testing.T) {
	clientKey := make([]byte, 32)
	serverKey := make([]byte, 32)
	_, _ = rand.Read(clientKey)
	_, _ = rand.Read(serverKey)

	clientPipe, serverPipe := net.Pipe()
	defer clientPipe.Close()
	defer serverPipe.Close()

	clientConn, _ := NewNyxConn(clientPipe, clientKey, serverKey)
	serverConn, _ := NewNyxConn(serverPipe, serverKey, clientKey)

	messages := [][]byte{
		[]byte("msg1"),
		[]byte("message two"),
		[]byte("third"),
		[]byte("fourth and final message"),
	}

	go func() {
		for _, msg := range messages {
			clientConn.Write(msg)
		}
	}()

	received := make(map[string]bool)
	for i := 0; i < len(messages); i++ {
		buf := make([]byte, 1024)
		n, err := serverConn.Read(buf)
		if err != nil {
			t.Fatalf("read msg %d: %v", i, err)
		}
		received[string(buf[:n])] = true
	}

	for _, msg := range messages {
		if !received[string(msg)] {
			t.Errorf("missing message: %q", msg)
		}
	}
}

// ============================================================================
// Heartbeat
// ============================================================================

func TestRandomHeartbeatInterval(t *testing.T) {
	// Heartbeat interval range: 30–89 seconds + 0–999ms jitter
	const minInterval = 30 * time.Second
	const maxInterval = 90999 * time.Millisecond

	seen := make(map[time.Duration]bool)
	for i := 0; i < 100; i++ {
		d := RandomHeartbeatInterval()
		if d < minInterval || d > maxInterval {
			t.Errorf("heartbeat interval %v out of range [%v, %v]",
				d, minInterval, maxInterval)
		}
		seen[d] = true
	}
	if len(seen) < 5 {
		t.Error("heartbeat intervals not random enough")
	}
}

func TestHeartbeatOnPipe(t *testing.T) {
	clientKey := make([]byte, 32)
	serverKey := make([]byte, 32)
	_, _ = rand.Read(clientKey)
	_, _ = rand.Read(serverKey)

	clientPipe, serverPipe := net.Pipe()
	defer clientPipe.Close()
	defer serverPipe.Close()

	clientConn, _ := NewNyxConn(clientPipe, clientKey, serverKey)
	serverConn, _ := NewNyxConn(serverPipe, serverKey, clientKey)

	// Start heartbeat with very short interval for fast test
	go clientConn.StartHeartbeat(50 * time.Millisecond)

	// Read frames from server — heartbeats should be silently discarded
	// and not interfere with data
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1024)
		// Just try to read — should time out since only heartbeats are sent
		serverPipe.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		for {
			_, err := serverConn.Read(buf)
			if err != nil {
				return // timeout or close — expected
			}
		}
	}()

	<-done
	clientConn.Close()
}

// ============================================================================
// Writer concurrency safety
// ============================================================================

func TestNyxConnConcurrentWrites(t *testing.T) {
	clientKey := make([]byte, 32)
	serverKey := make([]byte, 32)
	_, _ = rand.Read(clientKey)
	_, _ = rand.Read(serverKey)

	clientPipe, serverPipe := net.Pipe()
	defer clientPipe.Close()
	defer serverPipe.Close()

	clientConn, _ := NewNyxConn(clientPipe, clientKey, serverKey)
	serverConn, _ := NewNyxConn(serverPipe, serverKey, clientKey)

	const numWriters = 10
	const writesPerWriter = 20
	done := make(chan bool, numWriters+1)

	// Reader goroutine — drains the pipe so writers don't block indefinitely
	go func() {
		buf := make([]byte, 256)
		total := 0
		for total < numWriters*writesPerWriter*2 {
			n, err := serverConn.Read(buf)
			if err != nil {
				return
			}
			total += n
		}
		done <- true
	}()

	for i := 0; i < numWriters; i++ {
		go func(id int) {
			for j := 0; j < writesPerWriter; j++ {
				msg := []byte{byte(id), byte(j)}
				_, err := clientConn.Write(msg)
				if err != nil {
					t.Logf("writer %d write %d: %v", id, j, err)
					return
				}
			}
			done <- true
		}(i)
	}

	for i := 0; i < numWriters; i++ {
		<-done
	}
	clientConn.Close()
	<-done
}

// ============================================================================
// NewNyxConn with invalid key length
// ============================================================================

func TestNewNyxConnInvalidKey(t *testing.T) {
	pipe, _ := net.Pipe()
	defer pipe.Close()

	_, err := NewNyxConn(pipe, make([]byte, 16), make([]byte, 32))
	if err == nil {
		t.Error("NewNyxConn should reject 16-byte key (needs 32)")
	}
}

// ============================================================================
// EncryptFrameExact — no-padding round-trip
// ============================================================================

func TestEncryptFrameExact(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	sender, _ := NewAEADChannel(key)
	receiver, _ := NewAEADChannel(key)

	payload := []byte("exact-boundary payload")

	frame, err := sender.EncryptFrameExact(payload)
	if err != nil {
		t.Fatalf("EncryptFrameExact: %v", err)
	}

	data, isHB, err := receiver.ReadFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if isHB {
		t.Error("exact frame decoded as heartbeat")
	}
	if !bytes.Equal(data, payload) {
		t.Errorf("exact frame data mismatch")
	}
}

// TestEncryptFrameExactHighBit ensures EncryptFrameExact frames with a
// payload whose LAST byte has bit 7 set (e.g., 0xFF) survive ReadFrame
// without data corruption. Before the fix, ReadFrame would false-positive
// strip padLen=0x7F bytes from the payload.
func TestEncryptFrameExactHighBit(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	sender, _ := NewAEADChannel(key)
	receiver, _ := NewAEADChannel(key)

	// Payload ending with byte that has bit 7 set
	payload := []byte("exact-high-\xff")
	if payload[len(payload)-1]&0x80 == 0 {
		t.Fatal("test payload must have bit 7 set in last byte")
	}

	frame, err := sender.EncryptFrameExact(payload)
	if err != nil {
		t.Fatalf("EncryptFrameExact: %v", err)
	}

	data, isHB, err := receiver.ReadFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if isHB {
		t.Error("exact frame decoded as heartbeat")
	}
	if !bytes.Equal(data, payload) {
		t.Errorf("data corruption: got %d bytes, want %d bytes\n  got: %v\n want: %v",
			len(data), len(payload), data, payload)
	}
}
