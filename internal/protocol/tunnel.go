// Package protocol — Nyx encrypted tunnel (v2)
//
// Data frame format (Shadowsocks AEAD-style with XChaCha20-Poly1305):
//   [encrypted_len: 2B] [AEAD_ciphertext: var]
//   encrypted_len = actual_len XOR keystream[0:2]
//   AEAD_ciphertext = XChaCha20-Poly1305(nonce, payload || random_pad, nil)
//
// Nonce design: XChaCha20 24-byte nonce, first 8 bytes = LE counter.
//   data nonce:     counter || 0x0...0x00  (used for AEAD encrypt/decrypt)
//   keystream nonce: counter || 0x0...0xFF  (used for length-field XOR)
// Never collide because byte 23 differs (0x00 vs 0xFF).
//
// v2.1: Pre-created keystream AEAD for length field (no per-frame allocation).
//        AEADChannel.ReadFrame() handles entire frame read in one call.
//        Removed wasteful readOneFrame buffer loop.
package protocol

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// Frame constants
const (
	LenFieldSize = 2  // encrypted length field
	TagSize      = 16 // Poly1305 auth tag

	MinPayload = 64   // minimum heartbeat payload size
	MaxPayload = 8192 // maximum data payload size
	MaxPadSize  = 512 // maximum random padding per heartbeat frame

	XNonceSize = 24 // XChaCha20-Poly1305 nonce size

	// Frame type markers — first byte of decrypted AEAD payload
	FrameTypeData      = 0x00 // regular data
	FrameTypeHeartbeat = 0x01 // idle keepalive (random payload, no real data)

	// FrameMaxPadLen is the maximum random tail padding added to data frames.
	// Padding occurs INSIDE the AEAD plaintext (before XChaCha20-Poly1305 encrypt),
	// not at the TLS layer. Go's crypto/tls does NOT implement RFC 8446 §5.4
	// record padding — each Nyx frame translates to exactly one TLS ApplicationData
	// record, so without Nyx-level padding, record sizes are deterministic.
	// Format: [type][payload][random_pad:0~FrameMaxPadLen][pad_len:1B]
	// Receiver strips pad_len+1 bytes from the tail to recover the payload.
	FrameMaxPadLen = 127 // 0–127 bytes of random padding per frame (7 bits, bit 7 reserved for marker)

	// Max wire frame = LenField + AEAD_ciphertext
	// Worst case: 1-byte data → 1(type)+1(data) = 2B plaintext → AEAD overhead(TagSize)
	//              = LenField(2) + ciphertext(2+TagSize) = 20 bytes minimum
	// Max case:   MaxPayload + FrameMaxPadLen + 1(pad_len marker)
	MaxWireFrame = LenFieldSize + 1 + MaxPayload + FrameMaxPadLen + 1 + TagSize
)

// ============================================================================
// XChaCha20-Poly1305
// ============================================================================

func newXChaChaAEAD(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.NewX(key)
}

// ============================================================================
// AEADChannel — single-direction encrypt/decrypt with nonce counter (v2.1)
// ============================================================================

type AEADChannel struct {
	aead      cipher.AEAD // data AEAD (nonce byte 23 = 0x00)
	ksAEAD    cipher.AEAD // keystream AEAD (nonce byte 23 = 0xFF), created once
	nonce     uint64
	mu        sync.Mutex   // protect nonce and crypto operations
	nonceBuf  [XNonceSize]byte  // pre-allocated nonce buffer (no per-frame alloc)
	zeroPl    [2]byte            // pre-allocated zero plaintext for length-field keystream
	ksSealBuf [2 + TagSize]byte  // pre-allocated Seal output for length-field keystream
}

// NewAEADChannel creates a new AEAD channel for one direction.
func NewAEADChannel(key []byte) (*AEADChannel, error) {
	aead, err := newXChaChaAEAD(key)
	if err != nil {
		return nil, fmt.Errorf("XChaCha20-Poly1305 data AEAD: %w", err)
	}
	// Second AEAD for keystream — different nonce space (last byte flipped)
	// so there is ZERO risk of nonce reuse with the data AEAD.
	ksAEAD, err := newXChaChaAEAD(key)
	if err != nil {
		return nil, fmt.Errorf("XChaCha20-Poly1305 keystream AEAD: %w", err)
	}
	return &AEADChannel{
		aead:   aead,
		ksAEAD: ksAEAD,
		nonce:  0,
	}, nil
}

// makeNonce fills the pre-allocated nonce buffer with the given counter.
// Data nonces use byte 23 = 0x00; keystream nonces flip byte 23 to 0xFF.
// Returns a slice backed by ch.nonceBuf — valid only until the next call
// within the same locked section.
func (ch *AEADChannel) makeNonce(counter uint64, keystream bool) []byte {
	binary.LittleEndian.PutUint64(ch.nonceBuf[0:8], counter)
	if keystream {
		ch.nonceBuf[XNonceSize-1] = 0xFF
	} else {
		ch.nonceBuf[XNonceSize-1] = 0x00
	}
	return ch.nonceBuf[:]
}

// encryptLength XOR-encrypts the 2-byte length field with XChaCha20 keystream.
// Uses pre-created ksAEAD and pre-allocated buffers — no alloc per frame.
// counter is the nonce for the KEYSREAM operation (counter byte 23 = 0xFF).
func (ch *AEADChannel) encryptLength(actualLen uint16, counter uint64) [2]byte {
	ksNonce := ch.makeNonce(counter, true)
	ks := ch.ksAEAD.Seal(ch.ksSealBuf[:0], ksNonce, ch.zeroPl[:], nil)[:2]
	return [2]byte{ks[0] ^ byte(actualLen>>8), ks[1] ^ byte(actualLen)}
}

// decryptLength XOR-decrypts the 2-byte length field.
// counter is the nonce for the KEYSREAM operation.
func (ch *AEADChannel) decryptLength(encLen [2]byte, counter uint64) uint16 {
	ksNonce := ch.makeNonce(counter, true)
	ks := ch.ksAEAD.Seal(ch.ksSealBuf[:0], ksNonce, ch.zeroPl[:], nil)[:2]
	return uint16(encLen[0]^ks[0])<<8 | uint16(encLen[1]^ks[1])
}

// EncryptFrameExact encrypts payload WITHOUT random padding.
// Appends a padLen=0|0x80 marker to make the frame format identical to
// EncryptFrame's output, so ReadFrame's padding-strip logic works for both.
// Without the marker, ReadFrame may false-positive strip data if the last
// payload byte coincidentally has bit 7 set (~0.8% probability per frame).
func (ch *AEADChannel) EncryptFrameExact(payload []byte) ([]byte, error) {
	ch.mu.Lock()
	defer ch.mu.Unlock()

	ch.nonce++
	if ch.nonce == 0 {
		return nil, fmt.Errorf("nonce counter exhausted — connection must be re-established")
	}
	ksCounter := ch.nonce
	dataCounter := ch.nonce - 1

	// FrameTypeData + payload + padLen=0 marker (bit 7 set)
	plaintext := make([]byte, 1+len(payload)+1)
	plaintext[0] = FrameTypeData
	copy(plaintext[1:], payload)
	plaintext[len(plaintext)-1] = 0x80 // padLen=0 with bit 7 set

	dataNonce := ch.makeNonce(dataCounter, false)
	ciphertext := ch.aead.Seal(nil, dataNonce, plaintext, nil)
	actualLen := uint16(len(ciphertext))
	encLen := ch.encryptLength(actualLen, ksCounter)

	frame := make([]byte, LenFieldSize+len(ciphertext))
	copy(frame, encLen[:])
	copy(frame[LenFieldSize:], ciphertext)

	return frame, nil
}

// EncryptFrame encrypts payload and returns the complete wire frame.
// Prepends FrameTypeData (0x00) marker to the plaintext for frame type detection.
//
// Nonce safety: increments ch.nonce FIRST, then uses ch.nonce for keystream
// and ch.nonce-1 for data AEAD. This guarantees no nonce reuse even if the
// function returns an error between keystream and data operations.
//
// Nonce exhaustion: after 2^64 frames the uint64 counter wraps to zero.
// This is theoretically impossible on any real connection (it would require
// transmitting over 10^17 PB of data), but we detect it as a defense-in-depth
// measure — silent nonce reuse is cryptographically catastrophic.
func (ch *AEADChannel) EncryptFrame(payload []byte) ([]byte, error) {
	ch.mu.Lock()
	defer ch.mu.Unlock()

	ch.nonce++
	if ch.nonce == 0 {
		return nil, fmt.Errorf("nonce counter exhausted — connection must be re-established")
	}
	ksCounter := ch.nonce       // keystream nonce: (N+1, 0xFF)
	dataCounter := ch.nonce - 1 // data nonce:      (N,   0x00)

	padded := wrapFrameData(payload)
	dataNonce := ch.makeNonce(dataCounter, false)
	ciphertext := ch.aead.Seal(nil, dataNonce, padded, nil)
	actualLen := uint16(len(ciphertext))
	encLen := ch.encryptLength(actualLen, ksCounter)

	frame := make([]byte, LenFieldSize+len(ciphertext))
	copy(frame, encLen[:])
	copy(frame[LenFieldSize:], ciphertext)

	return frame, nil
}

// EncryptHeartbeat creates a heartbeat frame — indistinguishable from
// a regular data frame on the wire, but with a FrameTypeHeartbeat marker.
//
// Wire size: random (64–320 byte plaintext → 82–338 byte wire frame),
// identical distribution to light-traffic data frames.
// GFW cannot distinguish heartbeat frames from data by size alone.
func (ch *AEADChannel) EncryptHeartbeat() ([]byte, error) {
	ch.mu.Lock()
	defer ch.mu.Unlock()

	ch.nonce++
	if ch.nonce == 0 {
		return nil, fmt.Errorf("nonce counter exhausted — connection must be re-established")
	}
	ksCounter := ch.nonce
	dataCounter := ch.nonce - 1

	// Heartbeat payload: random size to blend with data frame distribution.
	// Bounded [MinPayload, MinPayload+MaxPadSize/2] = [64, 320] — matching
	// the size distribution of small encrypted data frames.
	hbSize := MinPayload
	if MaxPadSize > 0 {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(MaxPadSize/2+1)))
		if err == nil {
			hbSize = MinPayload + int(n.Int64())
		}
	}
	hbPayload := make([]byte, hbSize)
	hbPayload[0] = FrameTypeHeartbeat
	if _, err := rand.Read(hbPayload[1:]); err != nil {
		// CSPRNG failure is a system-level emergency. Fall back to time-seeded
		// deterministic mixer so heartbeat payloads are never all-zero.
		// Seed once with time (NOT per-iteration — time.Now() in a tight loop
		// returns the same nanosecond, creating a trivially fingerprintable pattern).
		log.Printf("[CRITICAL] rand.Read heartbeat payload failed: %v — using SplitMix64 fallback", err)
		base := uint64(time.Now().UnixNano())
		for i := 1; i < hbSize; i++ {
			hbPayload[i] = byte((base>>uint((i*17)%64)) ^ uint64(i)*0x9E3779B97F4A7C15)
		}
	}

	dataNonce := ch.makeNonce(dataCounter, false)
	ciphertext := ch.aead.Seal(nil, dataNonce, hbPayload, nil)
	actualLen := uint16(len(ciphertext))
	encLen := ch.encryptLength(actualLen, ksCounter)

	frame := make([]byte, LenFieldSize+len(ciphertext))
	copy(frame, encLen[:])
	copy(frame[LenFieldSize:], ciphertext)

	return frame, nil
}

// ReadFrame reads one complete Nyx frame from the reader.
// Handles TCP fragmentation — reads exactly what it needs based on decrypted length.
// Returns the data payload (with type byte stripped) and a boolean indicating
// whether this is a heartbeat frame.
//
// Nonce safety: increments ch.nonce BEFORE any network I/O. Uses ch.nonce for
// keystream and ch.nonce-1 for data AEAD. If a network read fails mid-frame,
// the nonce is already advanced — no reuse on retry.
func (ch *AEADChannel) ReadFrame(r io.Reader) (payload []byte, isHeartbeat bool, err error) {
	ch.mu.Lock()
	defer ch.mu.Unlock()

	// Increment nonce FIRST to prevent keystream nonce reuse on mid-frame failure.
	ch.nonce++
	if ch.nonce == 0 {
		return nil, false, fmt.Errorf("nonce counter exhausted — connection must be re-established")
	}
	ksCounter := ch.nonce       // keystream nonce: (N+1, 0xFF)
	dataCounter := ch.nonce - 1 // data nonce:      (N,   0x00)

	// 1. Read encrypted length field (2 bytes)
	var lenBuf [LenFieldSize]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, false, err
	}

	// 2. Decrypt length to get actual ciphertext size
	actualLen := ch.decryptLength(lenBuf, ksCounter)

	// 3. Validate — prevent absurdly large allocations
	if actualLen > uint16(MaxWireFrame) {
		return nil, false, fmt.Errorf("frame too large: %d > %d", actualLen, MaxWireFrame)
	}
	if actualLen < TagSize+1 { // minimum: 1 byte payload (heartbeat marker)
		return nil, false, fmt.Errorf("frame too small: %d < %d", actualLen, TagSize+1)
	}

	// 4. Read exactly the ciphertext
	ciphertext := make([]byte, actualLen)
	if _, err := io.ReadFull(r, ciphertext); err != nil {
		return nil, false, fmt.Errorf("read ciphertext: %w", err)
	}

	// 5. AEAD decrypt
	dataNonce := ch.makeNonce(dataCounter, false)
	plaintext, err := ch.aead.Open(nil, dataNonce, ciphertext, nil)
	if err != nil {
		return nil, false, fmt.Errorf("AEAD open: %w", err)
	}

	if len(plaintext) == 0 {
		return nil, false, fmt.Errorf("empty plaintext")
	}

	// 6. Check frame type marker (first byte)
	frameType := plaintext[0]
	payload = plaintext[1:]

	switch frameType {
	case FrameTypeData:
		isHeartbeat = false
		// Strip padding: last byte is pad_len|0x80 marker.
		// plaintext = [type][payload][pad_bytes...][marker]
		// payload  = plaintext[1 : len-1-padLen]
		if len(plaintext) >= 2 {
			padLenMarker := plaintext[len(plaintext)-1]
			padLen := padLenMarker & 0x7F
			// Defensive: if marker is invalid (padLen too large), skip stripping.
			if padLenMarker&0x80 != 0 && int(padLen)+2 <= len(plaintext) {
				payload = plaintext[1 : len(plaintext)-1-int(padLen)]
			} else {
				payload = plaintext[1:]
			}
		} else {
			payload = plaintext[1:]
		}
	case FrameTypeHeartbeat:
		isHeartbeat = true
	default:
		return nil, false, fmt.Errorf("unknown frame type: 0x%02x", frameType)
	}

	return payload, isHeartbeat, nil
}

// ============================================================================
// NyxConn — encrypting net.Conn (v2.4)
// ============================================================================

type NyxConn struct {
	rawConn net.Conn
	writeCh *AEADChannel
	readCh  *AEADChannel

	readBuf []byte // leftover decrypted data
	readOff int
	mu      sync.Mutex

	hbDone chan struct{} // closed when connection is shut down
	hbOnce sync.Once     // ensures hbDone is closed exactly once

	// First-frame obfuscation — randomizes the first Nyx data frame size
	// to prevent DPI from fingerprinting the initial yamux protocol SYN.
	// Applied at the Nyx level (before AEAD encryption) so both client
	// and server see the same salted/desalted data through the tunnel.
	firstWrite bool // true until first Write() completes
	firstRead  bool // true until first data frame is Read()
}

// NewNyxConn wraps a raw connection with Nyx encryption.
// writeKey encrypts outgoing data, readKey decrypts incoming data.
func NewNyxConn(raw net.Conn, writeKey, readKey []byte) (*NyxConn, error) {
	writeCh, err := NewAEADChannel(writeKey)
	if err != nil {
		return nil, fmt.Errorf("write channel: %w", err)
	}
	readCh, err := NewAEADChannel(readKey)
	if err != nil {
		return nil, fmt.Errorf("read channel: %w", err)
	}
	return &NyxConn{
		rawConn:    raw,
		writeCh:    writeCh,
		readCh:     readCh,
		hbDone:     make(chan struct{}),
		firstWrite: true,
		firstRead:  true,
	}, nil
}

// WriteExact writes exactly one frame without random padding.
// Use for protocol-level payloads where the receiver needs the exact boundary.
// The payload MUST fit in a single frame (max 1446 bytes with MaxPayload padding).
func (nc *NyxConn) WriteExact(p []byte) error {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	frame, err := nc.writeCh.EncryptFrameExact(p)
	if err != nil {
		return fmt.Errorf("encrypt exact: %w", err)
	}
	if _, err := nc.rawConn.Write(frame); err != nil {
		return fmt.Errorf("raw write: %w", err)
	}
	return nil
}

// Write encrypts data into Nyx frames and writes them to the raw connection.
//
// First-frame obfuscation: the initial write after auth (typically the yamux
// protocol SYN frame) is salted with SaltFirstFrame to randomize its wire size.
// This prevents DPI from correlating the fixed-size yamux SYN across connections.
// Only applied when p fits in one frame — salting a multi-frame write would break
// the unsalt logic on the receiver side. yamux SYN is ~12 bytes (<< MaxPayload),
// so this always applies in practice.
func (nc *NyxConn) Write(p []byte) (int, error) {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	// First-frame obfuscation: wrap the first write with random salt.
	// Max salt overhead: SaltMarker(1) + salt_len(1) + MaxSaltLen(16) = 18 bytes
	if nc.firstWrite && len(p)+SaltMarkerOverhead <= MaxPayload {
		p = SaltFirstFrame(p)
	}
	nc.firstWrite = false

	offset := 0
	for offset < len(p) {
		end := offset + MaxPayload
		if end > len(p) {
			end = len(p)
		}
		chunk := p[offset:end]

		frame, err := nc.writeCh.EncryptFrame(chunk)
		if err != nil {
			return offset, fmt.Errorf("encrypt: %w", err)
		}

		if _, err := nc.rawConn.Write(frame); err != nil {
			return offset, fmt.Errorf("raw write: %w", err)
		}

		offset = end
	}
	return len(p), nil
}

// Read decrypts the next Nyx frame and returns its payload.
// Heartbeat frames are silently skipped — the caller never sees them.
//
// Goroutine safety: Read() is safe for single-reader use — concurrent
// Read() from multiple goroutines on the same NyxConn is not supported
// (Net.Conn is not goroutine-safe for concurrent reads in general).
// The mutex is released during network I/O (ReadFrame) so concurrent
// Write() calls in the relay pattern are not blocked — only readBuf
// mutation is serialized.
func (nc *NyxConn) Read(p []byte) (int, error) {
	nc.mu.Lock()
	// Serve buffered data first
	if nc.readOff < len(nc.readBuf) {
		n := copy(p, nc.readBuf[nc.readOff:])
		nc.readOff += n
		if nc.readOff >= len(nc.readBuf) {
			nc.readBuf = nil
			nc.readOff = 0
		}
		nc.mu.Unlock()
		return n, nil
	}
	nc.mu.Unlock()

	// Read complete frames
	for {
		payload, isHeartbeat, err := nc.readCh.ReadFrame(nc.rawConn)
		if err != nil {
			return 0, err
		}

		// Heartbeat: silently discard, read next frame
		if isHeartbeat {
			continue
		}

		if len(payload) == 0 {
			continue
		}

		// First-frame desalting: strip the random salt prefix added by
		// SaltFirstFrame on the write side. Applied only once per connection,
		// matching the first Write() on the peer side.
		if nc.firstRead {
			payload = UnsaltFirstFrame(payload)
			nc.firstRead = false
		}

		n := copy(p, payload)
		if n < len(payload) {
			// Buffer leftover data for next Read
			nc.mu.Lock()
			nc.readBuf = payload
			nc.readOff = n
			nc.mu.Unlock()
		}
		return n, nil
	}
}

// Close closes the underlying connection and signals the heartbeat goroutine
// to stop. Safe to call multiple times.
func (nc *NyxConn) Close() error {
	nc.hbOnce.Do(func() { close(nc.hbDone) })
	return nc.rawConn.Close()
}

// SendHeartbeat sends a single heartbeat frame. Safe for concurrent use.
//
// Holds nc.mu during the rawConn.Write to prevent frame interleaving with
// Write()/WriteExact(). This does NOT cause deadlocks — Read() releases
// nc.mu before calling ReadFrame() (the network I/O call), so a heartbeat
// waiting on nc.mu while Read() is in progress won't block the reader.
//
// P109: Without this lock, concurrent SendHeartbeat + Write could produce
// interleaved Nyx frames on the wire, causing AEAD decryption failures
// and tunnel disconnection during idle periods.
func (nc *NyxConn) SendHeartbeat() error {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	frame, err := nc.writeCh.EncryptHeartbeat()
	if err != nil {
		return err
	}
	_, err = nc.rawConn.Write(frame)
	return err
}

// StartHeartbeat sends heartbeat frames at the given interval to prevent
// dead-air detection by GFW. Runs until the connection is closed.
// Typical interval: 30s–120s (randomized per-connection to avoid fingerprint).
func (nc *NyxConn) StartHeartbeat(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-nc.hbDone:
			return // connection closed, stop immediately
		case <-ticker.C:
			if err := nc.SendHeartbeat(); err != nil {
				return // connection closed, stop
			}
		}
	}
}

// SetReadBuffer injects pre-read bytes into the NyxConn's read buffer.
// This is used when auth frame parsing consumed more bytes than the auth
// frame itself — the leftover bytes are the first Nyx-encrypted data frame.
func (nc *NyxConn) SetReadBuffer(data []byte) {
	if len(data) == 0 {
		return
	}
	nc.mu.Lock()
	defer nc.mu.Unlock()
	nc.readBuf = data
	nc.readOff = 0
	// Set firstRead=false because data came from the network after auth,
	// not from the first Nyx frame read path. The first real Nyx frame
	// has already been consumed — this IS it.
	nc.firstRead = false
}

// LocalAddr returns the local network address.
func (nc *NyxConn) LocalAddr() net.Addr { return nc.rawConn.LocalAddr() }

// RemoteAddr returns the remote network address.
func (nc *NyxConn) RemoteAddr() net.Addr { return nc.rawConn.RemoteAddr() }

// SetDeadline sets the read/write deadline on the underlying connection.
func (nc *NyxConn) SetDeadline(t time.Time) error { return nc.rawConn.SetDeadline(t) }

// SetReadDeadline sets the read deadline on the underlying connection.
func (nc *NyxConn) SetReadDeadline(t time.Time) error { return nc.rawConn.SetReadDeadline(t) }

// SetWriteDeadline sets the write deadline on the underlying connection.
func (nc *NyxConn) SetWriteDeadline(t time.Time) error { return nc.rawConn.SetWriteDeadline(t) }

// ============================================================================
// Padding
// ============================================================================

func wrapFrameData(payload []byte) []byte {
	// Generate random pad length: 0 – FrameMaxPadLen bytes.
	// Uses crypto/rand for unpredictability. PadLen ≤ 127 (7 bits) so
	// padLen|0x80 never appears in real payload data — if a payload byte
	// matches padLen by chance, the extra bit disambiguates it from the marker.
	padLen := byte(0)
	n, err := rand.Int(rand.Reader, big.NewInt(int64(FrameMaxPadLen+1)))
	if err == nil {
		padLen = byte(n.Int64())
	} else {
		// CSPRNG failure — use time-seeded fallback to avoid deterministic sizing.
		padLen = byte(uint64(time.Now().UnixNano()) % (FrameMaxPadLen + 1))
	}

	// Frame format: [type_byte:1][payload][random_pad:padLen][pad_len|0x80:1]
	// The pad_len byte has bit 7 set to distinguish it from normal payload bytes.
	raw := make([]byte, 1+len(payload)+int(padLen)+1)
	raw[0] = FrameTypeData
	copy(raw[1:], payload)
	// Fill padding bytes
	if padLen > 0 {
		if _, err := rand.Read(raw[1+len(payload) : 1+len(payload)+int(padLen)]); err != nil {
			// CSPRNG failure — time-seeded fallback.
			base := uint64(time.Now().UnixNano())
			for i := byte(0); i < padLen; i++ {
				raw[1+len(payload)+int(i)] = byte((base>>uint((i*17)%64)) ^ uint64(i)*0x9E3779B97F4A7C15)
			}
		}
	}
	// Marker: padLen with bit 7 set for unambiguous identification.
	raw[len(raw)-1] = padLen | 0x80
	return raw
}

// ============================================================================
// Convenience
// ============================================================================

// RandomHeartbeatInterval returns a randomized heartbeat interval (30–90 seconds).
// Per-connection randomization prevents timing fingerprint correlation across flows.
// Uses crypto/rand.Int for uniform distribution — no modulo bias.
func RandomHeartbeatInterval() time.Duration {
	// Base range: 30–89 seconds (60 possible values)
	baseN, err := rand.Int(rand.Reader, big.NewInt(60))
	if err != nil {
		baseN = big.NewInt(30) // fallback: 60s
	}
	base := 30 + int(baseN.Int64())

	// Jitter: 0–999ms
	jitterN, err := rand.Int(rand.Reader, big.NewInt(1000))
	if err != nil {
		jitterN = big.NewInt(500) // fallback: 500ms
	}
	jitter := time.Duration(jitterN.Int64()) * time.Millisecond

	return time.Duration(base)*time.Second + jitter
}

// ============================================================================
// First-frame obfuscation — eliminates host:port fingerprint
// ============================================================================
//
// Problem: Without obfuscation, the very first data frame after handshake
// always contains a host:port address (e.g., "www.example.com:443").
// An observer seeing N connections with identical first-frame length
// distribution can fingerprint it as Nyx.
//
// Solution: Prefix the target address with a random-length salt.
// Wire format: [salt_len:1B][salt:0-16B][targetAddr]
// GFW sees random-length first frames, indistinguishable from regular data.

const MaxSaltLen = 16 // max bytes of random salt before target address
const SaltMarkerOverhead = 1 + 1 + MaxSaltLen // SaltMarker(1) + salt_len(1) + max salt(16) = 18

// SaltMarker is prepended to salted first frames so the receiver can
// reliably distinguish salted from unsalted payloads without out-of-band
// signaling. Set to 0xFE to avoid collision with FrameTypeData (0x00),
// FrameTypeHeartbeat (0x01), and any common yamux frame prefix.
const SaltMarker = 0xFE

// SaltFirstFrame wraps a payload (targetAddr) with random salt prefix.
// Format: [SaltMarker:1][salt_len:1][salt:0-16][payload]
// The SaltMarker allows UnsaltFirstFrame to self-detect whether the
// payload was salted — no out-of-band signal needed between peers.
func SaltFirstFrame(payload []byte) []byte {
	saltLen := byte(0)
	n, err := rand.Int(rand.Reader, big.NewInt(int64(MaxSaltLen+1)))
	if err == nil {
		saltLen = byte(n.Int64())
	} else {
		// CSPRNG failure — seed with time so salt length is never locked at 0.
		// A fixed salt=0 on first frame creates a trivially fingerprintable
		// frame size (exactly len(payload)+2), distinguishable from the
		// variable-size frames of genuine TLS ApplicationData.
		saltLen = byte(uint64(time.Now().UnixNano()) % (MaxSaltLen + 1))
	}

	salt := make([]byte, saltLen)
	if saltLen > 0 {
		if _, err := rand.Read(salt); err != nil {
			// CSPRNG failure — use time-seeded mixer fallback.
			base := uint64(time.Now().UnixNano())
			for i := range salt {
				salt[i] = byte((base>>uint((i*17)%64)) ^ uint64(i)*0x9E3779B97F4A7C15)
			}
		}
	}

	result := make([]byte, 1+1+int(saltLen)+len(payload))
	result[0] = SaltMarker
	result[1] = saltLen
	copy(result[2:], salt)
	copy(result[2+saltLen:], payload)
	return result
}

// UnsaltFirstFrame strips the salt prefix IF the SaltMarker is present.
// If the data doesn't start with SaltMarker, it's returned as-is —
// the payload was never salted (e.g., too large for single-frame salting).
func UnsaltFirstFrame(data []byte) []byte {
	if len(data) < 2 {
		return data
	}
	if data[0] != SaltMarker {
		return data // not salted — pass through
	}
	saltLen := data[1]
	if int(saltLen)+2 > len(data) {
		// Corrupted frame — best effort
		return data
	}
	return data[2+saltLen:]
}
