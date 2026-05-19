package protocol

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"
)

// ============================================================================
// Key exchange tests
// ============================================================================

func TestX25519Keypair(t *testing.T) {
	priv1, pub1, err := NewX25519Keypair()
	if err != nil {
		t.Fatalf("keypair1: %v", err)
	}
	pub1Len := len(pub1)
	priv1Len := len(priv1.Bytes())
	if priv1Len != 32 {
		t.Errorf("private key len = %d, want 32", priv1Len)
	}
	if pub1Len != 32 {
		t.Errorf("public key len = %d, want 32", pub1Len)
	}

	// Generate a second keypair — must be different
	priv2, pub2, err := NewX25519Keypair()
	if err != nil {
		t.Fatalf("keypair2: %v", err)
	}
	if bytes.Equal(priv1.Bytes(), priv2.Bytes()) {
		t.Error("two keypairs produced identical private keys")
	}
	if bytes.Equal(pub1, pub2) {
		t.Error("two keypairs produced identical public keys")
	}
}

func TestECDHSharedSecret(t *testing.T) {
	privA, pubA, _ := NewX25519Keypair()
	privB, pubB, _ := NewX25519Keypair()

	s1, err := ComputeSharedSecret(privA, pubB)
	if err != nil {
		t.Fatalf("shared A→B: %v", err)
	}
	s2, err := ComputeSharedSecret(privB, pubA)
	if err != nil {
		t.Fatalf("shared B→A: %v", err)
	}

	if !bytes.Equal(s1, s2) {
		t.Error("ECDH shared secrets do not match")
	}
	if len(s1) != 32 {
		t.Errorf("shared secret len = %d, want 32", len(s1))
	}
}

func TestDeriveBidirectionalKeys(t *testing.T) {
	sharedSecret := make([]byte, 32)
	_, _ = rand.Read(sharedSecret)

	clientKey, serverKey, err := DeriveBidirectionalKeys(sharedSecret)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}

	if len(clientKey) != 32 {
		t.Errorf("clientSendKey len = %d, want 32", len(clientKey))
	}
	if len(serverKey) != 32 {
		t.Errorf("serverSendKey len = %d, want 32", len(serverKey))
	}

	if bytes.Equal(clientKey, serverKey) {
		t.Error("clientSendKey == serverSendKey — bidirectional keys must differ")
	}

	// Deterministic
	c2, s2, _ := DeriveBidirectionalKeys(sharedSecret)
	if !bytes.Equal(clientKey, c2) || !bytes.Equal(serverKey, s2) {
		t.Error("DeriveBidirectionalKeys is not deterministic")
	}
}

// ============================================================================
// Auth frame encode/decode round-trip
// ============================================================================

func TestAuthFrameEncodeDecode(t *testing.T) {
	_, clientPub, _ := NewX25519Keypair()
	shortID := make([]byte, 8)
	_, _ = rand.Read(shortID)
	preamble := GenerateHTTPPreamble("www.example.com")

	frame := &NyxAuthFrame{
		HTTPPreamble: preamble,
		PreambleLen:  uint16(len(preamble)),
		ShortID:      shortID,
		Timestamp:    uint64(time.Now().Unix()),
		ClientECDHPk: clientPub,
	}

	encoded, err := frame.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	if len(encoded) == 0 {
		t.Fatal("encoded frame is empty")
	}

	// Decode
	decoded, bodyEnd, err := DecodeAuthFrame(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if !bytes.Equal(decoded.ClientECDHPk, clientPub) {
		t.Error("client public key mismatch")
	}
	if !bytes.Equal(decoded.ShortID, shortID) {
		t.Error("short ID mismatch")
	}
	if decoded.PreambleLen != uint16(len(preamble)) {
		t.Errorf("preamble len = %d, want %d", decoded.PreambleLen, len(preamble))
	}
	if decoded.Timestamp != frame.Timestamp {
		t.Errorf("timestamp = %d, want %d", decoded.Timestamp, frame.Timestamp)
	}
	// decoded.HTTPPreamble = preamble + random pad bytes.
	// PreambleLen tells us where the real preamble ends.
	extracted := decoded.HTTPPreamble
	if decoded.PreambleLen > 0 && int(decoded.PreambleLen) <= len(extracted) {
		extracted = extracted[:decoded.PreambleLen]
	}
	if !bytes.Equal(extracted, preamble) {
		t.Errorf("HTTP preamble mismatch: got %d bytes, want %d", len(extracted), len(preamble))
	}

	if bodyEnd <= 0 || bodyEnd > len(encoded) {
		t.Errorf("bodyEnd = %d, out of range [1, %d]", bodyEnd, len(encoded))
	}
}

func TestAuthFrameDecodeWithTrailingNoise(t *testing.T) {
	_, clientPub, _ := NewX25519Keypair()
	shortID := make([]byte, 8)
	_, _ = rand.Read(shortID)
	preamble := GenerateHTTPPreamble("www.example.com")

	frame := &NyxAuthFrame{
		HTTPPreamble: preamble,
		PreambleLen:  uint16(len(preamble)),
		ShortID:      shortID,
		Timestamp:    uint64(time.Now().Unix()),
		ClientECDHPk: clientPub,
	}
	encoded, _ := frame.Encode()

	// Add random noise AFTER the frame — tests that the decoder correctly
	// identifies the frame boundary and returns bodyEnd < total length.
	trailingNoise := make([]byte, 64)
	_, _ = rand.Read(trailingNoise)
	noisy := append(encoded, trailingNoise...)

	decoded, bodyEnd, err := DecodeAuthFrame(noisy)
	if err != nil {
		t.Fatalf("decode with trailing noise: %v", err)
	}
	if !bytes.Equal(decoded.ShortID, shortID) {
		t.Error("short ID mismatch with trailing noise")
	}
	if bodyEnd >= len(noisy) {
		t.Errorf("bodyEnd=%d should be < total=%d (noise after frame not detected)",
			bodyEnd, len(noisy))
	}
}

// ============================================================================
// Auth response encode/decode
// ============================================================================

func TestAuthResponseRoundTrip(t *testing.T) {
	sharedSecret := make([]byte, 32)
	_, _ = rand.Read(sharedSecret)
	_, serverKey, _ := DeriveBidirectionalKeys(sharedSecret)
	_, serverPub, _ := NewX25519Keypair()

	encoded, err := EncodeAuthResponse(serverKey, StatusSuccess, serverPub)
	if err != nil {
		t.Fatalf("encode response: %v", err)
	}

	if len(encoded) != AuthResponseMinLen {
		t.Errorf("response len = %d, want %d", len(encoded), AuthResponseMinLen)
	}

	// Parse server pubkey
	parsedPub, err := ParseServerPubkey(encoded)
	if err != nil {
		t.Fatalf("parse pubkey: %v", err)
	}
	if !bytes.Equal(parsedPub, serverPub) {
		t.Error("server pubkey mismatch")
	}

	// Decode response
	resp, err := DecodeAuthResponse(serverKey, encoded[:24], encoded[56:56+AuthRespCiphertextLen])
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != StatusSuccess {
		t.Errorf("status = %02x, want %02x", resp.Status, StatusSuccess)
	}
}

func TestAuthResponseRejectStatus(t *testing.T) {
	sharedSecret := make([]byte, 32)
	_, _ = rand.Read(sharedSecret)
	_, serverKey, _ := DeriveBidirectionalKeys(sharedSecret)
	_, serverPub, _ := NewX25519Keypair()

	encoded, err := EncodeAuthResponse(serverKey, StatusFail, serverPub)
	if err != nil {
		t.Fatalf("encode fail: %v", err)
	}

	resp, err := DecodeAuthResponse(serverKey, encoded[:24], encoded[56:56+AuthRespCiphertextLen])
	if err != nil {
		t.Fatalf("decode fail: %v", err)
	}
	if resp.Status != StatusFail {
		t.Errorf("status = %02x, want %02x", resp.Status, StatusFail)
	}
}

func TestAuthResponseRejectWrongKey(t *testing.T) {
	sk1 := make([]byte, 32)
	sk2 := make([]byte, 32)
	_, _ = rand.Read(sk1)
	_, _ = rand.Read(sk2)

	_, key1, _ := DeriveBidirectionalKeys(sk1)
	_, key2, _ := DeriveBidirectionalKeys(sk2)
	_, serverPub, _ := NewX25519Keypair()

	encoded, _ := EncodeAuthResponse(key1, StatusSuccess, serverPub)

	_, err := DecodeAuthResponse(key2, encoded[:24], encoded[56:56+AuthRespCiphertextLen])
	if err == nil {
		t.Error("decode with wrong key should have failed but didn't")
	}
}

// ============================================================================
// Timestamp validation
// ============================================================================

func TestGenerateHTTPPreamble(t *testing.T) {
	preamble := GenerateHTTPPreamble("www.example.com")

	if len(preamble) < 4 {
		t.Fatal("preamble too short")
	}

	first4 := string(preamble[:4])
	if first4 != "GET " && first4 != "POST" {
		t.Errorf("preamble starts with %q, want GET or POST", first4)
	}

	if len(preamble) < MinPreambleLen || len(preamble) > MaxPreambleLen {
		t.Errorf("preamble len = %d, want [%d, %d]", len(preamble), MinPreambleLen, MaxPreambleLen)
	}

	if !bytes.Contains(preamble, []byte("Host:")) {
		t.Error("preamble missing Host header")
	}
}

func TestGenerateHTTPPreambleRandomness(t *testing.T) {
	p1 := GenerateHTTPPreamble("example.com")
	p2 := GenerateHTTPPreamble("example.com")

	if bytes.Equal(p1, p2) {
		t.Error("two preambles identical — randomization failed")
	}
}

// ============================================================================
// Helper
// ============================================================================

func hexToBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
