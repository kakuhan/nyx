// Package protocol implements Nyx v2 anti-censorship tunnel protocol.
// v2 improvements over v1:
//   - XChaCha20-Poly1305 AEAD (24-byte nonce, > ChaCha20's 12-byte)
//   - Bidirectional keys (HKDF derives clientSendKey + serverSendKey)
//   - Anti-replay timestamp in auth frame (8-byte Unix second, ±90s window)
//   - Randomized preamble: varied User-Agent, path, headers
//   - Randomized pad length (16-64 bytes, not fixed 12)
//   - AuthResponse encrypted with serverSendKey
//   - Protocol version byte for future negotiation
package protocol

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
)

// Protocol constants
const (
	// Marker is the 4-byte magic that begins every Nyx auth frame.
	// Hidden inside HTTP-like preamble noise — not trivially DPI-matchable.
	Marker = "NYXK"

	ProtocolVersion byte = 0x02 // v2 protocol

	// Preamble bounds
	// MaxPreambleLen=768 prevents silent truncation: with ALL optional headers
	// (Upgrade-Insecure-Requests + Cache-Control + Sec-Fetch-* triplet) and a
	// long User-Agent, the preamble can reach 533 bytes. Truncation at 512
	// cuts the HTTP request mid-header, creating a malformed preamble that
	// DPI can fingerprint as non-browser traffic. 768 provides safe headroom
	// while staying well within the server's 4096-byte read buffer.
	MinPreambleLen = 200
	MaxPreambleLen = 768

	// PadLen randomized per-frame
	MinPadLen = 16
	MaxPadLen = 64

	// Auth frame wire layout (after preamble+pad+marker):
	//   version(1) + shortID(8) + preambleLen(2) + timestamp(8) + clientPub(32) + hmac(32) = 83
	AuthBodyLen = 1 + 8 + 2 + 8 + 32 + 32

	// AuthResponse: nonce(24) + server_pubkey_cleartext(32) + encrypted(version+status=2 + tag=16)
	// Total: exactly 74 bytes. No random padding — TLS 1.3 provides record-level padding.
	AuthResponseMinLen   = 74   // nonce(24) + pubkey(32) + ciphertext(18)
	AuthRespCiphertextLen = AuthResponseMinLen - 24 - 32 // = 18 bytes: version(1)+status(1)+tag(16)
	// Callers MUST pass exactly AuthRespCiphertextLen bytes of ciphertext to DecodeAuthResponse.

	StatusSuccess = 0x01
	StatusFail    = 0x00

	// HKDF salts (noise strings from Shadowsocks AEAD-2022 design)
	SaltSession      = "nyx-v2-session-key"
	SaltClientSend   = "nyx-v2-client-send"
	SaltServerSend   = "nyx-v2-server-send"
	SaltAuthHMAC     = "nyx-v2-auth-hmac"

	// Anti-replay window
	MaxTimeSkew = 90 // seconds
)

// Sentinel errors for auth frame decoding.
var (
	ErrMarkerNotFound = errors.New("marker 'NYXK' not found in expected region — may need more data")
	ErrAuthTooShort   = errors.New("auth frame too short")
	ErrAuthVersion    = errors.New("unsupported protocol version")
	ErrAuthHMAC       = errors.New("HMAC verification failed")
	ErrTimeSkew       = errors.New("timestamp skew too large")
)

// ============================================================================
// NyxAuthFrame — Client → Server auth frame (v2)
// ============================================================================
// On-wire format (v2.4 — preamble length embedded in auth body):
//   [HTTP_preamble:200-768B] [random_pad:16-64B] [Marker:"NYXK":4B]
//   [version:1B] [shortID:8B] [preambleLen:2B] [timestamp:8B] [clientECDHPk:32B] [HMAC:32B]
//
// CRITICAL: The HTTP preamble is FIRST on the wire — the very first byte is
// always 'G' (from "GET"), a printable ASCII character. This guarantees SET-bit
// exemption: GFW's TLS ApplicationData inspection sees genuine plaintext HTTP.
// Random padding follows the preamble so it cannot contaminate the first byte.
//
// The HTTP preamble contains randomized User-Agent, path, and headers,
// making every auth frame look different to DPI.
// The marker is buried after the preamble+pad — without knowing the
// exact preamble length, a passive observer cannot locate it.

type NyxAuthFrame struct {
	HTTPPreamble []byte // randomized HTTP-like preamble (200-768B)
	PreambleLen  uint16 // actual preamble byte length (validated vs decoder position)
	ShortID      []byte // 8-byte pre-shared identifier
	Timestamp    uint64 // Unix second, anti-replay
	ClientECDHPk []byte // X25519 ephemeral public key (32B)
}

// ============================================================================
// Preamble generation — randomized HTTP request camouflage
// ============================================================================

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:126.0) Gecko/20100101 Firefox/126.0",
}

var paths = []string{
	"/", "/index.html", "/api/v1/status", "/health", "/favicon.ico",
	"/static/js/app.js", "/static/css/style.css", "/robots.txt",
}

var acceptHeaders = []string{
	"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
	"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
	"*/*",
}

// randIntN returns a uniform random integer in [0, n).
// Uses crypto/rand.Int to avoid modulo bias.
// On CSPRNG failure: uses time-based fallback to avoid deterministic (all-0) fingerprint.
func randIntN(n int) int {
	if n <= 0 {
		return 0
	}
	val, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		// CSPRNG failure is a system-level emergency. Do NOT fallback to 0 —
		// that creates a trivially fingerprintable deterministic pattern.
		// Use time-based mixer as a non-crypto emergency fallback.
		log.Printf("[CRITICAL] crypto/rand.Int failed: %v — using time-based fallback", err)
		return int(uint64(time.Now().UnixNano()) % uint64(n))
	}
	return int(val.Int64())
}

// randIntRange returns a uniform random integer in [min, max].
// Uses crypto/rand.Int to avoid modulo bias.
func randIntRange(min, max int) int {
	if min >= max {
		return min
	}
	return min + randIntN(max-min+1)
}

// selectFrom picks a random element from the slice.
// Uses crypto/rand.Int to avoid modulo bias.
func selectFrom[T any](s []T) T {
	if len(s) == 0 {
		var zero T
		return zero
	}
	return s[randIntN(len(s))]
}

// GenerateHTTPPreamble creates a randomized HTTP request preamble.
// Every invocation produces a different preamble — no fixed fingerprint.
func GenerateHTTPPreamble(targetDomain string) []byte {
	ua := selectFrom(userAgents)
	path := selectFrom(paths)
	accept := selectFrom(acceptHeaders)

	// Add random query parameter to path for extra variance
	if randIntN(3) == 0 {
		path += fmt.Sprintf("?v=%d&t=%d",
			randIntRange(100000, 999999),
			time.Now().Unix()%100000)
	}

	b := &bytes.Buffer{}
	fmt.Fprintf(b, "GET %s HTTP/1.1\r\n", path)
	fmt.Fprintf(b, "Host: %s\r\n", targetDomain)
	fmt.Fprintf(b, "User-Agent: %s\r\n", ua)
	fmt.Fprintf(b, "Accept: %s\r\n", accept)
	fmt.Fprintf(b, "Accept-Language: zh-CN,zh;q=0.9,en;q=0.8\r\n")
	fmt.Fprintf(b, "Accept-Encoding: gzip, deflate, br\r\n")
	fmt.Fprintf(b, "Connection: keep-alive\r\n")

	// Random additional headers for variance
	if randIntN(2) == 0 {
		fmt.Fprintf(b, "Upgrade-Insecure-Requests: 1\r\n")
	}
	if randIntN(3) == 0 {
		fmt.Fprintf(b, "Cache-Control: max-age=0\r\n")
	}

	// Sec-Fetch headers (modern Chromium-based browsers only)
	// Firefox does not send these — sending them with a Firefox UA is a
	// protocol-level fingerprint that DPI can use to identify Nyx.
	if strings.Contains(ua, "Chrome") {
		fmt.Fprintf(b, "Sec-Fetch-Dest: document\r\n")
		fmt.Fprintf(b, "Sec-Fetch-Mode: navigate\r\n")
		fmt.Fprintf(b, "Sec-Fetch-Site: none\r\n")
	}

	b.WriteString("\r\n")

	preamble := b.Bytes()

	// Pad preamble to minimum length with random printable ASCII noise.
	// In practice this rarely fires (even the shortest real preamble exceeds
	// MinPreambleLen=200), but uniform spaces would be DPI-detectable if the
	// preamble generator were ever changed to produce shorter output.
	for len(preamble) < MinPreambleLen {
		// Random ASCII: 0x20-0x7E (printable, like HTTP header noise)
		noise := byte(0x20)
		n, err := rand.Int(rand.Reader, big.NewInt(95)) // 95 printable chars
		if err == nil {
			noise = 0x20 + byte(n.Int64())
		}
		b.WriteByte(noise)
		preamble = b.Bytes()
	}

	// Cap at max length
	if len(preamble) > MaxPreambleLen {
		preamble = preamble[:MaxPreambleLen]
	}

	return preamble
}

// ============================================================================
// Encode / Decode
// ============================================================================

// Encode serializes the auth frame for transmission.
func (f *NyxAuthFrame) Encode() ([]byte, error) {
	if len(f.ShortID) != 8 {
		return nil, fmt.Errorf("shortId must be 8 bytes, got %d", len(f.ShortID))
	}
	if len(f.ClientECDHPk) != 32 {
		return nil, fmt.Errorf("ECDH pubkey must be 32 bytes, got %d", len(f.ClientECDHPk))
	}
	if len(f.HTTPPreamble) < MinPreambleLen {
		return nil, fmt.Errorf("preamble too short: %d < %d", len(f.HTTPPreamble), MinPreambleLen)
	}

	buf := &bytes.Buffer{}

	// 1. HTTP preamble — FIRST on wire (guarantees first byte = 'G' from "GET",
	//    a printable ASCII char, satisfying GFW SET-bit exemption).
	buf.Write(f.HTTPPreamble)

	// 2. Random padding AFTER preamble (0-MaxPadLen bytes).
	//    Placed here so it never contaminates the critical first byte.
	padLen := randIntRange(MinPadLen, MaxPadLen)
	pad := make([]byte, padLen)
	if padLen > 0 {
		if _, err := io.ReadFull(rand.Reader, pad); err != nil {
			return nil, fmt.Errorf("generate pad: %w", err)
		}
		buf.Write(pad)
	}

	// 3. Marker "NYXK" (4 bytes) — in clear, buried after preamble+pad
	buf.WriteString(Marker)

	// 4. Auth body: version + shortID + preambleLen + timestamp + pubkey
	body := make([]byte, AuthBodyLen-HMacLen)
	body[0] = ProtocolVersion
	copy(body[1:9], f.ShortID)
	binary.BigEndian.PutUint16(body[9:11], f.PreambleLen)
	binary.BigEndian.PutUint64(body[11:19], f.Timestamp)
	copy(body[19:51], f.ClientECDHPk)
	buf.Write(body)

	// 5. HMAC-SHA256 over (body), keyed by HKDF(shortID, SaltAuthHMAC)
	hmacKey, err := deriveHKDF(f.ShortID, SaltAuthHMAC, 32)
	if err != nil {
		return nil, err
	}
	h := hmac.New(sha256.New, hmacKey)
	h.Write(body)
	buf.Write(h.Sum(nil))

	return buf.Bytes(), nil
}

// DecodeAuthFrame parses and authenticates an incoming auth frame.
// Wire format (v2.4): [HTTP_preamble:200-512B] [pad:0-64B] [Marker:4B] [auth_body:81B]
// Returns the parsed frame and the total consumed bytes (index after auth body).
func DecodeAuthFrame(data []byte) (*NyxAuthFrame, int, error) {
	minLen := MinPreambleLen + len(Marker) + AuthBodyLen // preamble(min) + marker + auth body
	if len(data) < minLen {
		return nil, 0, fmt.Errorf("%w: %d < %d", ErrAuthTooShort, len(data), minLen)
	}

	// Search for marker AFTER the minimum preamble.
	// With preamble first, marker can be at offset [MinPreambleLen, MaxPreambleLen+MaxPadLen].
	// Marker cannot appear in the HTTP preamble (no HTTP header/value contains "NYXK").
	searchStart := MinPreambleLen
	searchEnd := MaxPreambleLen + MaxPadLen + len(Marker)
	if searchEnd > len(data) {
		searchEnd = len(data)
	}

	markerIdx := bytes.Index(data[searchStart:searchEnd], []byte(Marker))
	if markerIdx < 0 {
		return nil, 0, ErrMarkerNotFound
	}
	markerIdx += searchStart

	// markerIdx is the total preamble+pad length. Validate it's in range.
	// Min: MinPreambleLen (200). Max: MaxPreambleLen + MaxPadLen (768+64=832).
	if markerIdx < MinPreambleLen || markerIdx > MaxPreambleLen+MaxPadLen {
		return nil, 0, fmt.Errorf("preamble+pad len %d out of range [%d,%d]",
			markerIdx, MinPreambleLen, MaxPreambleLen+MaxPadLen)
	}

	bodyStart := markerIdx + len(Marker)
	bodyEnd := bodyStart + AuthBodyLen
	if bodyEnd > len(data) {
		return nil, 0, fmt.Errorf("incomplete auth body: need %d bytes from offset %d, only %d available",
			AuthBodyLen, bodyStart, len(data)-bodyStart)
	}

	body := data[bodyStart : bodyStart+AuthBodyLen-HMacLen]
	providedHMAC := data[bodyStart+AuthBodyLen-HMacLen : bodyEnd]

	// Parse version — MUST exactly match ProtocolVersion (0x02).
	// A future v3 client with changed auth frame layout would have a different
	// AuthBodyLen/field structure. Accepting version > ProtocolVersion risks
	// misinterpreting the wire format — the HMAC would fail, but the error
	// would be misdiagnosed as "bad HMAC" instead of "unsupported version".
	// Version negotiation belongs in the auth response, not in blind acceptance.
	version := body[0]
	if version != ProtocolVersion {
		return nil, 0, fmt.Errorf("%w: got %d (require %d)", ErrAuthVersion, version, ProtocolVersion)
	}

	// Extract fields
	shortID := make([]byte, 8)
	copy(shortID, body[1:9])

	preambleLen := binary.BigEndian.Uint16(body[9:11])

	timestamp := binary.BigEndian.Uint64(body[11:19])

	clientPub := make([]byte, 32)
	copy(clientPub, body[19:51])

	// Validate preamble length against constants
	if int(preambleLen) < MinPreambleLen || int(preambleLen) > MaxPreambleLen {
		return nil, 0, fmt.Errorf("preamble length %d out of range [%d,%d]",
			preambleLen, MinPreambleLen, MaxPreambleLen)
	}

	// Validate pad length: reconstruct from marker position and preamble length
	padLen := markerIdx - int(preambleLen)
	if padLen < MinPadLen || padLen > MaxPadLen {
		return nil, 0, fmt.Errorf("pad length %d out of range [%d,%d] (marker at %d, preamble %d)",
			padLen, MinPadLen, MaxPadLen, markerIdx, preambleLen)
	}

	// Verify HMAC: HKDF(shortID, "auth-hmac") → key, HMAC-SHA256(body)
	hmacKey, err := deriveHKDF(shortID, SaltAuthHMAC, 32)
	if err != nil {
		return nil, 0, err
	}
	h := hmac.New(sha256.New, hmacKey)
	h.Write(body)
	expectedHMAC := h.Sum(nil)

	if !hmac.Equal(expectedHMAC, providedHMAC) {
		return nil, 0, ErrAuthHMAC
	}

	// Anti-replay: check timestamp
	now := uint64(time.Now().Unix())
	skew := int64(now) - int64(timestamp)
	if skew < 0 {
		skew = -skew
	}
	if skew > MaxTimeSkew {
		return nil, 0, fmt.Errorf("%w: %ds (max %ds)", ErrTimeSkew, skew, MaxTimeSkew)
	}

	frame := &NyxAuthFrame{
		HTTPPreamble: data[:markerIdx], // preamble + random pad (PreambleLen gives exact split)
		PreambleLen:  preambleLen,
		ShortID:      shortID,
		Timestamp:    timestamp,
		ClientECDHPk: clientPub,
	}

	return frame, bodyEnd, nil
}

// ============================================================================
// Auth Response — Server → Client (v2: encrypted)
// ============================================================================

type NyxAuthResponse struct {
	Status       byte
}

// EncodeAuthResponse encrypts and encodes the auth response.
//
// Wire format (exactly 74 bytes):
//   nonce(24) || server_pubkey_cleartext(32) || XChaCha20-Poly1305{version(1)||status(1)}
//
// No random padding is added — the response is only sent once per connection and
// is hidden inside the TLS 1.3 stream (which has its own record-level padding).
// Padding here would also leak into the next Nyx frame read if the client's
// io.ReadAtLeast doesn't consume all bytes, causing AEAD decryption failures.
//
// Server pubkey is sent in cleartext so the client can derive keys before decrypting.
func EncodeAuthResponse(serverSendKey []byte, status byte, serverPub []byte) ([]byte, error) {
	// Build plaintext: version(1) + status(1)
	plain := make([]byte, 1+1)
	plain[0] = ProtocolVersion
	plain[1] = status

	// Encrypt with XChaCha20-Poly1305
	aead, err := newXChaChaAEAD(serverSendKey)
	if err != nil {
		return nil, err
	}

	// Generate random 24-byte nonce, prepend to ciphertext
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, plain, nil)

	// Wire format: nonce(24) + server_pubkey(32) + ciphertext(18)
	result := make([]byte, len(nonce)+len(serverPub)+len(ciphertext))
	copy(result, nonce)
	copy(result[len(nonce):], serverPub)
	copy(result[len(nonce)+len(serverPub):], ciphertext)

	return result, nil
}

// DecodeAuthResponse decrypts and decodes the auth response.
//
// Wire format of the full server response (exactly 74 bytes):
//
//	nonce(24) || server_pubkey_cleartext(32) || XChaCha20-Poly1305{version(1)||status(1)}
//
// The caller MUST:
//  1. Extract server_pubkey from bytes 24–55 of the full response (ParseServerPubkey).
//  2. Derive serverSendKey via ECDH(sharedSecret, "nyx-v2-server-send").
//  3. Extract nonce from bytes 0–23.
//  4. Extract ciphertext from bytes 56–73 (exactly 18 bytes).
//  5. Call this function with (serverSendKey, nonce, ciphertext).
//
// The server_pubkey is sent in cleartext to avoid the cryptographic deadlock
// where the client would need the key to decrypt the response that contains
// the key needed to derive that key.
func DecodeAuthResponse(serverSendKey, nonce, ciphertext []byte) (*NyxAuthResponse, error) {
	aead, err := newXChaChaAEAD(serverSendKey)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < 2+aead.Overhead() {
		return nil, fmt.Errorf("ciphertext too short: %d < %d", len(ciphertext), 2+aead.Overhead())
	}

	plain, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt response: %w", err)
	}

	// Forward-compatible version check: accept any version ≥ 2.
	// A v2 client must interoperate with a v3 server that negotiates
	// down to v2 semantics — the version byte in the response confirms
	// the server is at least v2-capable.
	if plain[0] < 0x02 {
		return nil, fmt.Errorf("response version too old: got %d (need >= 2)", plain[0])
	}

	return &NyxAuthResponse{
		Status: plain[1],
	}, nil
}

// ParseServerPubkey extracts the server's ECDH public key from the cleartext
// portion of the auth response (bytes 24-55 of the raw response buffer).
// The caller must validate the buffer length before calling.
func ParseServerPubkey(rawResponse []byte) ([]byte, error) {
	const (
		nonceSize = 24
		pubkeySize = 32
	)
	if len(rawResponse) < nonceSize+pubkeySize {
		return nil, fmt.Errorf("response too short for pubkey: %d", len(rawResponse))
	}
	return rawResponse[nonceSize : nonceSize+pubkeySize], nil
}

// ============================================================================
// Key derivation — X25519 ECDH → bidirectional session keys
// ============================================================================

// DeriveBidirectionalKeys derives clientSendKey and serverSendKey from the
// ECDH shared secret. This matches Shadowsocks AEAD-2022's dual-key design.
//   clientSendKey = HKDF(sharedSecret, "nyx-v2-client-send", 32)
//   serverSendKey = HKDF(sharedSecret, "nyx-v2-server-send", 32)
func DeriveBidirectionalKeys(sharedSecret []byte) (clientSendKey, serverSendKey []byte, err error) {
	// Derive a master session key first
	masterKey, err := deriveHKDF(sharedSecret, SaltSession, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("master key: %w", err)
	}

	clientSendKey, err = deriveHKDF(masterKey, SaltClientSend, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("client send key: %w", err)
	}
	serverSendKey, err = deriveHKDF(masterKey, SaltServerSend, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("server send key: %w", err)
	}

	return clientSendKey, serverSendKey, nil
}

// deriveHKDF derives a key using HKDF-SHA256.
func deriveHKDF(secret []byte, salt string, length int) ([]byte, error) {
	kdf := hkdf.New(sha256.New, secret, []byte(salt), nil)
	key := make([]byte, length)
	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, fmt.Errorf("HKDF derivation: %w", err)
	}
	return key, nil
}

// ============================================================================
// X25519 ECDH helpers
// ============================================================================

func NewX25519Keypair() (*ecdh.PrivateKey, []byte, error) {
	curve := ecdh.X25519()
	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate X25519 key: %w", err)
	}
	pubKey := privKey.PublicKey().Bytes()
	return privKey, pubKey, nil
}

func ComputeSharedSecret(privKey *ecdh.PrivateKey, peerPubKey []byte) ([]byte, error) {
	curve := ecdh.X25519()
	peerPub, err := curve.NewPublicKey(peerPubKey)
	if err != nil {
		return nil, fmt.Errorf("parse peer public key: %w", err)
	}
	sharedSecret, err := privKey.ECDH(peerPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH computation: %w", err)
	}
	return sharedSecret, nil
}

// ============================================================================
// Utility
// ============================================================================

// HMacLen is the size of HMAC-SHA256 output.
const HMacLen = 32
