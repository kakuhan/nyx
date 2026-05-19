// Package clientapp provides a reusable Nyx client entry point.
// Both cmd/client (CLI) and cmd/apk (Android) use this.
package clientapp

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"nyx/internal/mux"
	"nyx/internal/protocol"
	"nyx/internal/socks5"
	nyxtls "nyx/internal/tls"
)

// Config is the client configuration.
type Config struct {
	Server       string `json:"server"`
	ShortID      string `json:"short_id"`
	TargetDomain string `json:"target_domain"`
	Socks5Listen string `json:"socks5_listen"`
	IdleTimeout  int    `json:"idle_timeout"`
}

// Run starts the Nyx client with the given config file path.
// Returns when the SOCKS5 proxy shuts down.
func Run(configPath string) error {
	log.SetFlags(log.Ltime | log.Lshortfile)
	log.Printf("=== Nyx Client v2.4 ===")

	cfg := loadConfig(configPath)

	s := &session{
		serverAddr:  cfg.Server,
		targetSNI:   cfg.TargetDomain,
		idleTimeout: time.Duration(cfg.IdleTimeout) * time.Second,
	}
	if s.idleTimeout <= 0 {
		s.idleTimeout = 300 * time.Second
	}

	var err error
	s.shortID, err = hex.DecodeString(cfg.ShortID)
	if err != nil || len(s.shortID) != 8 {
		return fmt.Errorf("invalid short_id: %v (needs 16 hex chars = 8 bytes)", err)
	}

	proxy := socks5.NewServer(cfg.Socks5Listen, s.dialNyx)
	activeServer = proxy

	log.Printf("Nyx client @ %s → %s (SNI: %s)", cfg.Socks5Listen, s.serverAddr, s.targetSNI)
	if err := proxy.Run(); err != nil {
		return fmt.Errorf("socks5 server: %w", err)
	}
	log.Println("Nyx client stopped.")
	return nil
}

// activeServer is the currently running SOCKS5 server.
// Set by Run/after RunWithConfig; used by Shutdown() for graceful shutdown.
var activeServer *socks5.Server

// Shutdown gracefully stops the running Nyx client by closing the SOCKS5 listener.
// Safe to call from any goroutine. After Shutdown returns, Run() will return nil.
// Idempotent — calling Shutdown() multiple times is safe.
func Shutdown() {
	if activeServer != nil {
		activeServer.Shutdown()
	}
}

// RunWithConfig starts the Nyx client with a given Config struct directly.
func RunWithConfig(cfg Config) error {
	log.SetFlags(log.Ltime | log.Lshortfile)
	log.Printf("=== Nyx Client v2.4 ===")

	s := &session{
		serverAddr:  cfg.Server,
		targetSNI:   cfg.TargetDomain,
		idleTimeout: time.Duration(cfg.IdleTimeout) * time.Second,
	}
	if s.idleTimeout <= 0 {
		s.idleTimeout = 300 * time.Second
	}

	if cfg.Socks5Listen == "" {
		cfg.Socks5Listen = "127.0.0.1:1080"
	}

	var err error
	s.shortID, err = hex.DecodeString(cfg.ShortID)
	if err != nil || len(s.shortID) != 8 {
		return fmt.Errorf("invalid short_id: %v (needs 16 hex chars = 8 bytes)", err)
	}

	activeServer = socks5.NewServer(cfg.Socks5Listen, s.dialNyx)

	log.Printf("Nyx client @ %s → %s (SNI: %s)", cfg.Socks5Listen, s.serverAddr, s.targetSNI)
	return activeServer.Run()
}

type session struct {
	serverAddr  string
	targetSNI   string
	shortID     []byte
	idleTimeout time.Duration
	pool        *mux.Pool // connection pool with yamux multiplexing
}

func (s *session) dialNyx(targetAddr string) (net.Conn, error) {
	// Lazy-init the connection pool on first dial.
	if s.pool == nil {
		s.pool = mux.NewPool(s.dialNyxAuth, 4)
	}
	return s.pool.DialStream(targetAddr)
}

// dialNyxAuth creates a new authenticated Nyx connection (TLS + auth handshake).
// Used by the mux.Pool as its DialFunc. Each connection is a TLS tunnel
// carrying multiple streams via yamux.
func (s *session) dialNyxAuth() (net.Conn, error) {
	clientPriv, clientPub, err := protocol.NewX25519Keypair()
	if err != nil {
		return nil, fmt.Errorf("keygen: %w", err)
	}

	log.Printf("[debug] dialing TLS to %s (SNI: %s)...", s.serverAddr, s.targetSNI)

	var rawConn net.Conn
	for attempt := 0; attempt < 3; attempt++ {
		rawConn, err = nyxtls.DialTLS("tcp", s.serverAddr, s.targetSNI)
		if err == nil {
			break
		}
		log.Printf("[debug] TLS attempt %d failed: %v", attempt+1, err)
		if attempt < 2 {
			time.Sleep(time.Duration(50*(attempt+1)) * time.Millisecond)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	log.Printf("[debug] TLS handshake OK, remote=%s", rawConn.RemoteAddr())

	rawConn.SetDeadline(time.Now().Add(30 * time.Second))

	preamble := protocol.GenerateHTTPPreamble(s.targetSNI)
	authFrame := &protocol.NyxAuthFrame{
		HTTPPreamble: preamble,
		PreambleLen:  uint16(len(preamble)),
		ShortID:      s.shortID,
		Timestamp:    uint64(time.Now().Unix()),
		ClientECDHPk: clientPub,
	}

	authBytes, err := authFrame.Encode()
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("encode auth: %w", err)
	}
	log.Printf("[debug] auth frame encoded: %d bytes (preamble=%d, pad=%d, marker+body=%d)",
		len(authBytes), len(preamble), len(authBytes)-len(preamble)-4-83, 4+83)

	if _, err := rawConn.Write(authBytes); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("send auth: %w", err)
	}
	log.Printf("[debug] auth frame sent, waiting for response...")

	respBuf, err := readAuthResponse(rawConn)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("read response: %w", err)
	}

	serverPub, err := protocol.ParseServerPubkey(respBuf)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("parse server pubkey: %w", err)
	}

	sharedSecret, err := protocol.ComputeSharedSecret(clientPriv, serverPub)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("ECDH: %w", err)
	}

	clientSendKey, serverSendKey, err := protocol.DeriveBidirectionalKeys(sharedSecret)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("derive keys: %w", err)
	}

	resp, err := protocol.DecodeAuthResponse(serverSendKey, respBuf[:24], respBuf[56:56+protocol.AuthRespCiphertextLen])
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if resp.Status != protocol.StatusSuccess {
		rawConn.Close()
		return nil, fmt.Errorf("auth rejected (status=%02x)", resp.Status)
	}

	idleConn := &deadlineConn{Conn: rawConn, timeout: s.idleTimeout}
	nyxConn, err := protocol.NewNyxConn(idleConn, clientSendKey, serverSendKey)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("nyx wrap: %w", err)
	}

	rawConn.SetDeadline(time.Time{})
	log.Printf("[nyx] tunnel established → %s (mux session)", s.serverAddr)

	// Start bidirectional heartbeat — prevents GFW from detecting
	// the connection as idle (server already sends heartbeats, client
	// must also send to maintain bidirectional flow).
	go nyxConn.StartHeartbeat(protocol.RandomHeartbeatInterval())

	return nyxConn, nil
}

func readAuthResponse(conn net.Conn) ([]byte, error) {
	buf := make([]byte, protocol.AuthResponseMinLen)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, fmt.Errorf("read auth response: %w", err)
	}
	return buf, nil
}

func loadConfig(path string) *Config {
	cfg := &Config{
		Server:       "your-server.com:443",
		ShortID:      "a1b2c3d4e5f6a7b8",
		TargetDomain: "www.bilibili.com",
		Socks5Listen: "127.0.0.1:1080",
	}

	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("Config not found, using defaults: %v", err)
		return cfg
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		log.Printf("Config parse error: %v", err)
	}
	return cfg
}

type deadlineConn struct {
	net.Conn
	timeout time.Duration
}

func (c *deadlineConn) Read(b []byte) (int, error) {
	c.Conn.SetReadDeadline(time.Now().Add(c.timeout))
	return c.Conn.Read(b)
}

func (c *deadlineConn) Write(b []byte) (int, error) {
	c.Conn.SetWriteDeadline(time.Now().Add(c.timeout))
	return c.Conn.Write(b)
}
