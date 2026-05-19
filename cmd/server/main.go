// Nyx Server v2.4 — Anti-censorship tunnel server
//
// v2.4 fixes:
//   - Heartbeat started AFTER tunnel fully established (was before target dial)
//   - Graceful shutdown via SIGINT/SIGTERM with connection drain
//   - Graceful shutdown FIXED: signal handler moved to goroutine (was deadlock: select-in-loop couldn't read from sigCh while blocked in Accept())
//   - Max concurrent connections semaphore (configurable, default 256)
//   - ReplaySeen map max entry guard (100k limit, prevent memory exhaustion)
//   - readAuthFrameStream chunk buffer reuse (was per-iteration alloc)
//
// v2.3 fixes:
//   - CRITICAL: Rate limiter moved to post-auth-failure (was DoS-vulnerable pre-auth)
//   - Rate limit window decoupled from ReplayWindow (now separate rate_limit_window config)
//   - SOCKS5 io.ReadFull error handling
//   - Removed dead code (WriteExactFrame, SaltResponseHMAC)
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"nyx/internal/mux"
	"nyx/internal/protocol"
	"nyx/internal/reality"
)

// Config is the server configuration.
type Config struct {
	Listen            string   `json:"listen"`
	ShortIDs          []string `json:"short_ids"`
	TargetDomain      string   `json:"target_domain"`
	TargetAddr        string   `json:"target_addr"`
	CertPath          string   `json:"cert_path"`
	KeyPath           string   `json:"key_path"`
	MaxConnsPerWindow int `json:"max_conns_per_window"`
	RateLimitWindow   int `json:"rate_limit_window"`  // seconds, default 30
	ReplayWindow      int `json:"replay_window"`
	IdleTimeout       int `json:"idle_timeout"`       // seconds, 0 = no timeout
	MaxConcurrentConns int `json:"max_concurrent_conns"` // 0 = unlimited
}

// ipWindow tracks per-IP connection timestamps for sliding-window rate limiting.
type ipWindow struct {
	timestamps []time.Time
}

// rateLimiter is a per-IP sliding window rate limiter for failed auth attempts.
type rateLimiter struct {
	mu      sync.Mutex
	windows map[string]*ipWindow
	window  time.Duration
	max     int
}

// RecordAndCheck records a failed auth attempt for the given IP and returns
// false if the IP has exceeded the rate limit within the current window.
func (r *rateLimiter) RecordAndCheck(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	w, ok := r.windows[ip]
	if !ok {
		w = &ipWindow{}
		r.windows[ip] = w
	}

	// Prune expired timestamps
	cutoff := now.Add(-r.window)
	valid := w.timestamps[:0]
	for _, ts := range w.timestamps {
		if ts.After(cutoff) {
			valid = append(valid, ts)
		}
	}
	w.timestamps = valid

	// Check if at limit
	if len(w.timestamps) >= r.max {
		return false
	}

	w.timestamps = append(w.timestamps, now)
	return true
}

func main() {
	log.SetFlags(log.Ltime | log.Lshortfile)

	// Parse flags
	configPath := flag.String("config", "nyx-server.json", "path to config file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("Nyx Server v2.4")
		os.Exit(0)
	}

	log.Printf("=== Nyx Server v2.4 ===")

	var connCounter uint64 // atomic connection ID counter

	cfg := loadConfig(*configPath)

	shortIDs := make(map[string]bool)
	for _, s := range cfg.ShortIDs {
		shortIDs[strings.ToLower(s)] = true
	}
	log.Printf("Loaded %d short IDs", len(shortIDs))

	// TLS certificate
	cert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
	if err != nil {
		log.Printf("Loading cert failed: %v, fetching from target...", err)
		certPEM, keyPEM, err := reality.FetchCert(cfg.TargetDomain)
		if err != nil {
			log.Printf("Fetch cert failed: %v, using self-signed", err)
			certPEM, keyPEM, _ = reality.GenSelfSigned(cfg.TargetDomain)
		}
		reality.SaveCert(cfg.CertPath, cfg.KeyPath, certPEM, keyPEM)
		cert, err = tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			log.Printf("X509KeyPair failed: %v, regenerating self-signed", err)
			certPEM, keyPEM, err = reality.GenSelfSigned(cfg.TargetDomain)
			if err != nil {
				log.Fatalf("self-signed cert gen failed: %v", err)
			}
			reality.SaveCert(cfg.CertPath, cfg.KeyPath, certPEM, keyPEM)
			cert, err = tls.X509KeyPair(certPEM, keyPEM)
			if err != nil {
				log.Fatalf("X509KeyPair retry failed: %v", err)
			}
		}
	}
	// R-fix: tls.LoadX509KeyPair never populates cert.Leaf in Go 1.15+.
	// Parse the first certificate in the chain so the auto-refresh goroutine
	// can check expiry via cert.Leaf.NotAfter.
	if cert.Leaf == nil {
		for _, der := range cert.Certificate {
			if cert.Leaf, err = x509.ParseCertificate(der); err == nil {
				break
			}
		}
		if cert.Leaf == nil {
			log.Printf("WARNING: could not parse certificate — auto-refresh will not work")
		}
	}

	tlsCfg := &tls.Config{
		Certificates:           []tls.Certificate{cert},
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		NextProtos:             []string{"http/1.1"}, // ALPN — only http/1.1 to match Nyx auth frame payload (h2 removed — server can't parse HTTP/2 DATA frames)
		SessionTicketsDisabled: false,                // TLS 1.3 PSK resumption (reduces handshake overhead on reconnect)
		// R18-fix: Removed SNI rejection (GetConfigForClient returning error).
		//
		// Previous behavior: TLS handshake was ABORTED for SNI ≠ target_domain.
		// This created a TLS-level fingerprint — a GFW probe sending SNI=google.com
		// would receive a TLS alert, not a ServerHello with bilibili cert. A real
		// HTTPS server always serves its cert regardless of SNI.
		//
		// New behavior: TLS handshake always completes normally with the configured
		// certificate. Application-layer auth/fail determines whether the connection
		// gets a Nyx tunnel or transparent fallback. Every connection path now
		// produces application-data traffic, eliminating the TLS-layer anomaly.
		//
		// This is consistent with how Hysteria2, Reality, and real HTTPS servers
		// handle unknown SNI: serve the default cert, complete the handshake, let
		// the application decide.
	}

	// Periodic cert expiry check — self-signed certs expire after 1 year.
	// Auto-refresh when within 30 days of expiry and save to disk for next restart.
	// (Hot-reload requires listener restart; this at least prevents hard expiry.)
	go func() {
		for {
			time.Sleep(24 * time.Hour)
			if cert.Leaf == nil {
				continue
			}
			remaining := time.Until(cert.Leaf.NotAfter)
			if remaining > 30*24*time.Hour {
				continue
			}
			log.Printf("Cert expires in %v, refreshing...", remaining.Round(time.Hour))
			certPEM, keyPEM, err := reality.FetchCert(cfg.TargetDomain)
			if err != nil {
				log.Printf("Cert refresh failed (will retry): %v", err)
				continue
			}
			if err := reality.SaveCert(cfg.CertPath, cfg.KeyPath, certPEM, keyPEM); err != nil {
				log.Printf("Cert save failed: %v", err)
				continue
			}
			log.Printf("Cert refreshed and saved to %s/%s. Restart required to use new cert.",
				cfg.CertPath, cfg.KeyPath)
		}
	}()

	ln, err := tls.Listen("tcp", cfg.Listen, tlsCfg)
	if err != nil {
		log.Fatalf("Listen %s: %v", cfg.Listen, err)
	}
	defer ln.Close()
	log.Printf("Nyx server listening on %s (camouflage: %s)", cfg.Listen, cfg.TargetDomain)

	// Anti-replay cache
	replaySeen := make(map[string]time.Time)
	var replayMu sync.Mutex

	// Stop channel for cleanup goroutines (replay + rate limiter).
	// Closed when the accept loop exits to stop the periodic cleanup.
	cleanupDone := make(chan struct{})

	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-cleanupDone:
				return
			case <-ticker.C:
				replayMu.Lock()
				cutoff := time.Now().Add(-2 * time.Duration(cfg.ReplayWindow) * time.Second)
				for k, t := range replaySeen {
					if t.Before(cutoff) {
						delete(replaySeen, k)
					}
				}
				replayMu.Unlock()
			}
		}
	}()

	// ============================================================================
	// Auth-failure rate limiter — only counts FAILED authentication attempts.
	// Legitimate clients never hit the limit. Only attackers probing credentials
	// or replaying auth frames are rate-limited. This prevents the DoS vulnerability
	// of pre-auth rate limiting (where an attacker can exhaust the limit with
	// garbage TLS connections before authentication even begins).
	// ============================================================================

	limiter := &rateLimiter{
		windows: make(map[string]*ipWindow),
		window:  time.Duration(cfg.RateLimitWindow) * time.Second,
		max:     cfg.MaxConnsPerWindow,
	}

	// Periodic cleanup goroutine — prevents unbounded map growth.
	// Stops when cleanupDone is closed (accept loop exits).
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-cleanupDone:
				return
			case <-ticker.C:
				limiter.mu.Lock()
				cutoff := time.Now().Add(-limiter.window)
				for ip, w := range limiter.windows {
					valid := w.timestamps[:0]
					for _, ts := range w.timestamps {
						if ts.After(cutoff) {
							valid = append(valid, ts)
						}
					}
					w.timestamps = valid
					if len(valid) == 0 {
						delete(limiter.windows, ip)
					}
				}
				limiter.mu.Unlock()
			}
		}
	}()

	// Signal handling for graceful shutdown — MUST be in a goroutine, NOT a
	// non-blocking select inside the accept loop. If the main goroutine is
	// blocked in Accept(), it cannot read from sigCh, and the signal is never
	// processed. A separate goroutine reads the signal and closes the listener,
	// which causes Accept() to return net.ErrClosed.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("Received %v, shutting down gracefully...", sig)
		ln.Close()
	}()

	// Max concurrent connections semaphore (nil when 0 = unlimited).
	// Uses a WaitGroup for drain tracking — the semaphore ONLY limits
	// concurrency. WaitGroup counts every active handler goroutine and
	// is the authoritative drain mechanism, fixing the bug where
	// MaxConcurrentConns=0 (unlimited) bypassed the drain entirely.
	var maxConns chan struct{}
	if cfg.MaxConcurrentConns > 0 {
		maxConns = make(chan struct{}, cfg.MaxConcurrentConns)
	}

	var activeWg sync.WaitGroup

	for {
		conn, err := ln.Accept()
		if err != nil {
			// Listener closed (graceful shutdown) — exit the loop
			if errors.Is(err, net.ErrClosed) {
				break
			}
			log.Printf("accept: %v", err)
			continue
		}

		// Acquire semaphore (blocks if at max capacity)
		if maxConns != nil {
			maxConns <- struct{}{}
		}

		activeWg.Add(1)
		id := atomic.AddUint64(&connCounter, 1)
		go func() {
			defer activeWg.Done()
			if maxConns != nil {
				defer func() { <-maxConns }()
			}
			defer recoverPanic(id, "handleConnection")
			handleConnection(id, conn, cfg, shortIDs, &replaySeen, &replayMu, limiter)
		}()
	}

	log.Println("Stopping cleanup goroutines and draining active connections...")
	close(cleanupDone)
	activeWg.Wait()
	log.Println("All connections drained. Nyx server stopped.")
}

// ============================================================================
// Panic recovery — prevents a single relay goroutine crash from taking down
// the entire server. All relay goroutines (server side + SOCKS5) MUST use this.
// ============================================================================

func recoverPanic(id uint64, label string) {
	if r := recover(); r != nil {
		log.Printf("[#%d] [PANIC] %s recovered: %v", id, label, r)
	}
}

func handleConnection(id uint64, raw net.Conn, cfg *Config, shortIDs map[string]bool,
	replaySeen *map[string]time.Time, replayMu *sync.Mutex, limiter *rateLimiter) {

	conn := raw

	ip, _, _ := net.SplitHostPort(raw.RemoteAddr().String())

	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// 1. Read auth frame
	authFrame, rawBuf, bodyEnd, err := readAuthFrameStream(conn)
	if err != nil {
		log.Printf("[#%d] auth read: %v", id, err)
		if !limiter.RecordAndCheck(ip) {
			log.Printf("[#%d] [rate-limit] rejected %s after auth failure", id, ip)
		} else if len(rawBuf) > 0 {
			// R17-fix: ALL auth failures with readable data go through transparent fallback.
			// Previously only ErrMarkerNotFound/ErrAuthTooShort were forwarded — HMAC failures,
			// version mismatches, and timestamp errors closed immediately, creating a distinguishable
			// timing fingerprint. GFW could reverse-engineer the protocol format and send a
			// syntactically valid auth frame to trigger an immediate close, distinguishing Nyx
			// from a genuine bilibili server.
			// Now ALL data-bearing failed connections are forwarded to the target as-is.
			// The preamble (first 200-768 bytes, always starting with "GET") is extracted and
			// relayed; the authentic bilibili server determines the response — indistinguishable.
			handleTransparentFallback(conn, rawBuf, cfg.TargetDomain, cfg.TargetAddr)
		}
		conn.Close()
		return
	}

	// 2. Validate shortID
	shortIDHex := hex.EncodeToString(authFrame.ShortID)
	if !shortIDs[shortIDHex] {
		log.Printf("[#%d] unknown shortId: %s", id, shortIDHex[:16])
		if !limiter.RecordAndCheck(ip) {
			log.Printf("[#%d] [rate-limit] rejected %s after unknown shortID", id, ip)
		}
		// R17-fix: unknown shortID gets transparent fallback like all other auth failures.
		// While "tunnel established vs not" is inherently distinguishable (every circumvention
		// protocol must distinguish authorized users), ALL failure paths now produce identical
		// external behavior — forwarding to the real target.
		// This prevents timing-based probing of the shortID namespace.
		handleTransparentFallback(conn, rawBuf, cfg.TargetDomain, cfg.TargetAddr)
		conn.Close()
		return
	}

	// 3. Anti-replay: (shortID, full_clientPub, timestamp) dedup.
	//    clientPub (32B X25519) is unique per connection (fresh X25519 each time),
	//    so legitimate concurrent connections in the same second never collide.
	//    Using the full 32-byte key eliminates birthday-bound collisions that the
	//    previous 4-byte truncation could cause at scale (~60 collisions per 1M conns).
	//    An actual replay attack sends the SAME frame → same clientPub → same key → blocked.
	//    Combined with the ReplayWindow timestamp validation in the protocol layer,
	//    an attacker can try at most ~1 auth attempt per second per shortID.
	replayKey := fmt.Sprintf("%s:%x:%d", shortIDHex, authFrame.ClientECDHPk, authFrame.Timestamp)
	replayMu.Lock()
	// Guard against memory exhaustion: refuse if cache exceeds 100k entries
	const maxReplayEntries = 100000
	if len(*replaySeen) >= maxReplayEntries {
		replayMu.Unlock()
		log.Printf("[#%d] replay cache full (%d entries), refusing connection", id, len(*replaySeen))
		limiter.RecordAndCheck(ip)
		handleTransparentFallback(conn, rawBuf, cfg.TargetDomain, cfg.TargetAddr)
		conn.Close()
		return
	}
	if _, exists := (*replaySeen)[replayKey]; exists {
		replayMu.Unlock()
		log.Printf("[#%d] replay detected: %s", id, replayKey)
		// Count this as an auth failure — legitimate replays should never occur
		limiter.RecordAndCheck(ip)
		handleTransparentFallback(conn, rawBuf, cfg.TargetDomain, cfg.TargetAddr)
		conn.Close()
		return
	}
	(*replaySeen)[replayKey] = time.Now()
	replayMu.Unlock()

	// 4. ECDH key exchange
	serverPriv, serverPub, err := protocol.NewX25519Keypair()
	if err != nil {
		log.Printf("[#%d] keygen: %v", id, err)
		handleTransparentFallback(conn, rawBuf, cfg.TargetDomain, cfg.TargetAddr)
		conn.Close()
		return
	}

	sharedSecret, err := protocol.ComputeSharedSecret(serverPriv, authFrame.ClientECDHPk)
	if err != nil {
		log.Printf("[#%d] ECDH: %v", id, err)
		handleTransparentFallback(conn, rawBuf, cfg.TargetDomain, cfg.TargetAddr)
		conn.Close()
		return
	}

	// 5. Derive bidirectional keys
	clientSendKey, serverSendKey, err := protocol.DeriveBidirectionalKeys(sharedSecret)
	if err != nil {
		log.Printf("[#%d] key derivation: %v", id, err)
		handleTransparentFallback(conn, rawBuf, cfg.TargetDomain, cfg.TargetAddr)
		conn.Close()
		return
	}

	// 6. Send auth response
	respBytes, err := protocol.EncodeAuthResponse(serverSendKey, protocol.StatusSuccess, serverPub)
	if err != nil {
		log.Printf("[#%d] encode response: %v", id, err)
		conn.Close()
		return
	}
	if _, err := conn.Write(respBytes); err != nil {
		log.Printf("[#%d] write response: %v", id, err)
		conn.Close()
		return
	}

	conn.SetDeadline(time.Time{})

	// Wrap with idle timeout — resets read deadline on every read.
	// Dead connections are automatically reclaimed after IdleTimeout.
	idleConn := &deadlineConn{Conn: conn, timeout: time.Duration(cfg.IdleTimeout) * time.Second}
	defer idleConn.Close() // Ensures cleanup on early return (dial/target-read failure)

	log.Printf("[#%d] [✓] tunnel established for %s", id, shortIDHex[:8])

	// 7. Wrap with Nyx encryption
	nyxConn, err := protocol.NewNyxConn(idleConn, serverSendKey, clientSendKey)
	if err != nil {
		log.Printf("[#%d] nyx wrap: %v", id, err)
		return
	}

	// 7.1 Inject any bytes that arrived after the auth frame.
	//     TLS record coalescing can deliver the auth frame and the first
	//     Nyx-encrypted data frame (yamux SYN) in the same TCP segment.
	//     Without this injection the client's first frame is silently
	//     discarded and the tunnel hangs.
	if bodyEnd < len(rawBuf) {
		leftover := make([]byte, len(rawBuf[bodyEnd:]))
		copy(leftover, rawBuf[bodyEnd:])
		nyxConn.SetReadBuffer(leftover)
	}

	// 7.2 Start Nyx-level heartbeat (server→client direction dead-air
	//     prevention). Complements the client-side heartbeat for full
	//     bidirectional coverage.
	go nyxConn.StartHeartbeat(protocol.RandomHeartbeatInterval())

	// 8. Create yamux session over the encrypted Nyx connection.
	//    Multiple SOCKS5 connections (browser tabs) now share one TLS tunnel.
	//    This mirrors Hysteria2's QUIC stream multiplexing and v2ray's mux.cool.
	session, err := mux.NewServerSession(nyxConn)
	if err != nil {
		log.Printf("[#%d] yamux server: %v", id, err)
		return
	}
	defer session.Close()

	// 9. Accept streams — each stream = one SOCKS5 connection.
	//    Stream format: [target_addr]\n → dial → bidirectional relay.
	if err := mux.AcceptStreams(session, mux.DefaultStreamHandler); err != nil {
		log.Printf("[#%d] accept streams: %v", id, err)
	}
}

// ============================================================================
// Streamed auth frame reader
// ============================================================================

func readAuthFrameStream(conn net.Conn) (frame *protocol.NyxAuthFrame, rawBuf []byte, bodyEnd int, err error) {
	buf := make([]byte, 0, 4096)
	chunk := make([]byte, 1024) // Allocate once, reuse across reads

	for len(buf) < 4096 {
		n, err := conn.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
			frame, bodyEnd, decErr := protocol.DecodeAuthFrame(buf)
			if decErr == nil {
				return frame, buf, bodyEnd, nil
			}
			// ErrMarkerNotFound means we haven't received enough data yet — keep reading
			if !errors.Is(decErr, protocol.ErrMarkerNotFound) {
				return nil, buf, 0, decErr
			}
			// R11-8: prevent garbage accumulation. If the buffer exceeds the
			// maximum possible frame size, trim from the front — any valid
			// frame must fit entirely within the tail.
			maxFrame := protocol.MaxPreambleLen + protocol.MaxPadLen + len(protocol.Marker) + protocol.AuthBodyLen
			if len(buf) > maxFrame {
				buf = buf[len(buf)-maxFrame:]
			}
		}
		if err != nil {
			if len(buf) > 0 {
				frame, bodyEnd, decErr := protocol.DecodeAuthFrame(buf)
				if decErr == nil {
					return frame, buf, bodyEnd, nil
				}
				// If the final decode also returned ErrMarkerNotFound, propagate it
				// so callers can distinguish "no marker found" from other failures.
				if errors.Is(decErr, protocol.ErrMarkerNotFound) {
					return nil, buf, 0, fmt.Errorf("%w after %d bytes: %w", protocol.ErrMarkerNotFound, len(buf), err)
				}
				return nil, buf, 0, fmt.Errorf("incomplete auth frame after %d bytes: %w", len(buf), decErr)
			}
			return nil, nil, 0, err
		}
	}

	return nil, buf, 0, fmt.Errorf("auth frame exceeds 4096 bytes")
}

// ============================================================================
// Transparent fallback proxy — indistinguishable from legitimate HTTPS
// ============================================================================
// On auth failure, extracts the forged HTTP request from the auth frame preamble
// and relays it to the real target website. The client sees a genuine response
// — GFW active probing cannot distinguish Nyx from a legitimate connection.
//
// Wire flow (observer's view):
//   ClientHello(SNI=target) → ServerHello(target_cert) → AppData(HTTP req) → AppData(real HTTP resp)

func handleTransparentFallback(conn net.Conn, rawBuf []byte, targetDomain, targetAddr string) bool {
	if len(rawBuf) == 0 || targetAddr == "" {
		return false
	}

	// Extract the HTTP request from the auth frame preamble.
	// v2.2 wire format: [HTTP_preamble:200-768B] [pad:0-64B] [Marker:4B] [auth_body:81B]
	// HTTP preamble is FIRST on wire — first byte is always printable ASCII ('G' from "GET").
	reqStart, reqEnd := extractHTTPRequest(rawBuf)
	// R17-fix: When no HTTP structure is found (e.g., garbage data, GFW probe),
	// forward the raw data as-is. A real bilibili server would return HTTP 400
	// for garbage — by forwarding unconditionally, Nyx behavior is identical.
	payload := rawBuf
	if reqStart >= 0 && reqEnd >= 0 && reqEnd > reqStart {
		payload = rawBuf[reqStart:reqEnd]
	}

	// If the target is HTTPS (port 443), wrap with TLS
	_, port, err := net.SplitHostPort(targetAddr)
	useTLS := err == nil && port == "443"

	var remote net.Conn
	if useTLS {
		remote, err = tls.DialWithDialer(
			&net.Dialer{Timeout: 10 * time.Second},
			"tcp", targetAddr,
			&tls.Config{
				// Verify the target's TLS certificate against system root CAs.
				// Unlike the Nyx tunnel path (which uses its own auth layer),
				// transparent fallback is forwarding real user HTTP/HTTPS traffic
				// to the target — PKI verification is the correct trust anchor here.
				ServerName: targetDomain,
				MinVersion: tls.VersionTLS12,
			},
		)
	} else {
		remote, err = net.DialTimeout("tcp", targetAddr, 10*time.Second)
	}
	if err != nil {
		return false
	}
	defer remote.Close()

	remote.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := remote.Write(payload); err != nil {
		return false
	}

	// Relay the response back to the client (already TLS-encrypted by the outer TLS session)
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.Copy(conn, remote); err != nil {
		log.Printf("[fallback] relay error: %v", err)
	}
	return true // successfully relayed
}

// extractHTTPRequest finds the HTTP request boundary in the auth frame buffer.
// Returns (start_offset, end_offset) where start is the first byte of the HTTP method
// (e.g., "GET ") and end is the byte after \r\n\r\n (end of HTTP headers).
// Returns (-1, -1) if no valid HTTP request is found.
// v2.2: HTTP preamble is FIRST on wire, so the search starts from position 0.
func extractHTTPRequest(data []byte) (int, int) {
	// Try common HTTP methods in order of likelihood
	methods := [][]byte{
		[]byte("GET "),
		[]byte("POST "),
		[]byte("HEAD "),
		[]byte("PUT "),
	}
	for _, method := range methods {
		start := bytes.Index(data, method)
		if start < 0 {
			continue
		}
		// Find \r\n\r\n after the method — the end of HTTP headers
		rest := data[start:]
		crlfIdx := bytes.Index(rest, []byte("\r\n\r\n"))
		if crlfIdx < 0 {
			return -1, -1
		}
		// +4 to include the \r\n\r\n itself
		return start, start + crlfIdx + 4
	}
	return -1, -1
}

// ============================================================================
// Config
// ============================================================================

func loadConfig(path string) *Config {
	cfg := &Config{
		Listen:            ":443",
		TargetDomain:      "www.bilibili.com",
		TargetAddr:        "www.bilibili.com:443",
		CertPath:          "nyx-cert.pem",
		KeyPath:           "nyx-key.pem",
		MaxConnsPerWindow: 10,
		RateLimitWindow:   30,
		ReplayWindow:      90,
	}

	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("Config file not found, using defaults: %v", err)
		return cfg
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		log.Printf("Config parse error: %v, using defaults", err)
	}

	if cfg.ReplayWindow <= 0 {
		cfg.ReplayWindow = 90
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 300 // 5 minutes
	}
	if cfg.MaxConcurrentConns <= 0 {
		cfg.MaxConcurrentConns = 256 // default: 256 concurrent connections
	}

	// Guard against misconfiguration: if target_addr resolves to the server's
	// own listen address, failed-auth fallback creates an infinite loop.
	// Each failed auth → handleTransparentFallback → dials target_addr →
	// connects back to self → another failed auth → ...
	if cfg.TargetAddr != "" {
		targetHost, _, err := net.SplitHostPort(cfg.TargetAddr)
		if err == nil {
			ips, err := net.LookupIP(targetHost)
			if err == nil {
				for _, ip := range ips {
					if ip.String() == cfg.Listen {
						log.Fatalf("CONFIG ERROR: target_addr (%s) resolves to listen address (%s) — this creates an infinite fallback loop. Fix the target_addr config.",
							cfg.TargetAddr, cfg.Listen)
					}
				}
			}
		}
	}

	return cfg
}

// ============================================================================
// deadlineConn — wraps net.Conn to reset read deadline on every read.
// Prevents dead connections from consuming goroutines indefinitely.
// ============================================================================

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
