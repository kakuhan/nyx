// Package mux provides connection multiplexing for Nyx tunnels.
//
// Each authenticated Nyx connection carries multiple independent streams
// via yamux (HashiCorp). This reduces TLS handshake overhead and DPI
// visibility — similar to Hysteria2's QUIC streams and v2ray's mux.cool.
//
// Architecture:
//   Client: Connection pool → TLS → Nyx auth → yamux session → streams
//   Server: TLS accept → Nyx auth → yamux session → streams → target relay
//
// Each stream carries one SOCKS5 connection: target address + bidirectional data.
package mux

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

// Default config tuned for Nyx's use case:
// - 128 streams per session (plenty for browser tabs)
// - 16MB stream window (good for throughput)
// - KeepAlive keeps DPI-quiet connections alive
func DefaultConfig() *yamux.Config {
	return &yamux.Config{
		AcceptBacklog:          256,
		EnableKeepAlive:        true,
		KeepAliveInterval:      30 * time.Second,
		ConnectionWriteTimeout: 30 * time.Second,
		MaxStreamWindowSize:    16 * 1024 * 1024, // 16 MB
		StreamOpenTimeout:      15 * time.Second,
		StreamCloseTimeout:     5 * time.Minute,
		LogOutput:              io.Discard,
	}
}

// NewServerSession creates a yamux session wrapping an authenticated NyxConn.
// The server accepts streams and handles each as a SOCKS5-like relay.
func NewServerSession(conn net.Conn) (*yamux.Session, error) {
	session, err := yamux.Server(conn, DefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("yamux server: %w", err)
	}
	return session, nil
}

// NewClientSession creates a yamux session over an authenticated NyxConn.
func NewClientSession(conn net.Conn) (*yamux.Session, error) {
	session, err := yamux.Client(conn, DefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("yamux client: %w", err)
	}
	return session, nil
}

// ============================================================================
// Server: accept streams, dial targets, relay
// ============================================================================

// StreamHandler is called for each accepted stream with the target address.
// On the server side, it reads the target address from the stream, dials it,
// and relays data bidirectionally.
type StreamHandler func(stream net.Conn, targetAddr string) error

// DefaultStreamHandler dials the target and relays data.
func DefaultStreamHandler(stream net.Conn, targetAddr string) error {
	remote, err := net.DialTimeout("tcp", targetAddr, 15*time.Second)
	if err != nil {
		log.Printf("[mux] dial target %s: %v", targetAddr, err)
		return err
	}
	defer remote.Close()

	// Bidirectional relay
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer remote.Close()
		io.Copy(remote, stream)
	}()

	go func() {
		defer wg.Done()
		defer stream.Close()
		io.Copy(stream, remote)
	}()

	wg.Wait()
	return nil
}

// AcceptStreams continuously accepts streams from the session and handles them.
// Returns when the session is closed or encounters an error.
func AcceptStreams(session *yamux.Session, handler StreamHandler) error {
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			if err == yamux.ErrSessionShutdown {
				return nil
			}
			return fmt.Errorf("accept stream: %w", err)
		}

		go func(s net.Conn) {
			defer s.Close()
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[mux] [PANIC] stream handler recovered: %v", r)
				}
			}()

			// Read target address (length-prefixed: 2-byte big-endian length + address bytes).
		// Using length prefix instead of newline delimiter because TCP does not
		// preserve message boundaries — the HTTP request data may arrive in the
		// same TCP segment as the target address, causing Read to consume both.
		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(s, lenBuf); err != nil {
			log.Printf("[mux] read target len: %v", err)
			return
		}
		addrLen := int(lenBuf[0])<<8 | int(lenBuf[1])
		if addrLen <= 0 || addrLen > 255 {
			log.Printf("[mux] invalid target len: %d", addrLen)
			return
		}
		addrBuf := make([]byte, addrLen)
		if _, err := io.ReadFull(s, addrBuf); err != nil {
			log.Printf("[mux] read target addr: %v", err)
			return
		}

		targetAddr := string(addrBuf)
		log.Printf("[mux] stream → %s", targetAddr)

		if err := handler(s, targetAddr); err != nil {
			log.Printf("[mux] handler error for %s: %v", targetAddr, err)
		}
		}(stream)
	}
}

// ============================================================================
// Client: connection pool + stream dialing
// ============================================================================

// DialFunc creates a new authenticated Nyx connection.
type DialFunc func() (net.Conn, error)

// Pool manages a pool of multiplexed connections.
// Each connection is a TLS+Nyx+yamux session.
type Pool struct {
	mu       sync.Mutex
	sessions []*yamux.Session
	dial     DialFunc
	maxSize  int
	nextIdx  int
}

// NewPool creates a connection pool.
func NewPool(dial DialFunc, maxSize int) *Pool {
	if maxSize <= 0 {
		maxSize = 4 // default: 4 concurrent TLS connections
	}
	return &Pool{
		dial:    dial,
		maxSize: maxSize,
	}
}

// DialStream opens a new stream on a pooled connection.
// Falls back to creating a new connection if the pool is empty
// or all existing sessions are at capacity.
func (p *Pool) DialStream(targetAddr string) (net.Conn, error) {
	// Try existing sessions first
	session := p.pickSession()
	if session != nil && !session.IsClosed() {
		stream, err := session.Open()
		if err == nil {
			// Send target address (length-prefixed: 2-byte big-endian + addr)
			addrBytes := []byte(targetAddr)
			header := make([]byte, 2+len(addrBytes))
			header[0] = byte(len(addrBytes) >> 8)
			header[1] = byte(len(addrBytes))
			copy(header[2:], addrBytes)
			if _, err := stream.Write(header); err != nil {
				stream.Close()
				return nil, fmt.Errorf("write target: %w", err)
			}
			return stream, nil
		}
		// Session exhausted — remove and create new one
	}

	// Create new connection
	conn, err := p.dial()
	if err != nil {
		return nil, fmt.Errorf("dial nyx: %w", err)
	}

	session, err = NewClientSession(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("yamux: %w", err)
	}

	p.addSession(session)

	// Cleanup goroutine for this session
	go func() {
		<-session.CloseChan()
		p.removeSession(session)
	}()

	stream, err := session.Open()
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}

	addrBytes := []byte(targetAddr)
	header := make([]byte, 2+len(addrBytes))
	header[0] = byte(len(addrBytes) >> 8)
	header[1] = byte(len(addrBytes))
	copy(header[2:], addrBytes)
	if _, err := stream.Write(header); err != nil {
		stream.Close()
		return nil, fmt.Errorf("write target: %w", err)
	}

	return stream, nil
}

// Close closes all sessions in the pool.
func (p *Pool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, s := range p.sessions {
		s.Close()
	}
	p.sessions = nil
	return nil
}

func (p *Pool) pickSession() *yamux.Session {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.sessions) == 0 {
		return nil
	}

	// Round-robin
	idx := p.nextIdx % len(p.sessions)
	p.nextIdx++
	return p.sessions[idx]
}

func (p *Pool) addSession(s *yamux.Session) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.sessions = append(p.sessions, s)

	// Trim excess sessions
	for len(p.sessions) > p.maxSize {
		oldest := p.sessions[0]
		p.sessions = p.sessions[1:]
		go oldest.Close()
	}
}

func (p *Pool) removeSession(s *yamux.Session) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for i, sess := range p.sessions {
		if sess == s {
			p.sessions = append(p.sessions[:i], p.sessions[i+1:]...)
			return
		}
	}
}


