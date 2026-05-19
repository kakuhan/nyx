// Package socks5 — Local SOCKS5 proxy server
// Accepts SOCKS5 connections from local applications and forwards
// them through a Nyx encrypted tunnel.
package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync/atomic"
)

const (
	SOCKS5Version = 0x05
	CmdConnect    = 0x01
	AtypIPv4      = 0x01
	AtypDomain    = 0x03
	AtypIPv6      = 0x04
	RepSuccess    = 0x00
	RepFail       = 0x01
	RepCmdNotSup  = 0x07
	RepAtypNotSup = 0x08
)

// Dialer establishes a connection to the target through Nyx.
// Called once per SOCKS5 connection, already knows the target address.
type Dialer func(targetAddr string) (net.Conn, error)

// Server is a local SOCKS5 proxy.
type Server struct {
	listen      string
	dialer      Dialer
	connCounter uint64        // atomic counter for per-connection IDs
	listener    net.Listener  // stored for graceful Shutdown()
}

// NewServer creates a SOCKS5 proxy server.
func NewServer(listen string, dialer Dialer) *Server {
	return &Server{
		listen: listen,
		dialer: dialer,
	}
}

// Run starts the SOCKS5 listener. Blocks until Shutdown() is called.
func (s *Server) Run() error {
	ln, err := net.Listen("tcp", s.listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.listen, err)
	}
	s.listener = ln
	defer ln.Close()
	log.Printf("[SOCKS5] listening on %s", s.listen)

	for {
		conn, err := ln.Accept()
		if err != nil {
			// Listener closed by Shutdown() — exit cleanly
			if errors.Is(err, net.ErrClosed) {
				log.Printf("[SOCKS5] listener closed, shutting down")
				return nil
			}
			log.Printf("[SOCKS5] accept: %v", err)
			continue
		}
		go s.handle(conn, atomic.AddUint64(&s.connCounter, 1))
	}
}

// Shutdown gracefully stops the SOCKS5 server by closing the listener.
// Run() returns nil after the listener is closed.
func (s *Server) Shutdown() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *Server) handle(conn net.Conn, id uint64) {
	defer conn.Close()

	// 1. Handshake — read auth methods
	buf := make([]byte, 258)
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		log.Printf("[S#%d] handshake read: %v", id, err)
		return
	}
	if buf[0] != SOCKS5Version {
		log.Printf("[S#%d] bad version: %02x", id, buf[0])
		return
	}
	nmethods := int(buf[1])
	if nmethods > 0 {
		if _, err := io.ReadFull(conn, buf[:nmethods]); err != nil {
			log.Printf("[S#%d] auth methods read: %v", id, err)
			return
		}
	}

	// Reply: no authentication required
	if _, err := conn.Write([]byte{SOCKS5Version, 0x00}); err != nil {
		log.Printf("[S#%d] auth reply write: %v", id, err)
		return
	}

	// 2. Request — read CMD + target address
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		log.Printf("[S#%d] request read: %v", id, err)
		return
	}

	if header[1] != CmdConnect {
		if _, err := conn.Write([]byte{SOCKS5Version, RepCmdNotSup, 0x00, header[3], 0, 0, 0, 0, 0, 0}); err != nil {
			log.Printf("[S#%d] CMD failure write: %v", id, err)
		}
		return
	}

	atyp := header[3]

	// Parse target address
	target, err := parseTarget(conn, atyp)
	if err != nil {
		if _, err := conn.Write([]byte{SOCKS5Version, RepAtypNotSup, 0x00, atyp, 0, 0, 0, 0, 0, 0}); err != nil {
			log.Printf("[S#%d] ATYP failure write: %v", id, err)
		}
		return
	}

	log.Printf("[S#%d] → %s", id, target)

	// 3. Dial target through Nyx tunnel
	nyxConn, err := s.dialer(target)
	if err != nil {
		log.Printf("[S#%d] dial: %v", id, err)
		if _, err := conn.Write([]byte{SOCKS5Version, RepFail, 0x00, atyp, 0, 0, 0, 0, 0, 0}); err != nil {
			log.Printf("[S#%d] DIAL failure write: %v", id, err)
		}
		return
	}
	defer nyxConn.Close()

	// 4. Reply success — use ATYP=1 (IPv4) with 0.0.0.0:0 per RFC 1928 §6.
	// The bound address is irrelevant for CONNECT; most SOCKS5 clients ignore it.
	// This avoids leftover bytes in the buffer (unlike the previous ATYP=3 hack
	// that wrote a fixed 10 bytes but encoded a zero-length domain).
	if _, err := conn.Write([]byte{
		SOCKS5Version, RepSuccess, 0x00,
		AtypIPv4,                // address type
		0, 0, 0, 0,             // bound IP: 0.0.0.0
		0, 0,                    // bound port: 0
	}); err != nil {
		return
	}

	// 5. Bidirectional relay
	// Each goroutine closes its write-side connection when copying finishes,
	// so the opposite goroutine is unblocked. This is the standard TCP half-close
	// pattern: close nyxConn when the app is done sending, close conn when the
	// tunnel is done sending.
	done := make(chan struct{}, 2)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[S#%d] [PANIC] app→tunnel recovered: %v", id, r)
				done <- struct{}{} // unblock parent to prevent goroutine leak
			}
		}()
		defer nyxConn.Close() // unblock tunnel→app goroutine
		n, werr := io.Copy(nyxConn, conn)
		log.Printf("[S#%d] app→tunnel copied %d bytes (err=%v)", id, n, werr)
		done <- struct{}{}
	}()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[S#%d] [PANIC] tunnel→app recovered: %v", id, r)
				done <- struct{}{} // unblock parent to prevent goroutine leak
			}
		}()
		defer conn.Close() // unblock app→tunnel goroutine
		n, werr := io.Copy(conn, nyxConn)
		log.Printf("[S#%d] tunnel→app copied %d bytes (err=%v)", id, n, werr)
		done <- struct{}{}
	}()

	<-done
	<-done // wait for both relay goroutines before returning
}

// parseTarget parses the target address from SOCKS5 request.
func parseTarget(conn net.Conn, atyp byte) (string, error) {
	switch atyp {
	case AtypIPv4:
		addr := make([]byte, 4+2) // IP + port
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		return net.JoinHostPort(
			net.IP(addr[:4]).String(),
			strconv.Itoa(int(binary.BigEndian.Uint16(addr[4:]))),
		), nil

	case AtypDomain:
		var lenBuf [1]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return "", err
		}
		domain := make([]byte, int(lenBuf[0])+2) // domain + port
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", err
		}
		portIdx := len(domain) - 2
		return net.JoinHostPort(
			string(domain[:portIdx]),
			strconv.Itoa(int(binary.BigEndian.Uint16(domain[portIdx:]))),
		), nil

	case AtypIPv6:
		addr := make([]byte, 16+2)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		return net.JoinHostPort(
			net.IP(addr[:16]).String(),
			strconv.Itoa(int(binary.BigEndian.Uint16(addr[16:]))),
		), nil

	default:
		return "", fmt.Errorf("unsupported ATYP: %d", atyp)
	}
}
