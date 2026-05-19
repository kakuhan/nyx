// Package tls provides uTLS-based TLS fingerprint randomization for Nyx.
//
// Standard Go crypto/tls produces a fixed ClientHello fingerprint that GFW
// can trivially identify and block. uTLS (utls) mimics real browser TLS
// handshakes (Chrome, Firefox, Safari, Edge) — every connection gets a
// randomized browser fingerprint, making Nyx indistinguishable from
// legitimate HTTPS traffic.
//
// Reference: https://github.com/refraction-networking/utls
package tls

import (
	"crypto/rand"
	stdtls "crypto/tls"
	"math/big"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

// Supported browser fingerprints. Each maps to a real browser's
// TLS ClientHello profile — cipher suites, extensions, curves, etc.
//
// CONSTRAINT: Go's crypto/tls server rejects Kyber/Post-Quantum groups with
// "tls: protocol version not supported". Chrome 124+ enables Kyber by default.
// uTLS v1.6.7 caps Chrome at 120 (last pre-Kyber stable) and Firefox at 120.
// All non-_PQ Chrome variants, all Firefox variants, and all Safari/Edge are safe.
//
// Pool size: 14 fingerprints (vs 5 previously). Real browsers use dozens of
// minor versions in the wild — expanding the pool reduces the repeat rate
// and makes Nyx connections harder to cluster.
var browserFingerprints = []utls.ClientHelloID{
	// Chrome/Chromium family (pre-Kyber, X25519 only)
	utls.HelloChrome_120,
	utls.HelloChrome_106_Shuffle, // extension shuffling variant
	utls.HelloChrome_102,
	utls.HelloChrome_100,
	utls.HelloChrome_96,
	utls.HelloChrome_87,
	utls.HelloChrome_83,
	// Firefox family (no Kyber, all versions safe)
	utls.HelloFirefox_120,
	utls.HelloFirefox_105,
	utls.HelloFirefox_102,
	utls.HelloFirefox_99,
	// Edge family (Chromium-based, Pre-Kyber)
	utls.HelloEdge_106,
	utls.HelloEdge_85,
	// Safari family (no Kyber)
	utls.HelloSafari_16_0,
}

// sessionCache caches TLS 1.3 Session Tickets for 0-RTT/1-RTT resumption
// across multiple connections to the same server. Real browsers do this —
// without it, every connection performs a full handshake, creating a detectable
// fingerprint (no resumption = not a real browser).
var sessionCache = utls.NewLRUClientSessionCache(128)

// Randomize returns a random browser ClientHelloID from the pool.
// Uses crypto/rand (not math/rand) for unpredictable fingerprint selection.
// Called once per connection to produce a different fingerprint each time.
func Randomize() utls.ClientHelloID {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(browserFingerprints))))
	if err != nil {
		// Fallback: use the most common browser (Chrome 120)
		return utls.HelloChrome_120
	}
	return browserFingerprints[n.Int64()]
}

// DialTLSStandard establishes a TLS 1.3 connection using Go's standard crypto/tls.
// No uTLS fingerprint randomization — produces the standard Go ClientHello.
// Used when uTLS is incompatible with the server's Go crypto/tls (known issue:
// uTLS browser fingerprints may omit signature algorithms or encode versions
// in ways Go's server rejects). The standard Go fingerprint is well-known and
// widely used, making it reasonable camouflage for Nyx connections.
func DialTLSStandard(network, addr string, serverName string) (net.Conn, error) {
	config := &stdtls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, // We verify via Nyx auth, not PKI
		MinVersion:         stdtls.VersionTLS13, // Enforce TLS 1.3 (server requires it)
		MaxVersion:         stdtls.VersionTLS13,
		NextProtos:         []string{"http/1.1"}, // Plain HTTP/1.1 ALPN
	}

	d := &net.Dialer{Timeout: 15 * time.Second}
	return stdtls.DialWithDialer(d, network, addr, config)
}
// DialTLS establishes a TLS connection with a randomized browser fingerprint.
// Equivalent to tls.Dial but uses uTLS for the ClientHello.
func DialTLS(network, addr string, serverName string) (net.Conn, error) {
	fingerprint := Randomize()

	uConfig := &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, // We verify via Nyx auth, not PKI
		MinVersion:         stdtls.VersionTLS13,
		MaxVersion:         stdtls.VersionTLS13,
		// ALPN is fingerprint-specific — do NOT set NextProtos here.
		// Firefox 105 fingerprints offer only "http/1.1", Chrome offers "h2"+"http/1.1".
		// Hardcoding ["h2","http/1.1"] on a Firefox fingerprint creates a detectable
		// cross-browser inconsistency that DPI can use to identify Nyx tunnels.
		// Let each uTLS fingerprint determine its own ALPN values.
		ClientSessionCache: sessionCache,                     // TLS 1.3 session resumption (browser-identical behavior)
	}

	rawConn, err := net.DialTimeout(network, addr, 15*time.Second)
	if err != nil {
		return nil, err
	}

	// Set handshake deadline — prevents hanging forever if the server
	// accepts TCP but stalls the TLS handshake (active probing defense).
	rawConn.SetDeadline(time.Now().Add(15 * time.Second))

	uConn := utls.UClient(rawConn, uConfig, fingerprint)
	if err := uConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, err
	}

	// Clear handshake deadline — connection is established.
	rawConn.SetDeadline(time.Time{})

	return uConn, nil
}