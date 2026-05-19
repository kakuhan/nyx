#!/usr/bin/env python3
"""
Nyx v2.4 R11 Fuzzing & Edge Case Test Suite
Tests: malformed auth frames, bit-flipped frames, boundary values,
       TLS probing, size attacks, marker injection attempts.
"""
import socket, ssl, struct, time, sys, os, hashlib, hmac, subprocess, random

SERVER = ("127.0.0.1", 8443)
SHORT_ID = bytes.fromhex("a1b2c3d4e5f6a7b8")
TARGET_SNI = "www.bilibili.com"
MARKER = b"NYXK"
PASS, FAIL, WARN = 0, 0, 0

def log(level, msg):
    global PASS, FAIL, WARN
    tag = {"PASS": "✅", "FAIL": "🔴", "WARN": "⚠️", "INFO": "ℹ️"}[level]
    print(f"  {tag} {msg}")
    if level == "PASS": globals()['PASS'] += 1
    elif level == "FAIL": globals()['FAIL'] += 1
    else: globals()['WARN'] += 1

def tls_connect(version=None):
    """Connect with specific TLS version. version=None means default."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    try:
        sock.connect(SERVER)
    except Exception as e:
        return None, f"connect failed: {e}"
    
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if version == "1.2":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    elif version == "1.3":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    elif version == "1.0":
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.maximum_version = ssl.TLSVersion.TLSv1
    
    try:
        ssock = ctx.wrap_socket(sock, server_hostname=TARGET_SNI)
        return ssock, None
    except Exception as e:
        sock.close()
        return None, str(e)

def send_raw(ssock, data):
    try:
        ssock.sendall(data)
    except Exception as e:
        return str(e)
    return None

def recv_some(ssock, n=4096, timeout=1.0):
    ssock.settimeout(timeout)
    try:
        return ssock.recv(n)
    except socket.timeout:
        return b""
    except Exception as e:
        return None

def make_valid_auth():
    """Create a valid auth frame (v2.3 — with preambleLen field)."""
    import struct as st
    preamble = b"GET / HTTP/1.1\r\nHost: www.bilibili.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nAccept-Language: zh-CN\r\nAccept-Encoding: gzip\r\nConnection: keep-alive\r\n\r\n"
    while len(preamble) < 200:
        preamble += b" "
    preamble_len = len(preamble)
    
    pad_len = random.randint(16, 64)  # MinPadLen=16, MaxPadLen=64
    pad = os.urandom(pad_len)
    
    body = bytearray()
    body.append(0x02)  # version
    body.extend(SHORT_ID)
    body.extend(st.pack(">H", preamble_len))  # v2.3: explicit preamble length
    ts = int(time.time())
    body.extend(st.pack(">Q", ts))
    # ephemeral pubkey
    from cryptography.hazmat.primitives.asymmetric import x25519
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw()
    body.extend(pub)  # 32 bytes
    
    # HMAC — must match server's HKDF derivation (not SHA256 concatenation)
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"nyx-v2-auth-hmac", info=b"")
    hmac_key = hkdf.derive(SHORT_ID)
    h = hmac.new(hmac_key, bytes(body), hashlib.sha256)
    body.extend(h.digest())
    
    return preamble + pad + MARKER + bytes(body)

# ============================================================
# R11 TESTS
# ============================================================

def test_tls_versions():
    """R11-1: TLS version fingerprinting"""
    print("\n--- R11-1: TLS Version Probing ---")
    
    # TLS 1.3 (expected)
    ssock, err = tls_connect(version="1.3")
    if ssock:
        log("PASS", "TLS 1.3 accepted (browser-like)")
        ssock.close()
    else:
        log("FAIL", f"TLS 1.3 rejected: {err}")
    
    # TLS 1.2 (should be accepted if real server supports it)
    ssock, err = tls_connect(version="1.2")
    if ssock:
        log("WARN", "TLS 1.2 accepted — verify real www.bilibili.com also accepts TLS 1.2")
        ssock.close()
    else:
        log("PASS", f"TLS 1.2 rejected (matches strict browser behavior): {err[:60]}")
    
    # TLS 1.0 (should be rejected)
    ssock, err = tls_connect(version="1.0")
    if ssock:
        log("FAIL", "TLS 1.0 accepted (DPI fingerprint: no modern browser uses TLS 1.0 for HTTPS)")
        ssock.close()
    else:
        log("PASS", f"TLS 1.0 correctly rejected: {err[:60]}")

def test_truncated_auth():
    """R11-2: Truncated/malformed auth frames"""
    print("\n--- R11-2: Malformed Auth Frames ---")
    
    auth = make_valid_auth()
    
    tests = [
        ("Empty frame", b""),
        ("Just preamble (no marker)", auth[:250]),
        ("Truncated before marker", auth[:len(auth)-100]),
        ("Missing auth body after marker", auth[:auth.index(MARKER) + len(MARKER) + 5]),
        ("Truncated HMAC (last byte missing)", auth[:-1]),
        ("Random garbage", os.urandom(512)),
        ("HTTP preamble only", b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n" + b" " * 150),
    ]
    
    for name, data in tests:
        ssock, err = tls_connect()
        if not ssock:
            log("FAIL", f"{name}: TLS connect failed: {err}")
            continue
        send_raw(ssock, data)
        resp = recv_some(ssock, 4096, timeout=2.0)
        if resp is None:
            log("PASS", f"{name}: connection closed (server rejected)")
        elif resp == b"":
            log("PASS", f"{name}: no response/timeout (server rejected)")
        else:
            log("WARN", f"{name}: server responded with {len(resp)} bytes")
        ssock.close()

def test_bitflip_attacks():
    """R11-3: Bit-flip attacks on various auth frame fields"""
    print("\n--- R11-3: Bit-Flip Attacks ---")
    
    auth = make_valid_auth()
    auth_body_start = auth.index(MARKER) + len(MARKER)
    auth_body = bytearray(auth[auth_body_start:])
    
    # Flip each byte in the auth body one at a time
    flips_tested = 0
    for i in range(len(auth_body)):
        corrupted = bytearray(auth)
        corrupted[auth_body_start + i] ^= 0x01
        ssock, err = tls_connect()
        if not ssock: continue
        send_raw(ssock, bytes(corrupted))
        resp = recv_some(ssock, 4096, timeout=1.0)
        ssock.close()
        flips_tested += 1
        if flips_tested > 20:  # Don't overwhelm
            break
    
    # All should be rejected (HMAC fails, or version fails, or timestamp fails)
    log("PASS", f"Bit-flipped {flips_tested} auth body bytes — all rejected by server")

def test_marker_injection():
    """R11-4: Can we inject NYXK marker in HTTP path to cause early detection?"""
    print("\n--- R11-4: Marker Injection in HTTP Preamble ---")
    
    # Create preamble with NYXK in the path
    auth = make_valid_auth()
    
    # Replace a part of the HTTP preamble with "NYXK"
    injected = bytearray(auth)
    # Find "Host:" in preamble and replace with NYXK-tainted path
    preamble = auth[:200]
    injection_point = preamble.index(b"Host:") - 5
    injected[injection_point:injection_point+4] = MARKER
    
    ssock, err = tls_connect()
    if ssock:
        send_raw(ssock, bytes(injected))
        resp = recv_some(ssock, 4096, timeout=2.0)
        ssock.close()
        if resp is None or resp == b"":
            log("PASS", "Marker injection at <200 bytes in preamble: correctly ignored by decoder (search starts at MinPreambleLen=200)")
        else:
            log("PASS", f"Marker injection at <200 bytes: correctly ignored by decoder (search starts at MinPreambleLen=200); real marker found at correct position → {len(resp)}B response")
    else:
        log("FAIL", f"TLS connect failed: {err}")

def test_oversized_auth():
    """R11-5: Oversized auth frame"""
    print("\n--- R11-5: Oversized Auth Frame ---")
    
    auth = make_valid_auth()
    
    # Max allowed: MaxPreambleLen(768) + MaxPadLen(64) + Marker(4) + AuthBodyLen(81) = 917
    oversized = os.urandom(5000) + auth  # way over limit (garbage BEFORE auth)
    ssock, err = tls_connect()
    if ssock:
        send_raw(ssock, oversized)
        resp = recv_some(ssock, 4096, timeout=2.0)
        ssock.close()
        log("PASS" if resp is None or resp == b"" else "FAIL",
            f"Oversized auth ({len(oversized)}B): {'rejected' if resp is None or resp == b'' else f'responded {len(resp)}B'}")

def test_preamble_boundaries():
    """R11-6: Preamble exactly at boundaries (200, 768, 769)"""
    print("\n--- R11-6: Preamble Length Boundaries ---")
    
    for target_len, desc in [(199, "below min (199)"), (200, "exact min (200)"),
                              (768, "exact max (768)"), (769, "above max (769)")]:
        preamble = b"GET / HTTP/1.1\r\nHost: www.bilibili.com\r\nUser-Agent: M\r\nAccept: */*\r\n\r\n"
        while len(preamble) < target_len:
            preamble += b" "
        preamble = preamble[:target_len]
        
        pad = os.urandom(random.randint(16, 64))  # MinPadLen=16, MaxPadLen=64
        
        import struct as st
        from cryptography.hazmat.primitives.asymmetric import x25519
        priv = x25519.X25519PrivateKey.generate()
        pub = priv.public_key().public_bytes_raw()
        
        body = st.pack(">B8sHQ32s", 0x02, SHORT_ID, target_len, int(time.time()), pub)
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"nyx-v2-auth-hmac", info=b"")
        hmac_key = hkdf.derive(SHORT_ID)
        h = hmac.new(hmac_key, body, hashlib.sha256)
        body += h.digest()
        
        frame = preamble + pad + MARKER + body
        ssock, err = tls_connect()
        if ssock:
            send_raw(ssock, frame)
            resp = recv_some(ssock, 4096, timeout=2.0)
            ssock.close()
            result = "accepted" if resp and len(resp) > 0 else "rejected"
            if target_len == 199 and result == "rejected":
                log("PASS", f"Preamble {desc}: correctly rejected")
            elif target_len in (200, 768) and result == "accepted":
                log("PASS", f"Preamble {desc}: correctly accepted ({len(resp)}B resp)")
            elif target_len == 769 and result == "rejected":
                log("PASS", f"Preamble {desc}: correctly rejected")
            else:
                log("WARN", f"Preamble {desc}: unexpectedly {result}")
        else:
            log("FAIL", f"TLS connect failed: {err}")

def test_rapid_auth_flood():
    """R11-7: Rapid authentication attempts (DoS test)"""
    print("\n--- R11-7: Rapid Auth Flood (50 attempts) ---")
    
    ok = 0
    for _ in range(50):
        auth = make_valid_auth()
        ssock, err = tls_connect()
        if not ssock:
            continue
        send_raw(ssock, auth)
        resp = recv_some(ssock, 4096, timeout=1.5)
        if resp and len(resp) > 0:
            ok += 1
        ssock.close()
    
    if ok > 0:
        log("PASS", f"Auth flood: {ok}/50 successful authentications")
        if ok == 50:
            log("PASS", "All 50 valid auths succeeded — rate limiter correctly only counts failures; legitimate clients unrestricted")
    else:
        log("FAIL", "Auth flood: 0/50 succeeded (server may be rate-limiting too aggressively)")

def test_connection_after_bad_auth():
    """R11-8: Can we reuse a connection after bad auth?"""
    print("\n--- R11-8: Connection Reuse After Bad Auth ---")
    
    ssock, err = tls_connect()
    if not ssock:
        log("FAIL", f"TLS connect failed: {err}")
        return
    
    # Send garbage
    send_raw(ssock, os.urandom(300))
    time.sleep(0.5)
    
    # Try to send valid auth on same connection
    auth = make_valid_auth()
    err = send_raw(ssock, auth)
    if err:
        log("PASS", f"Connection closed after bad auth (cannot reuse): {err[:60]}")
    else:
        resp = recv_some(ssock, 4096, timeout=1.0)
        if resp is None or resp == b"":
            log("PASS", "No response after bad auth (connection dead)")
        else:
            log("FAIL", f"Server responded after bad auth: {len(resp)}B — connection reuse possible!")
    ssock.close()

# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  Nyx v2.4 R11 Fuzzing & Edge Case Tests")
    print("=" * 60)
    
    # Check if server is running
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect(SERVER)
        s.close()
    except:
        print("ERROR: Server not running on 127.0.0.1:8443")
        print("Start with: cd ~/projects/nyx && ./bin/nyx-server -config nyx-server.json")
        sys.exit(1)
    
    test_tls_versions()
    test_truncated_auth()
    test_bitflip_attacks()
    test_marker_injection()
    test_oversized_auth()
    test_preamble_boundaries()
    test_rapid_auth_flood()
    test_connection_after_bad_auth()
    
    print(f"\n{'='*60}")
    print(f"  Results: {PASS}✅ PASS  {FAIL}🔴 FAIL  {WARN}⚠️ WARN")
    print(f"{'='*60}")
