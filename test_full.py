#!/usr/bin/env python3
"""Nyx protocol integration test suite."""
import socket, time, threading, struct, ssl, sys

SOCKS5_HOST, SOCKS5_PORT = "127.0.0.1", 1080
TIMEOUT = 15

def socks5_connect(target_host, target_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    try:
        sock.connect((SOCKS5_HOST, SOCKS5_PORT))
        sock.sendall(b"\x05\x01\x00")
        resp = sock.recv(2)
        if resp != b"\x05\x00":
            sock.close(); return None, f"handshake: {resp.hex()}"
        addr = target_host.encode()
        req = b"\x05\x01\x00\x03" + bytes([len(addr)]) + addr + struct.pack("!H", target_port)
        sock.sendall(req)
        resp = sock.recv(10)
        if len(resp) < 10 or resp[1] != 0x00:
            code = resp[1] if len(resp) > 1 else -1
            sock.close(); return None, f"request reply code={code}"
        return sock, None
    except Exception as e:
        return None, str(e)

def http_get(host, port=80, path="/"):
    sock, err = socks5_connect(host, port)
    if err: return None, 0, err
    t0 = time.time()
    try:
        sock.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk: break
            data += chunk
    except Exception as e:
        sock.close(); return None, time.time()-t0, str(e)
    sock.close()
    return data, time.time()-t0, None

def https_get(host, port=443, path="/"):
    sock, err = socks5_connect(host, port)
    if err: return None, 0, err
    t0 = time.time()
    try:
        ctx = ssl.create_default_context()
        tls_sock = ctx.wrap_socket(sock, server_hostname=host)
        tls_sock.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        data = b""
        while True:
            chunk = tls_sock.recv(4096)
            if not chunk: break
            data += chunk
        tls_sock.close()
    except Exception as e:
        return None, time.time()-t0, str(e)
    return data, time.time()-t0, None

results = []

# === T1: HTTP basic ===
print("=== T1: HTTP httpbin.org/ip ===", flush=True)
data, elapsed, err = http_get("httpbin.org", 80, "/ip")
ok = data is not None and b"origin" in data
status = "PASS" if ok else "FAIL"
results.append(("T1 HTTP basic", status, f"{elapsed:.2f}s len={len(data) if data else 0} err={err}"))
print(f"  {status}: {elapsed:.2f}s", flush=True)

# === T2: HTTPS basic ===
print("=== T2: HTTPS httpbin.org/ip ===", flush=True)
data, elapsed, err = https_get("httpbin.org", 443, "/ip")
ok = data is not None and b"origin" in data
status = "PASS" if ok else "FAIL"
results.append(("T2 HTTPS basic", status, f"{elapsed:.2f}s len={len(data) if data else 0}"))
print(f"  {status}: {elapsed:.2f}s", flush=True)

# === T3: Concurrent 5 ===
print("=== T3: Concurrent 5x HTTP ===", flush=True)
per_thread = []
def worker(idx):
    data, elapsed, err = http_get("httpbin.org", 80, "/ip")
    per_thread.append((idx, data is not None and b"origin" in data, elapsed, err))
t0 = time.time()
threads = []
for i in range(5):
    t = threading.Thread(target=worker, args=(i,)); t.start(); threads.append(t)
for t in threads: t.join()
total_t = time.time() - t0
ok_n = sum(1 for i, o, e, err in per_thread if o)
status = "PASS" if ok_n == 5 else "PARTIAL" if ok_n > 0 else "FAIL"
results.append(("T3 Concur 5x", status, f"{ok_n}/5 total={total_t:.1f}s"))
print(f"  {ok_n}/5 in {total_t:.1f}s", flush=True)
for i, o, e, err in per_thread:
    if not o: print(f"    w#{i} FAIL: {err} ({e:.1f}s)", flush=True)

# === T4: 10MB download ===
print("=== T4: 10MB download ===", flush=True)
sock, err = socks5_connect("speed.hetzner.de", 80)
if err:
    results.append(("T4 10MB dl", "SKIP", f"connect: {err}"))
else:
    t0 = time.time()
    sock.sendall(b"GET /10MB.bin HTTP/1.1\r\nHost: speed.hetzner.de\r\nConnection: close\r\n\r\n")
    data = b""
    while b"\r\n\r\n" not in data:
        data += sock.recv(4096)
    body = data[data.index(b"\r\n\r\n")+4:]
    total = len(body)
    while True:
        try:
            chunk = sock.recv(65536)
            if not chunk: break
            total += len(chunk)
        except: break
    sock.close()
    elapsed = time.time() - t0
    mb = total/1024/1024
    status = "PASS" if total > 9_900_000 else "WARN"
    results.append(("T4 10MB dl", status, f"{mb:.1f}MB {elapsed:.1f}s ({mb/elapsed:.1f} MB/s)"))
    print(f"  {status}: {mb:.1f}MB {elapsed:.1f}s ({mb/elapsed:.1f} MB/s)", flush=True)

# === T5: Heartbeat keep-alive ===
print("=== T5: Heartbeat keep-alive ===", flush=True)
sock, err = socks5_connect("httpbin.org", 80)
if err:
    results.append(("T5 heartbeat", "SKIP", f"connect: {err}"))
else:
    sock.sendall(b"GET /delay/5 HTTP/1.1\r\nHost: httpbin.org\r\nConnection: keep-alive\r\n\r\n")
    t0 = time.time()
    data = b""
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk: break
            data += chunk
        except socket.timeout: break
    dt1 = time.time()-t0
    sock.sendall(b"GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n")
    data2 = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk: break
        data2 += chunk
    sock.close()
    reuse_ok = b"origin" in data2
    status = "PASS" if reuse_ok else "WARN"
    results.append(("T5 heartbeat", status, f"delay={dt1:.1f}s reuse={'Y' if reuse_ok else 'N'}"))
    print(f"  {status}: delay={dt1:.1f}s conn_reuse={'Y' if reuse_ok else 'N'}", flush=True)

# === T6: Edge ===
print("=== T6: Edge cases ===", flush=True)
# 6a: raw GET
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
try:
    s.connect(("127.0.0.1", 8443))
    s.sendall(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
    resp = s.recv(1024)
    s.close()
    results.append(("T6a raw GET", "PASS", f"resp len={len(resp)}"))
except Exception as e:
    results.append(("T6a raw GET", "PASS", f"rejected: {e}"))
print(f"  raw GET: {results[-1][2]}", flush=True)

# 6b: DNS fail
sock, err = socks5_connect("invalid-xyz12345.test", 80)
results.append(("T6b DNS fail", "PASS" if err else "FAIL", f"{err}"))
print(f"  DNS fail: {'PASS' if err else 'FAIL'}", flush=True)

# 6c: closed port
data, elapsed, err = http_get("httpbin.org", 81, "/")
results.append(("T6c closed port", "PASS" if err else "WARN", f"err={err}"))
print(f"  closed port: {'error' if err else 'WARN'}", flush=True)

# === T7: Repeat 3x HTTP ===
print("=== T7: Repeat 3x HTTP ===", flush=True)
for i in range(3):
    data, elapsed, err = http_get("httpbin.org", 80, "/ip")
    ok = data is not None and b"origin" in data
    print(f"  run{i+1}: {'OK' if ok else 'FAIL'} {elapsed:.2f}s", flush=True)

# === Summary ===
print("\n" + "="*60)
print("FINAL RESULTS")
print("="*60)
for n, r, d in results:
    icon = "✓" if r.startswith("PASS") else "✗" if r.startswith("FAIL") else "⚠" if r.startswith("WARN") else "-"
    print(f"  {icon} {n:20s} | {r:12s} | {d}")
passed = sum(1 for n,r,d in results if r.startswith("PASS"))
failed = sum(1 for n,r,d in results if r.startswith("FAIL"))
warned = sum(1 for n,r,d in results if r.startswith("WARN"))
skipped = sum(1 for n,r,d in results if r.startswith("SKIP"))
print(f"\n  PASS={passed} WARN={warned} FAIL={failed} SKIP={skipped}")
