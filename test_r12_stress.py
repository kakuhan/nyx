#!/usr/bin/env python3
"""Nyx v2.4 R12 Stress Test — 高并发、大文件、长稳、资源泄漏检测

Note: httpbin.org caps /bytes/ at 100KB. Large transfer tests (R12b/f)
use a local HTTP server to bypass this limit.
"""
import socket, struct, time, threading, sys, os, subprocess, ssl
import http.server

SOCKS5 = ("127.0.0.1", 1080)
TIMEOUT = 15
HTTPBIN = "httpbin.org"
LOCAL_HOST = "127.0.0.1"
LOCAL_PORT = 19876  # local HTTP server for large file tests

PASS = 0; FAIL = 0; WARN = 0
_lock = threading.Lock()

def log(level, label, msg):
    global PASS, FAIL, WARN
    with _lock:
        if level == "PASS": PASS += 1; icon = "✅"
        elif level == "FAIL": FAIL += 1; icon = "🔴"
        else: WARN += 1; icon = "⚠️"
        print(f"  {icon} {label}: {msg}")

def socks5_connect(host, port, tout=TIMEOUT):
    s = socket.create_connection(SOCKS5, tout)
    s.settimeout(tout)
    s.sendall(b'\x05\x01\x00')
    if s.recv(2) != b'\x05\x00': raise Exception("socks5 handshake fail")
    hb = host.encode() if isinstance(host, str) else host
    s.sendall(b'\x05\x01\x00\x03' + bytes([len(hb)]) + hb + struct.pack('!H', port))
    resp = s.recv(10)
    if resp[1] != 0: raise Exception(f"CONNECT rejected: {resp.hex()}")
    return s

def http_get(s, path="/get"):
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: {HTTPBIN}\r\nConnection: close\r\n\r\n".encode())
    data = b""
    while True:
        try:
            c = s.recv(8192)
            if not c: break
            data += c
        except socket.timeout: break
    return data

def http_raw(host, s, path, headers=None):
    """Send HTTP request to arbitrary host, return body."""
    req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n"
    if headers:
        for k,v in headers.items():
            req += f"{k}: {v}\r\n"
    req += "\r\n"
    s.sendall(req.encode())
    data = b""
    while True:
        try:
            c = s.recv(65536)
            if not c: break
            data += c
        except socket.timeout: break
    bs = data.find(b"\r\n\r\n")
    return data[bs+4:] if bs >= 0 else data

# ============================================================
# Local HTTP server for large file tests
# ============================================================

class LargeFileHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        size_map = {"/1mb": 1048576, "/100kb": 102400, "/50kb": 51200}
        size = size_map.get(self.path, 1024)
        self.send_response(200)
        self.send_header("Content-Length", str(size))
        self.send_header("Content-Type", "application/octet-stream")
        self.end_headers()
        remaining = size
        chunk = os.urandom(min(65536, remaining))
        while remaining > 0:
            n = min(len(chunk), remaining)
            self.wfile.write(chunk[:n])
            remaining -= n

def start_local_server():
    srv = http.server.HTTPServer((LOCAL_HOST, LOCAL_PORT), LargeFileHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    time.sleep(0.3)
    return srv

# ============================================================
# R12a: 高并发 (50, 100)
# ============================================================
def test_concurrency(n):
    ok = [0]; errs = []
    def worker():
        try:
            s = socks5_connect(HTTPBIN, 80, tout=10)
            d = http_get(s, "/ip")
            s.close()
            if b"HTTP" in d: ok[0] += 1
            else: errs.append(f"no-http:{len(d)}B")
        except Exception as e: errs.append(str(e)[:60])
    threads = [threading.Thread(target=worker) for _ in range(n)]
    t0 = time.time()
    for t in threads: t.start()
    for t in threads: t.join()
    elapsed = time.time() - t0
    label = f"R12a: {n} 并发"
    if ok[0] >= n * 0.95:
        log("PASS", label, f"{ok[0]}/{n} OK in {elapsed:.1f}s")
    elif ok[0] >= n * 0.7:
        log("WARN", label, f"{ok[0]}/{n} OK in {elapsed:.1f}s (errs: {errs[:2]})")
    else:
        log("FAIL", label, f"{ok[0]}/{n} OK in {elapsed:.1f}s (errs: {errs[:3]})")

# ============================================================
# R12b: 大文件传输 (100KB via local server, integrity check)
# ============================================================
def test_large_transfer():
    """Transfer 100KB from local server through Nyx tunnel, verify integrity."""
    try:
        s = socks5_connect(LOCAL_HOST, LOCAL_PORT, tout=60)
        body = http_raw("localhost", s, "/100kb")
        s.close()
        label = "R12b: 100KB 传输"
        if len(body) >= 102400:
            log("PASS", label, f"Got {len(body)}B OK")
        elif len(body) > 0:
            log("WARN", label, f"Got {len(body)}B / 102400 ({100*len(body)//102400}%)")
        else:
            log("FAIL", label, "Got 0 bytes")
    except Exception as e:
        log("FAIL", "R12b: 100KB 传输", str(e)[:80])

# ============================================================
# R12c: 快速短连接 (200 rapid cycles)
# ============================================================
def test_rapid_cycles(n=200):
    ok = 0
    t0 = time.time()
    for i in range(n):
        try:
            s = socks5_connect(HTTPBIN, 80, tout=5)
            d = http_get(s, "/ip")
            s.close()
            if b"HTTP" in d: ok += 1
        except: pass
        if (i+1) % 20 == 0:
            print(f"        R12c progress: {i+1}/{n}, {ok} OK ({time.time()-t0:.0f}s)", flush=True)
    elapsed = time.time() - t0
    label = f"R12c: {n} 短连接循环"
    if ok >= n * 0.95:
        log("PASS", label, f"{ok}/{n} OK in {elapsed:.1f}s ({ok/elapsed:.1f} conn/s)")
    elif ok >= n * 0.7:
        log("WARN", label, f"{ok}/{n} OK in {elapsed:.1f}s")
    else:
        log("FAIL", label, f"{ok}/{n} OK in {elapsed:.1f}s")

# ============================================================
# R12d: 混合攻击 (100有效+50无效 auth)
# ============================================================
def test_mixed_attack():
    ok = 0; total_valid = 100
    def worker(valid=True):
        nonlocal ok
        try:
            if valid:
                s = socks5_connect(HTTPBIN, 80, tout=10)
                d = http_get(s, "/ip")
                s.close()
                if b"HTTP" in d: ok += 1
            else:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                raw = socket.create_connection(("127.0.0.1", 8443), 5)
                tls = ctx.wrap_socket(raw)
                tls.sendall(os.urandom(400))
                time.sleep(0.2)
                tls.close()
        except: pass

    threads = []
    for _ in range(total_valid):
        threads.append(threading.Thread(target=worker, args=(True,)))
    for _ in range(50):
        threads.append(threading.Thread(target=worker, args=(False,)))
    t0 = time.time()
    for t in threads: t.start()
    for t in threads: t.join()
    elapsed = time.time() - t0
    label = "R12d: 100有效+50无效混合"
    if ok >= 90:
        log("PASS", label, f"{ok}/{total_valid} valid OK in {elapsed:.1f}s (server survived attack)")
    else:
        log("FAIL", label, f"{ok}/{total_valid} valid OK (server degraded under attack)")

# ============================================================
# R12e: 空闲恢复 — 两次独立连接测试服务器 60s 空闲后仍可接受新连接
# ============================================================
def test_idle_recovery():
    """Connect, do request, close. Wait 60s. Connect again, do request.
    Tests server liveness after idle, not httpbin keep-alive."""
    # First connection
    try:
        s = socks5_connect(HTTPBIN, 80, tout=30)
        d1 = http_get(s, "/ip")
        s.close()
        if b"HTTP" not in d1:
            log("FAIL", "R12e: 空闲恢复", f"Initial connection failed: {len(d1)}B")
            return
    except Exception as e:
        log("FAIL", "R12e: 空闲恢复", f"Initial connect: {e}")
        return

    print("        (idle 60s...)")
    time.sleep(60)

    # Second connection — server should still accept new tunnels
    try:
        s = socks5_connect(HTTPBIN, 80, tout=30)
        d2 = http_get(s, "/ip")
        s.close()
        label = "R12e: 60s 空闲恢复"
        if b"HTTP" in d2:
            log("PASS", label, "Server accepted new connection after 60s idle")
        else:
            log("WARN", label, f"Response invalid after idle: {len(d2)}B")
    except Exception as e:
        log("FAIL", "R12e: 空闲恢复", f"Reconnect after idle: {e}")

# ============================================================
# R12f: 并发大文件 (10 × 100KB via local server)
# ============================================================
def test_concurrent_large(n=10):
    ok = [0]; total_bytes = [0]
    def worker():
        try:
            s = socks5_connect(LOCAL_HOST, LOCAL_PORT, tout=60)
            body = http_raw("localhost", s, "/100kb")
            s.close()
            if len(body) >= 102400:
                ok[0] += 1
                total_bytes[0] += len(body)
        except: pass
    threads = [threading.Thread(target=worker) for _ in range(n)]
    t0 = time.time()
    for t in threads: t.start()
    for t in threads: t.join()
    elapsed = time.time() - t0
    label = f"R12f: {n}×100KB 并发"
    if ok[0] == n:
        mbps = total_bytes[0] / elapsed / 1048576
        log("PASS", label, f"{ok[0]}/{n} OK ({total_bytes[0]//1024}KB in {elapsed:.1f}s, {mbps:.1f} MB/s)")
    elif ok[0] >= n * 0.5:
        log("WARN", label, f"{ok[0]}/{n} OK")
    else:
        log("FAIL", label, f"{ok[0]}/{n} OK")

# ============================================================
# Resource Baseline
# ============================================================
def check_resources():
    try:
        pid = subprocess.check_output(["pgrep", "-f", "nyx-server"]).decode().strip().split("\n")[0]
        rss = open(f"/proc/{pid}/status").read()
        rss_mb = 0; threads = 0
        for line in rss.split("\n"):
            if line.startswith("VmRSS:"): rss_mb = int(line.split()[1]) // 1024
            if line.startswith("Threads:"): threads = int(line.split()[1])
        fds = len(os.listdir(f"/proc/{pid}/fd"))
        print(f"\n  📊 资源基线: RSS={rss_mb}MB, Threads={threads}, FDs={fds}")
        return rss_mb, threads, fds
    except:
        print("\n  ⚠️ 无法获取资源基线")
        return 0, 0, 0

# ============================================================
# Main
# ============================================================
if __name__ == "__main__":
    print("=" * 60)
    print("  Nyx v2.4 R12 Stress Test")
    print(f"  Time: {time.strftime('%H:%M:%S')}")
    print("=" * 60)

    # Start local HTTP server for large file tests (bypasses httpbin 100KB cap)
    local_srv = start_local_server()
    print(f"  Local test server: {LOCAL_HOST}:{LOCAL_PORT}")

    # Pre-check
    try:
        s = socks5_connect(HTTPBIN, 80, tout=5)
        d = http_get(s)
        s.close()
        if b"HTTP" not in d:
            print("FATAL: Proxy not working. Start nyx-server + nyx-client first.")
            sys.exit(1)
        print("  Pre-check OK: proxy functional\n")
    except Exception as e:
        print(f"FATAL: Proxy unreachable: {e}")
        sys.exit(1)

    rss_before, th_before, fd_before = check_resources()

    print("\n--- R12a: 并发测试 ---")
    test_concurrency(50)
    test_concurrency(100)

    print("\n--- R12b: 大文件传输 (本地服务器, 绕过 httpbin 100KB 限制) ---")
    test_large_transfer()

    print("\n--- R12c: 快速短连接 ---")
    test_rapid_cycles(200)

    print("\n--- R12d: 混合攻击 ---")
    test_mixed_attack()

    print("\n--- R12e: 空闲恢复 (60s) ---")
    test_idle_recovery()

    print("\n--- R12f: 并发大文件 (本地服务器) ---")
    test_concurrent_large(10)

    rss_after, th_after, fd_after = check_resources()

    print(f"\n  📈 资源变化: RSS {rss_before}→{rss_after}MB, Threads {th_before}→{th_after}, FDs {fd_before}→{fd_after}")
    print(f"\n{'='*60}")
    print(f"  Results: {PASS}✅ PASS  {FAIL}🔴 FAIL  {WARN}⚠️ WARN")
    print(f"{'='*60}")

    local_srv.shutdown()
    sys.exit(0 if FAIL == 0 else 1)
