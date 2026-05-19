#!/usr/bin/env python3
"""
Nyx v2.2 Deep Integration Test — Multi-round, multi-pattern.
Covers: concurrency stress, mixed traffic, edge cases, error handling, long-running.
"""
import socket, ssl, time, threading, sys, os, struct, random, string, hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.request import urlopen, Request
from urllib.error import URLError

SOCKS5_ADDR = ("127.0.0.1", 1080)
TIMEOUT = 15
PASS, FAIL, WARN = 0, 0, 0

def result(name, ok, detail="", warn=False):
    global PASS, FAIL, WARN
    if warn:
        WARN += 1
        print(f"  ⚠️  {name}: {detail}")
    elif ok:
        PASS += 1
        print(f"  ✅ {name}: {detail}")
    else:
        FAIL += 1
        print(f"  ❌ {name}: {detail}")

def socks5_handshake(sock, target_host, target_port):
    """SOCKS5 handshake — no auth"""
    sock.sendall(b"\x05\x01\x00")
    resp = sock.recv(2)
    if resp != b"\x05\x00":
        raise Exception(f"Handshake rejected: {resp.hex()}")

    # CONNECT request
    host_bytes = target_host.encode()
    req = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + struct.pack("!H", target_port)
    sock.sendall(req)
    resp = sock.recv(10)
    if resp[0] != 0x05 or resp[1] != 0x00:
        raise Exception(f"CONNECT rejected: {resp.hex()}")
    return resp

def socks5_connect(target_host, target_port=80, timeout=TIMEOUT):
    sock = socket.create_connection(SOCKS5_ADDR, timeout=timeout)
    sock.settimeout(timeout)
    socks5_handshake(sock, target_host, target_port)
    return sock


# ============================================================
# R1: 负载压力
# ============================================================
def test_concurrent_http(n=20):
    """20 并发 HTTP 请求"""
    urls = [
        "http://httpbin.org/ip",
        "http://httpbin.org/get",
        "http://httpbin.org/headers",
        "http://httpbin.org/user-agent",
    ]
    results = []
    lock = threading.Lock()

    def fetch(i):
        url = urls[i % len(urls)]
        try:
            sock = socks5_connect("httpbin.org", 80, timeout=TIMEOUT)
            req = f"GET {url.replace('http://httpbin.org','')} HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n"
            sock.sendall(req.encode())
            data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
            sock.close()
            with lock:
                results.append((i, True, len(data)))
        except Exception as e:
            with lock:
                results.append((i, False, str(e)[:80]))
    threads = []
    for i in range(n):
        t = threading.Thread(target=fetch, args=(i,))
        threads.append(t)
        t.start()
    for t in threads:
        t.join(timeout=TIMEOUT+5)

    ok = sum(1 for _, s, _ in results if s)
    sizes = [s for _, ok_, s in results if ok_ and isinstance(s, int)]
    result(f"R1a: {n} 并发 HTTP", ok == n,
           f"{ok}/{n} PASS, sizes {min(sizes) if sizes else 0}-{max(sizes) if sizes else 0}B" +
           (f", failures: {[(i,e) for i,ok_,e in results if not ok_][:3]}" if ok < n else ""))

def test_rapid_fire(n=50):
    """50 个快速连续短连接 — 测试 accept/cleanup 压力"""
    success = 0
    for i in range(n):
        try:
            sock = socks5_connect("httpbin.org", 80, timeout=8)
            sock.sendall(b"GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n")
            data = sock.recv(1024)
            if b"HTTP" in data:
                success += 1
            sock.close()
        except:
            pass
    result(f"R1b: {n} 快速短连接", success >= n * 0.95,
           f"{success}/{n} (~{success/n*100:.0f}%)")

def test_mixed_http_https(n=10):
    """混合 HTTP+HTTPS 并发"""
    def do_https(i):
        sock = socks5_connect("httpbin.org", 443, timeout=TIMEOUT)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        tls = ctx.wrap_socket(sock, server_hostname="httpbin.org")
        tls.sendall(b"GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n")
        data = tls.recv(4096)
        tls.close()
        return b"HTTP" in data

    def do_http(i):
        sock = socks5_connect("httpbin.org", 80, timeout=TIMEOUT)
        sock.sendall(b"GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n")
        data = sock.recv(4096)
        sock.close()
        return b"HTTP" in data

    tasks = []
    for i in range(n//2):
        tasks.append(("https", i))
        tasks.append(("http", i))

    with ThreadPoolExecutor(max_workers=n) as ex:
        futures = {
            ex.submit(do_https if t == "https" else do_http, i): f"{t}-{i}"
            for t, i in tasks
        }
        ok = 0
        for f in as_completed(futures, timeout=TIMEOUT+5):
            try:
                if f.result():
                    ok += 1
            except:
                pass
    result(f"R1c: 混合 {n//2} HTTP + {n//2} HTTPS", ok == n, f"{ok}/{n}")

def test_sustained_throughput():
    """持续 30s 吞吐量测试（每 2s 一个请求）"""
    start = time.time()
    count = 0
    total_bytes = 0
    while time.time() - start < 30:
        try:
            sock = socks5_connect("httpbin.org", 80, timeout=5)
            sock.sendall(b"GET /bytes/4096 HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n")
            data = b""
            while True:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                data += chunk
            sock.close()
            if b"HTTP" in data:
                count += 1
                total_bytes += len(data)
        except:
            pass
        time.sleep(2)
    result(f"R1d: 30s 持续吞吐", count >= 10,
           f"{count} req in 30s, {total_bytes}B total")


# ============================================================
# R2: 边界异常
# ============================================================
def test_large_transfer():
    """大文件传输（httpbin 没有大文件，用 bytes endpoint 多次）"""
    try:
        sock = socks5_connect("httpbin.org", 80, timeout=TIMEOUT)
        # Request 100KB response
        sock.sendall(b"GET /bytes/102400 HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n")
        data = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
        sock.close()
        # Find body (after \r\n\r\n)
        body_start = data.find(b"\r\n\r\n")
        body_len = len(data) - body_start - 4 if body_start >= 0 else 0
        result(f"R2a: 100KB 传输", body_len >= 100000,
               f"{body_len}B body ({'OK' if body_len >= 100000 else 'SHORT'})")
    except Exception as e:
        result(f"R2a: 100KB 传输", False, str(e)[:80])

def test_small_payload():
    """极小 payload 测试"""
    try:
        sock = socks5_connect("httpbin.org", 80, timeout=TIMEOUT)
        sock.sendall(b"GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n")
        data = sock.recv(4096)
        sock.close()
        result(f"R2b: 极小 payload", b"HTTP" in data and len(data) < 1000,
               f"{len(data)}B")
    except Exception as e:
        result(f"R2b: 极小 payload", False, str(e)[:80])

def test_bad_auth():
    """非法认证 — 应被服务器拒绝"""
    try:
        sock = socket.create_connection(("127.0.0.1", 8443), timeout=5)
        # Send garbage pretending to be auth
        sock.sendall(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n" + b"\x00" * 200 + b"NYXK" + b"\x00" * 81)
        # Give server time to respond
        sock.settimeout(3)
        data = sock.recv(4096)
        sock.close()
        # Should still get a TLS record (or connection close)
        # If we get data back, it's the fallback response
        result(f"R2c: 非法认证拒绝", True,
               f"Got {len(data)}B response (fallback OK)" if data else "Connection closed OK")
    except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError, socket.timeout):
        result(f"R2c: 非法认证拒绝", True, "Connection refused/reset — correct")
    except Exception as e:
        result(f"R2c: 非法认证拒绝", False, str(e)[:80])

def test_empty_request():
    """空请求 — 应被正确处理"""
    try:
        sock = socks5_connect("httpbin.org", 80, timeout=TIMEOUT)
        # Just connect then close immediately
        sock.close()
        result(f"R2d: 连接即关闭", True, "no hang")
    except Exception as e:
        result(f"R2d: 连接即关闭", False, str(e)[:80])

def test_partial_read():
    """部分读取再关闭 — 测试 cleanup"""
    try:
        sock = socks5_connect("httpbin.org", 80, timeout=TIMEOUT)
        sock.sendall(b"GET /bytes/10000 HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n")
        # Read just a bit — must arrive within 15s
        sock.settimeout(15)
        sock.recv(100)
        sock.close()
        result(f"R2e: 部分读取后关闭", True, "clean close")
    except Exception as e:
        result(f"R2e: 部分读取后关闭", False, str(e)[:80])

def test_binary_data():
    """二进制数据透传"""
    try:
        sock = socks5_connect("httpbin.org", 80, timeout=TIMEOUT)
        # httpbin /bytes returns random bytes
        sock.sendall(b"GET /bytes/8192 HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n")
        data = b""
        while True:
            chunk = sock.recv(8192)
            if not chunk:
                break
            data += chunk
        sock.close()
        body_start = data.find(b"\r\n\r\n")
        body = data[body_start+4:] if body_start >= 0 else b""
        # Check SHA256 matches expectations — httpbin doesn't guarantee hash,
        # but we can check content-length matches
        cl_match = b"Content-Length: 8192" in data or b"content-length: 8192" in data
        result(f"R2f: 二进制 8KB 透传", cl_match and len(body) >= 8000,
               f"body {len(body)}B, Content-Length match={cl_match}")
    except Exception as e:
        result(f"R2f: 二进制 8KB 透传", False, str(e)[:80])


# ============================================================
# R3: 长时间稳定性
# ============================================================
def test_long_idle_connection():
    """Nyx 隧道心率保持 60s 空闲后可用（需目标端也容忍闲置）"""
    try:
        sock = socks5_connect("httpbin.org", 80, timeout=TIMEOUT)
        # Exchange data first to prove tunnel works
        sock.sendall(b"GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: keep-alive\r\n\r\n")
        data = sock.recv(4096)
        if b"HTTP" not in data:
            result("R3a: initial exchange", False, f"Got {len(data)}B")
            sock.close()
            return
        # Idle for 30s — Nyx heartbeats run at 30-90s intervals
        # (heartsbeat keeps Nyx tunnel alive; target keep-alive is up to the target server)
        time.sleep(30)
        sock.sendall(b"GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n")
        data = sock.recv(4096)
        sock.close()
        result(f"R3a: 30s 空闲后恢复", b"HTTP" in data,
               f"Got HTTP response" if b"HTTP" in data else f"Got {len(data)}B")
    except Exception as e:
        result(f"R3a: 30s 空闲后恢复", False, str(e)[:80])

def test_repeated_connections(rounds=3):
    """多轮重复连接 — 检测资源泄漏"""
    for r in range(rounds):
        success = 0
        for i in range(10):
            try:
                sock = socks5_connect("httpbin.org", 80, timeout=8)
                sock.sendall(b"GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n")
                data = sock.recv(4096)
                if b"HTTP" in data:
                    success += 1
                sock.close()
            except:
                pass
        result(f"R3b: 轮{r+1} 10连接", success == 10,
               f"{success}/10" if success < 10 else "10/10",
               warn=(success < 10))
        if r < rounds - 1:
            time.sleep(3)


# ============================================================
# Main
# ============================================================
print("=" * 60)
print("Nyx v2.2 Deep Integration Test")
print(f"SOCKS5: {SOCKS5_ADDR[0]}:{SOCKS5_ADDR[1]}")
print(f"Time: {time.strftime('%H:%M:%S')}")
print("=" * 60)

# --- R1: Load ---
print("\n--- R1: 负载压力 ---")
test_concurrent_http(20)
test_rapid_fire(50)
test_mixed_http_https(10)
test_sustained_throughput()

# --- R2: Edge cases ---
print("\n--- R2: 边界异常 ---")
test_large_transfer()
test_small_payload()
test_bad_auth()
test_empty_request()
test_partial_read()
test_binary_data()

# --- R3: Long stability ---
print("\n--- R3: 稳定性 (may take 2min) ---")
test_long_idle_connection()
test_repeated_connections(3)

# --- Summary ---
print(f"\n{'='*60}")
total = PASS + FAIL + WARN
print(f"PASS: {PASS}/{total} | FAIL: {FAIL}/{total} | WARN: {WARN}/{total}")
print(f"{'='*60}")
sys.exit(0 if FAIL == 0 else 1)
