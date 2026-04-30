#!/usr/bin/env python3
"""
生成包含恶意IP的测试流量包

该脚本使用 Scapy 生成包含已知恶意IP的流量包，
可用于测试Intel框架的情报匹配能力。

流量包内容：
1. 包含恶意IP 171.25.193.25 的TCP连接
2. 包含恶意IP 1.1.1.1 的ICMP ping
3. 包含恶意IP 8.8.8.8 的DNS查询
"""

from scapy.all import *
import random
import time

# 配置参数
SRC_IP = "192.168.11.159"  # 源 IP 地址
MALICIOUS_IP1 = "171.25.193.25"  # 恶意 IP 地址 1
MALICIOUS_IP2 = "1.1.1.1"  # 恶意 IP 地址 2
MALICIOUS_IP3 = "8.8.8.8"  # 恶意 IP 地址 3
OUTPUT_FILE = "malicious_ip_test.pcapng"  # 输出文件名

# 生成包含恶意IP的TCP连接
def generate_malicious_tcp_traffic(packets, current_time):
    """生成包含恶意IP的TCP连接"""
    # 目标端口
    dst_port = 80
    
    # 创建TCP连接
    # SYN
    syn = IP(src=SRC_IP, dst=MALICIOUS_IP1) / TCP(sport=random.randint(1024, 65535), dport=dst_port, flags="S")
    syn.time = current_time
    packets.append(syn)
    current_time += 0.1
    
    # SYN-ACK
    syn_ack = IP(src=MALICIOUS_IP1, dst=SRC_IP) / TCP(sport=dst_port, dport=syn[TCP].sport, flags="SA")
    syn_ack.time = current_time
    packets.append(syn_ack)
    current_time += 0.1
    
    # ACK
    ack = IP(src=SRC_IP, dst=MALICIOUS_IP1) / TCP(sport=syn[TCP].sport, dport=dst_port, flags="A")
    ack.time = current_time
    packets.append(ack)
    current_time += 0.1
    
    # 发送HTTP请求
    http_request = IP(src=SRC_IP, dst=MALICIOUS_IP1) / TCP(sport=syn[TCP].sport, dport=dst_port, flags="PA") / b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    http_request.time = current_time
    packets.append(http_request)
    current_time += 0.1
    
    # 响应ACK
    ack = IP(src=MALICIOUS_IP1, dst=SRC_IP) / TCP(sport=dst_port, dport=syn[TCP].sport, flags="A")
    ack.time = current_time
    packets.append(ack)
    current_time += 0.1
    
    # 服务器回应
    http_response = IP(src=MALICIOUS_IP1, dst=SRC_IP) / TCP(sport=dst_port, dport=syn[TCP].sport, flags="PA") / b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<!DOCTYPE html><html><body><h1>Test</h1></body></html>"
    http_response.time = current_time
    packets.append(http_response)
    current_time += 0.1
    
    # ACK
    ack = IP(src=SRC_IP, dst=MALICIOUS_IP1) / TCP(sport=syn[TCP].sport, dport=dst_port, flags="A")
    ack.time = current_time
    packets.append(ack)
    current_time += 0.1
    
    # FIN-ACK
    fin_ack = IP(src=SRC_IP, dst=MALICIOUS_IP1) / TCP(sport=syn[TCP].sport, dport=dst_port, flags="FA")
    fin_ack.time = current_time
    packets.append(fin_ack)
    current_time += 0.1
    
    # ACK
    ack = IP(src=MALICIOUS_IP1, dst=SRC_IP) / TCP(sport=dst_port, dport=syn[TCP].sport, flags="A")
    ack.time = current_time
    packets.append(ack)
    current_time += 0.1
    
    return current_time

# 生成包含恶意IP的ICMP流量
def generate_malicious_icmp_traffic(packets, current_time):
    """生成包含恶意IP的ICMP流量"""
    # ICMP Echo Request
    icmp_req = IP(src=SRC_IP, dst=MALICIOUS_IP2) / ICMP(type=8, code=0) / b"test"
    icmp_req.time = current_time
    packets.append(icmp_req)
    current_time += 0.1
    
    # ICMP Echo Reply
    icmp_reply = IP(src=MALICIOUS_IP2, dst=SRC_IP) / ICMP(type=0, code=0) / b"test"
    icmp_reply.time = current_time
    packets.append(icmp_reply)
    current_time += 0.1
    
    return current_time

# 生成包含恶意IP的DNS流量
def generate_malicious_dns_traffic(packets, current_time):
    """生成包含恶意IP的DNS流量"""
    # DNS Query
    dns_query = IP(src=SRC_IP, dst=MALICIOUS_IP3) / UDP(sport=random.randint(1024, 65535), dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com"))
    dns_query.time = current_time
    packets.append(dns_query)
    current_time += 0.1
    
    # DNS Response
    dns_response = IP(src=MALICIOUS_IP3, dst=SRC_IP) / UDP(sport=53, dport=dns_query[UDP].sport) / DNS(an=DNSRR(rrname="example.com", rdata="93.184.216.34"))
    dns_response.time = current_time
    packets.append(dns_response)
    current_time += 0.1
    
    return current_time

def generate_malicious_traffic():
    """生成包含恶意IP的测试流量"""
    packets = []
    current_time = time.time()
    
    # 生成包含恶意IP的TCP流量
    current_time = generate_malicious_tcp_traffic(packets, current_time)
    
    # 生成包含恶意IP的ICMP流量
    current_time = generate_malicious_icmp_traffic(packets, current_time)
    
    # 生成包含恶意IP的DNS流量
    current_time = generate_malicious_dns_traffic(packets, current_time)
    
    # 写入流量包到文件
    wrpcap(OUTPUT_FILE, packets)
    print(f"生成包含恶意IP的测试流量包成功: {OUTPUT_FILE}")
    print(f"包含以下恶意IP:")
    print(f"  - {MALICIOUS_IP1}")
    print(f"  - {MALICIOUS_IP2}")
    print(f"  - {MALICIOUS_IP3}")

if __name__ == "__main__":
    generate_malicious_traffic()