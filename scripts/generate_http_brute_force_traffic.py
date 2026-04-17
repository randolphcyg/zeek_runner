#!/usr/bin/env python3
"""
生成HTTP暴力破解测试流量包

该脚本使用 Scapy 生成包含多次HTTP登录失败的流量包，
可用于测试 detect_http_brute_force.zeek 脚本的检测能力。

流量包内容：
1. 多次HTTP登录失败尝试
2. 模拟HTTP暴力破解行为
"""

from scapy.all import *
import random
import time

# 配置参数
SRC_IP = "192.168.11.159"  # 源 IP 地址
DST_IP = "192.168.11.160"  # 目标 IP 地址
DST_PORT = 80  # HTTP 端口
OUTPUT_FILE = "http_brute_force.pcapng"  # 输出文件名
FAILURE_COUNT = 10  # 登录失败次数

# 生成HTTP登录请求数据包
def generate_http_login_request(username, password):
    return f"POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(f'username={username}&password={password}')}\r\n\r\nusername={username}&password={password}".encode()

# 生成HTTP 401响应数据包
def generate_http_401_response():
    return b"HTTP/1.1 401 Unauthorized\r\nContent-Type: text/html\r\nContent-Length: 162\r\nWWW-Authenticate: Basic realm=\"Example\"\r\n\r\n<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>401 Unauthorized</title>\n</head><body>\n<h1>Unauthorized</h1>\n</body></html>"

# 生成HTTP 403响应数据包
def generate_http_403_response():
    return b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nContent-Length: 156\r\n\r\n<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>403 Forbidden</title>\n</head><body>\n<h1>Forbidden</h1>\n</body></html>"

def generate_brute_force_traffic():
    """生成HTTP暴力破解测试流量"""
    packets = []
    current_time = time.time()
    
    for i in range(FAILURE_COUNT):
        # 随机用户名和密码
        username = f"user{i}"
        password = f"pass{i}"
        
        # 创建TCP连接
        # SYN
        syn = IP(src=SRC_IP, dst=DST_IP) / TCP(sport=random.randint(1024, 65535), dport=DST_PORT, flags="S")
        syn.time = current_time
        packets.append(syn)
        current_time += 0.1
        
        # SYN-ACK
        syn_ack = IP(src=DST_IP, dst=SRC_IP) / TCP(sport=DST_PORT, dport=syn[TCP].sport, flags="SA")
        syn_ack.time = current_time
        packets.append(syn_ack)
        current_time += 0.1
        
        # ACK
        ack = IP(src=SRC_IP, dst=DST_IP) / TCP(sport=syn[TCP].sport, dport=DST_PORT, flags="A")
        ack.time = current_time
        packets.append(ack)
        current_time += 0.1
        
        # 发送HTTP登录请求
        http_request = IP(src=SRC_IP, dst=DST_IP) / TCP(sport=syn[TCP].sport, dport=DST_PORT, flags="PA") / generate_http_login_request(username, password)
        http_request.time = current_time
        packets.append(http_request)
        current_time += 0.1
        
        # 响应ACK
        ack = IP(src=DST_IP, dst=SRC_IP) / TCP(sport=DST_PORT, dport=syn[TCP].sport, flags="A")
        ack.time = current_time
        packets.append(ack)
        current_time += 0.1
        
        # 服务器回应401或403
        if i % 2 == 0:
            http_response = IP(src=DST_IP, dst=SRC_IP) / TCP(sport=DST_PORT, dport=syn[TCP].sport, flags="PA") / generate_http_401_response()
        else:
            http_response = IP(src=DST_IP, dst=SRC_IP) / TCP(sport=DST_PORT, dport=syn[TCP].sport, flags="PA") / generate_http_403_response()
        http_response.time = current_time
        packets.append(http_response)
        current_time += 0.1
        
        # ACK
        ack = IP(src=SRC_IP, dst=DST_IP) / TCP(sport=syn[TCP].sport, dport=DST_PORT, flags="A")
        ack.time = current_time
        packets.append(ack)
        current_time += 0.1
        
        # FIN-ACK
        fin_ack = IP(src=SRC_IP, dst=DST_IP) / TCP(sport=syn[TCP].sport, dport=DST_PORT, flags="FA")
        fin_ack.time = current_time
        packets.append(fin_ack)
        current_time += 0.1
        
        # ACK
        ack = IP(src=DST_IP, dst=SRC_IP) / TCP(sport=DST_PORT, dport=syn[TCP].sport, flags="A")
        ack.time = current_time
        packets.append(ack)
        current_time += 0.1
        
        # FIN-ACK
        fin_ack = IP(src=DST_IP, dst=SRC_IP) / TCP(sport=DST_PORT, dport=syn[TCP].sport, flags="FA")
        fin_ack.time = current_time
        packets.append(fin_ack)
        current_time += 0.1
        
        # ACK
        ack = IP(src=SRC_IP, dst=DST_IP) / TCP(sport=syn[TCP].sport, dport=DST_PORT, flags="A")
        ack.time = current_time
        packets.append(ack)
        current_time += 0.1
    
    # 写入流量包到文件
    wrpcap(OUTPUT_FILE, packets)
    print(f"生成HTTP暴力破解测试流量包成功: {OUTPUT_FILE}")
    print(f"包含 {FAILURE_COUNT} 次HTTP登录失败尝试")

if __name__ == "__main__":
    generate_brute_force_traffic()
