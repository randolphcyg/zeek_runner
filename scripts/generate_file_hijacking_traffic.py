#!/usr/bin/env python3
"""
生成文件劫持攻击测试流量包

该脚本使用 Scapy 生成包含可疑文件下载的流量包，
可用于测试 detect_file_hijacking.zeek 脚本的检测能力。

流量包内容：
1. 下载包含可疑扩展名的文件（.exe, .dll, .sys 等）
2. 模拟文件哈希值与已知值不匹配的情况
"""

from scapy.all import *
import random
import time

# 配置参数
SRC_IP = "192.168.11.159"  # 源 IP 地址
DST_IP = "192.168.11.160"  # 目标 IP 地址
SRC_PORT = random.randint(1024, 65535)  # 源端口
DST_PORT = 80  # 目标端口 (HTTP)
OUTPUT_FILE = "file_hijacking.pcapng"  # 输出文件名

# 可疑文件列表（包含可疑扩展名）
suspicious_files = [
    ("malware.exe", 1024),      # 可执行文件
    ("backdoor.dll", 512),      # 动态链接库
    ("rootkit.sys", 768),       # 系统文件
    ("script.bat", 256),        # 批处理文件
    ("payload.sh", 384),        # Shell 脚本
    ("webshell.php", 640),      # PHP 脚本
    ("malicious.jsp", 896),     # JSP 脚本
    ("legitimate_file.exe", 1024)  # 已知文件但哈希值不同
]

def generate_http_request(file_name, file_size):
    """生成 HTTP GET 请求"""
    http_request = f"""GET /download/{file_name} HTTP/1.1\r\n"""
    http_request += f"Host: example.com\r\n"
    http_request += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36\r\n"
    http_request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
    http_request += "Accept-Language: en-US,en;q=0.5\r\n"
    http_request += "Accept-Encoding: gzip, deflate\r\n"
    http_request += "Connection: keep-alive\r\n"
    http_request += "Upgrade-Insecure-Requests: 1\r\n"
    http_request += "\r\n"
    return http_request

def generate_http_response(file_name, file_size):
    """生成 HTTP 响应"""
    # 生成随机文件内容
    file_content = b"MZ" + b"\x00" * (file_size - 2)  # 简单的 PE 文件头部模拟
    
    http_response = """HTTP/1.1 200 OK\r\n"""
    http_response += f"Content-Type: application/octet-stream\r\n"
    http_response += f"Content-Length: {file_size}\r\n"
    http_response += f"Content-Disposition: attachment; filename=\"{file_name}\"\r\n"
    http_response += "Server: Apache/2.4.41 (Ubuntu)\r\n"
    http_response += "Date: " + time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime()) + "\r\n"
    http_response += "\r\n"
    
    return http_response.encode() + file_content

def generate_file_hijacking_traffic():
    """生成文件劫持测试流量"""
    packets = []
    current_time = time.time()
    
    for file_name, file_size in suspicious_files:
        # 创建 TCP 连接
        # SYN
        syn = IP(src=SRC_IP, dst=DST_IP) / TCP(sport=SRC_PORT, dport=DST_PORT, flags="S")
        syn.time = current_time
        packets.append(syn)
        current_time += 0.1
        
        # SYN-ACK
        syn_ack = IP(src=DST_IP, dst=SRC_IP) / TCP(sport=DST_PORT, dport=SRC_PORT, flags="SA")
        syn_ack.time = current_time
        packets.append(syn_ack)
        current_time += 0.1
        
        # ACK
        ack = IP(src=SRC_IP, dst=DST_IP) / TCP(sport=SRC_PORT, dport=DST_PORT, flags="A")
        ack.time = current_time
        packets.append(ack)
        current_time += 0.1
        
        # HTTP GET 请求
        http_req = IP(src=SRC_IP, dst=DST_IP) / TCP(sport=SRC_PORT, dport=DST_PORT, flags="PA") / generate_http_request(file_name, file_size)
        http_req.time = current_time
        packets.append(http_req)
        current_time += 0.1
        
        # ACK
        ack = IP(src=DST_IP, dst=SRC_IP) / TCP(sport=DST_PORT, dport=SRC_PORT, flags="A")
        ack.time = current_time
        packets.append(ack)
        current_time += 0.1
        
        # HTTP 响应
        http_resp = IP(src=DST_IP, dst=SRC_IP) / TCP(sport=DST_PORT, dport=SRC_PORT, flags="PA") / generate_http_response(file_name, file_size)
        http_resp.time = current_time
        packets.append(http_resp)
        current_time += 0.1
        
        # ACK
        ack = IP(src=SRC_IP, dst=DST_IP) / TCP(sport=SRC_PORT, dport=DST_PORT, flags="A")
        ack.time = current_time
        packets.append(ack)
        current_time += 0.1
        
        # FIN-ACK
        fin_ack = IP(src=SRC_IP, dst=DST_IP) / TCP(sport=SRC_PORT, dport=DST_PORT, flags="FA")
        fin_ack.time = current_time
        packets.append(fin_ack)
        current_time += 0.1
        
        # ACK
        ack = IP(src=DST_IP, dst=SRC_IP) / TCP(sport=DST_PORT, dport=SRC_PORT, flags="A")
        ack.time = current_time
        packets.append(ack)
        current_time += 0.1
        
        # FIN-ACK
        fin_ack = IP(src=DST_IP, dst=SRC_IP) / TCP(sport=DST_PORT, dport=SRC_PORT, flags="FA")
        fin_ack.time = current_time
        packets.append(fin_ack)
        current_time += 0.1
        
        # ACK
        ack = IP(src=SRC_IP, dst=DST_IP) / TCP(sport=SRC_PORT, dport=DST_PORT, flags="A")
        ack.time = current_time
        packets.append(ack)
        current_time += 0.1
        
        # 增加源端口以避免冲突
        SRC_PORT = (SRC_PORT + 1) % 65536
    
    # 写入流量包到文件
    wrpcap(OUTPUT_FILE, packets)
    print(f"生成文件劫持测试流量包成功: {OUTPUT_FILE}")
    print(f"包含 {len(suspicious_files)} 个可疑文件下载")

if __name__ == "__main__":
    generate_file_hijacking_traffic()
