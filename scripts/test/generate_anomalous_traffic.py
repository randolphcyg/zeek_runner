#!/usr/bin/env python3
"""
生成异常网络流量的测试流量包
用于测试 detect_anomalous_traffic.zeek 脚本
"""

import os
import sys
from scapy.all import *

# 生成大量数据传输的流量
def generate_large_traffic():
    packets = []
    
    # 源IP和目标IP
    src_ip = "192.168.11.159"
    dst_ip = "192.168.11.160"
    
    # 生成多个大尺寸数据包
    for i in range(2000):  # 增加到2000个数据包
        # 生成2000字节的数据包（超过1500字节的阈值）
        payload = b'A' * 2000
        
        # 创建IP数据包
        ip_pkt = IP(src=src_ip, dst=dst_ip)
        # 创建TCP数据包
        tcp_pkt = TCP(sport=12345, dport=80, flags="PA", seq=i*2000)
        # 组合数据包
        pkt = ip_pkt / tcp_pkt / payload
        
        # 添加到数据包列表
        packets.append(pkt)
    
    return packets

# 生成正常流量（用于对比）
def generate_normal_traffic():
    packets = []
    
    # 源IP和目标IP
    src_ip = "192.168.11.159"
    dst_ip = "192.168.11.160"
    
    # 生成少量正常尺寸的数据包
    for i in range(10):
        # 生成100字节的数据包
        payload = b'B' * 100
        
        # 创建IP数据包
        ip_pkt = IP(src=src_ip, dst=dst_ip)
        # 创建TCP数据包
        tcp_pkt = TCP(sport=12345, dport=80, flags="PA", seq=200*1600 + i*100)
        # 组合数据包
        pkt = ip_pkt / tcp_pkt / payload
        
        # 添加到数据包列表
        packets.append(pkt)
    
    return packets

if __name__ == "__main__":
    # 生成数据包
    packets = generate_large_traffic() + generate_normal_traffic()
    
    # 保存为pcap文件
    output_file = "anomalous_traffic.pcap"
    wrpcap(output_file, packets)
    
    print(f"生成异常流量测试包成功: {output_file}")
    print(f"数据包数量: {len(packets)}")
    print("包含:")
    print("- 2000个2000字节的大尺寸数据包（超过1500字节阈值）")
    print("- 10个100字节的正常尺寸数据包")
    print("- 总数据量: ~4001KB (~4MB)")
