#!/usr/bin/env python3
from scapy.all import IP, TCP, wrpcap, RandIP

def generate_syn_flood_pcap(output_file, target_ip, target_port, packet_count):
    """
    生成SYN洪水流量的pcap文件
    
    Args:
        output_file: 输出pcap文件路径
        target_ip: 目标IP地址
        target_port: 目标端口
        packet_count: 生成的数据包数量
    """
    packets = []
    
    print(f"正在生成 {packet_count} 个SYN包...")
    
    for i in range(packet_count):
        # 生成随机源IP
        src_ip = RandIP()
        # 生成随机源端口
        src_port = 1024 + (i % 64511)
        
        # 构造SYN包
        packet = IP(src=src_ip, dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="S")
        
        packets.append(packet)
        
        # 每1000个包显示一次进度
        if (i + 1) % 1000 == 0:
            print(f"已生成 {i + 1}/{packet_count} 个包")
    
    # 保存为pcap文件
    wrpcap(output_file, packets)
    print(f"SYN洪水流量已保存到 {output_file}，共 {len(packets)} 个包")

if __name__ == "__main__":
    # 配置参数
    output_file = "large_syn_flood.pcap"
    target_ip = "192.168.1.100"  # 目标IP地址
    target_port = 80  # 目标端口
    packet_count = 1000000  # 生成10000个包
    
    # 生成pcap文件
    generate_syn_flood_pcap(output_file, target_ip, target_port, packet_count)