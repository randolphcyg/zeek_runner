import socket
import time

def simulate_http_download(file_path, file_content):
    """模拟 HTTP 下载关键文件"""
    try:
        # 创建服务器套接字
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("192.168.11.159", 8000))
        server.listen(1)
        print(f"服务器启动，监听 192.168.11.159:8000")
        
        # 创建客户端套接字
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(("192.168.11.159", 8000))
        print("客户端连接成功")
        
        # 接受连接
        conn, addr = server.accept()
        print(f"接受到来自 {addr} 的连接")
        
        # 客户端发送 HTTP 请求
        request = f"GET {file_path} HTTP/1.1\r\nHost: 192.168.11.159:8000\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        client.send(request.encode())
        print(f"发送请求: GET {file_path}")
        
        # 服务器接收请求
        data = conn.recv(1024)
        print(f"接收到请求: {data.decode()[:100]}...")
        
        # 服务器发送响应
        response = f"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {len(file_content)}\r\n\r\n{file_content}"
        conn.send(response.encode())
        print(f"发送响应: HTTP 200 OK")
        
        # 客户端接收响应
        response_data = client.recv(1024)
        print(f"接收到响应: {len(response_data)} 字节")
        
        # 关闭连接
        conn.close()
        client.close()
        server.close()
        
    except Exception as e:
        print(f"错误: {e}")
        import traceback
        traceback.print_exc()

# 模拟下载可疑文件
print("=== 模拟文件篡改流量 ===")
simulate_http_download("/setup.exe", "malicious content")
time.sleep(2)
simulate_http_download("/etc/passwd", "root:x:0:0:root:/root:/bin/bash")
time.sleep(2)
simulate_http_download("/download/malware.exe", "malicious content")