### detect_dns_flood.zeek

```shell
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: your-token-here" \
  -d '{
    "pcapPath": "/zeek_runner/pcaps/amp.dns.RRSIG.fragmented.pcap",
    "scriptPath": "/zeek_runner/scripts/detect_dns_flood.zeek",
    "onlyNotice": true,
    "uuid": "test-detect_dns_flood",
    "taskID": "11111",
    "pcapID": "pcap-dns-flood",
    "scriptID": "script-detect-dns-flood"
  }' \
  http://localhost:8000/api/v1/analyze
```

### detect_http_cmd_injection.zeek

```shell
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: your-token-here" \
  -d '{
    "pcapPath": "/zeek_runner/pcaps/exploit.pcap",
    "scriptPath": "/zeek_runner/scripts/detect_http_cmd_injection.zeek",
    "onlyNotice": true,
    "uuid": "test-detect_http_cmd_injection",
    "taskID": "22222",
    "pcapID": "pcap-http-cmd-injection",
    "scriptID": "script-detect-http-cmd-injection"
  }' \
  http://localhost:8000/api/v1/analyze
```

### detect_http_flood.zeek

```shell
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: your-token-here" \
  -d '{
    "pcapPath": "/zeek_runner/pcaps/HTTPDoSNovember2021.pcapng",
    "scriptPath": "/zeek_runner/scripts/detect_http_flood.zeek",
    "onlyNotice": true,
    "uuid": "test-detect_http_flood",
    "taskID": "333333",
    "pcapID": "pcap-http-flood",
    "scriptID": "script-detect-http-flood"
  }' \
  http://localhost:8000/api/v1/analyze
```

### detect_http_suspicious_ua.zeek

```shell
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: your-token-here" \
  -d '{
    "pcapPath": "/zeek_runner/pcaps/ua.pcap",
    "scriptPath": "/zeek_runner/scripts/detect_http_suspicious_ua.zeek",
    "onlyNotice": true,
    "uuid": "test-detect_http_suspicious_ua",
    "taskID": "44444",
    "pcapID": "pcap-http-suspicious-ua",
    "scriptID": "script-detect-http-suspicious-ua"
  }' \
  http://localhost:8000/api/v1/analyze
```

### detect_http_webshell.zeek

```shell
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: your-token-here" \
  -d '{
    "pcapPath": "/zeek_runner/pcaps/BTLOPortScan.pcap",
    "scriptPath": "/zeek_runner/scripts/detect_http_webshell.zeek",
    "onlyNotice": true,
    "uuid": "test-detect_http_webshell",
    "taskID": "555555",
    "pcapID": "pcap-http-webshell",
    "scriptID": "script-detect-http-webshell"
  }' \
  http://localhost:8000/api/v1/analyze
```

### detect_ssh_bruteforce.zeek

```shell
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: your-token-here" \
  -d '{
    "pcapPath": "/zeek_runner/pcaps/sshguess.pcap",
    "scriptPath": "/zeek_runner/scripts/detect_ssh_bruteforce.zeek",
    "onlyNotice": true,
    "uuid": "test-detect_ssh_bruteforce",
    "taskID": "666666",
    "pcapID": "pcap-ssh-bruteforce",
    "scriptID": "script-detect-ssh-bruteforce"
  }' \
  http://localhost:8000/api/v1/analyze
```

### detect_ssh_file_transfer.zeek

```shell
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: your-token-here" \
  -d '{
    "pcapPath": "/zeek_runner/pcaps/scp.pcapng",
    "scriptPath": "/zeek_runner/scripts/detect_ssh_file_transfer.zeek",
    "onlyNotice": true,
    "uuid": "test-detect_ssh_file_transfer",
    "taskID": "77777777",
    "pcapID": "pcap-ssh-file-transfer",
    "scriptID": "script-detect-ssh-file-transfer"
  }' \
  http://localhost:8000/api/v1/analyze
```

### detect_syn_flood.zeek

```shell
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: your-token-here" \
  -d '{
    "pcapPath": "/zeek_runner/pcaps/SYNflood.pcap",
    "scriptPath": "/zeek_runner/scripts/detect_syn_flood.zeek",
    "onlyNotice": true,
    "uuid": "test-detect_syn_flood",
    "taskID": "8888888",
    "pcapID": "pcap-syn-flood",
    "scriptID": "script-detect-syn-flood"
  }' \
  http://localhost:8000/api/v1/analyze
```

### detect_slammer_worm.zeek

```shell
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: your-token-here" \
  -d '{
    "pcapPath": "/zeek_runner/pcaps/slammer.pcap",
    "scriptPath": "/zeek_runner/scripts/detect_slammer_worm.zeek",
    "onlyNotice": true,
    "uuid": "test-detect_slammer_worm",
    "taskID": "100000",
    "pcapID": "pcap-slammer-worm",
    "scriptID": "script-detect-slammer-worm"
  }' \
  http://localhost:8000/api/v1/analyze
```

### detect_sqli_webshell.zeek

```shell
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: your-token-here" \
  -d '{
    "pcapPath": "/zeek_runner/pcaps/dvwa-sqli-writeWebShell.pcap",
    "scriptPath": "/zeek_runner/scripts/detect_sqli_webshell.zeek",
    "onlyNotice": true,
    "uuid": "test-detect_sqli_webshell",
    "taskID": "999999",
    "pcapID": "pcap-sqli-webshell",
    "scriptID": "script-detect-sqli-webshell"
  }' \
  http://localhost:8000/api/v1/analyze
```

### detect_anomalous_traffic.zeek

检测异常网络流量，使用 `generate_anomalous_traffic.py` 生成测试流量包：

```shell
# 1. 生成测试流量包
python scripts/generate_anomalous_traffic.py
# 输出: anomalous_traffic.pcap (约4MB，包含2000个2000字节数据包)

# 2. 测试脚本
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: your-token-here" \
  -d '{
    "pcapPath": "/opt/zeek_runner/pcaps/anomalous_traffic.pcap",
    "scriptPath": "/opt/zeek_runner/scripts/detect_anomalous_traffic.zeek",
    "onlyNotice": true,
    "uuid": "test-detect_anomalous_traffic",
    "taskID": "test_anomalous_traffic",
    "pcapID": "pcap-anomalous-traffic",
    "scriptID": "script-detect-anomalous-traffic"
  }' \
  http://localhost:8000/api/v1/analyze
```

### detect_file_tampering.zeek

检测文件篡改行为，使用 `generate_file_tampering_traffic.py` 生成测试流量包：

```shell
# 1. 生成测试流量包
python scripts/generate_file_tampering_traffic.py

# 2. 测试脚本
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: your-token-here" \
  -d '{
    "pcapPath": "/opt/zeek_runner/pcaps/file_tampering.pcap",
    "scriptPath": "/opt/zeek_runner/scripts/detect_file_tampering.zeek",
    "onlyNotice": true,
    "uuid": "test-detect_file_tampering",
    "taskID": "test_file_tampering",
    "pcapID": "pcap-file-tampering",
    "scriptID": "script-detect-file-tampering"
  }' \
  http://localhost:8000/api/v1/analyze
```

### detect_http_brute_force.zeek

检测HTTP暴力破解攻击，使用 `generate_http_brute_force_traffic.py` 生成测试流量包：

```shell
# 1. 生成测试流量包
python scripts/generate_http_brute_force_traffic.py

# 2. 测试脚本
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: your-token-here" \
  -d '{
    "pcapPath": "/opt/zeek_runner/pcaps/http_brute_force.pcap",
    "scriptPath": "/opt/zeek_runner/scripts/detect_http_brute_force.zeek",
    "onlyNotice": true,
    "uuid": "test-detect_http_brute_force",
    "taskID": "test_http_brute_force",
    "pcapID": "pcap-http-brute-force",
    "scriptID": "script-detect-http-brute-force"
  }' \
  http://localhost:8000/api/v1/analyze
```

### detect_http_cmd_injection.zeek

检测HTTP命令注入攻击：

```shell
# 测试脚本
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: your-token-here" \
  -d '{
    "pcapPath": "/zeek_runner/pcaps/exploit.pcap",
    "scriptPath": "/zeek_runner/scripts/detect_http_cmd_injection.zeek",
    "onlyNotice": true,
    "uuid": "test-detect_http_cmd_injection",
    "taskID": "22222",
    "pcapID": "pcap-http-cmd-injection",
    "scriptID": "script-detect-http-cmd-injection"
  }' \
  http://localhost:8000/api/v1/analyze
```

## 流量包生成脚本

项目提供了以下流量包生成脚本，用于测试对应的检测脚本：

| 生成脚本 | 用途 | 生成的流量包 |
|---------|------|-------------|
| `generate_anomalous_traffic.py` | 生成异常网络流量 | `anomalous_traffic.pcap` |
| `generate_file_tampering_traffic.py` | 生成文件篡改流量 | `file_tampering.pcap` |
| `generate_http_brute_force_traffic.py` | 生成HTTP暴力破解流量 | `http_brute_force.pcap` |
| `generate_file_hijacking_traffic.py` | 生成文件劫持流量 | `file_hijacking.pcap` |

使用方法：
```shell
# 进入scripts目录
cd scripts

# 运行生成脚本
python generate_anomalous_traffic.py
python generate_file_tampering_traffic.py
python generate_http_brute_force_traffic.py
python generate_file_hijacking_traffic.py

# 生成的pcap文件位于 pcaps 目录
```

## File Extraction API

Use `outputDir` for HTTP/gRPC requests. `EXTRACTED_FILE_PATH` is only the internal Zeek script environment variable used when Zeek runs the extraction script.

```shell
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: your-token-here" \
  -d '{
    "pcapPath": "/opt/zeek_runner/pcaps/ext_111_test.pcap",
    "scriptPath": "/opt/zeek_runner/file_extract_script/extract_file.zeek",
    "outputDir": "/opt/zeek_runner/extracted/ext_111_test",
    "extractedFileMinSize": 0,
    "extractedFileMaxSize": 20,
    "uuid": "test-file-extract",
    "taskID": "test_file_extract",
    "pcapID": "pcap-ext-001"
  }' \
  http://localhost:8000/api/v1/extract
```
