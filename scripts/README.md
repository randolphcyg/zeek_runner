## Script metadata

Detection scripts should declare zeek_runner metadata as comments, not Zeek
globals. Do not add `const SCRIPT_ID = "...";` to scripts that may run in a
batch, because multiple scripts loaded by one Zeek process share the global
namespace.

```zeek
# SCRIPT_ID: DETECT_EXAMPLE_v1
# NoticeTypes: ExampleModule::Example_Notice
# 行为类型：示例行为
# 行为分类：示例分类
# 行为描述：示例检测描述
# 攻击特征：示例攻击特征

@load base/frameworks/notice

module ExampleModule;

export {
    redef enum Notice::Type += { Example_Notice };
}
```

Scripts that cannot be uniquely attributed by notice type should use
`# BatchMode: disabled` and run as single-script tasks until they can declare a
stable `# NoticeTypes:` mapping.

### detect_dns_flood.zeek

```shell
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: your-token-here" \
  -d '{
    "pcapPath": "/opt/zeek_runner/pcaps/dns_flood_test.pcap",
    "scriptPath": "/opt/zeek_runner/scripts/detect_dns_flood.zeek",
    "onlyNotice": true,
    "uuid": "test-detect_dns_flood",
    "taskID": "11111",
    "pcapID": "pcap-dns-flood",
    "scriptID": "script-detect-dns-flood"
  }' \
  http://localhost:18080/api/v1/analyze
```

### detect_http_cmd_injection.zeek

```shell
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: your-token-here" \
  -d '{
    "pcapPath": "/opt/zeek_runner/pcaps/http_cmd_injection_test.pcap",
    "scriptPath": "/opt/zeek_runner/scripts/detect_http_cmd_injection.zeek",
    "onlyNotice": true,
    "uuid": "test-detect_http_cmd_injection",
    "taskID": "22222",
    "pcapID": "pcap-http-cmd-injection",
    "scriptID": "script-detect-http-cmd-injection"
  }' \
  http://localhost:18080/api/v1/analyze
```

### detect_http_flood.zeek

```shell
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: your-token-here" \
  -d '{
    "pcapPath": "/opt/zeek_runner/pcaps/http_flood_test.pcap",
    "scriptPath": "/opt/zeek_runner/scripts/detect_http_flood.zeek",
    "onlyNotice": true,
    "uuid": "test-detect_http_flood",
    "taskID": "333333",
    "pcapID": "pcap-http-flood",
    "scriptID": "script-detect-http-flood"
  }' \
  http://localhost:18080/api/v1/analyze
```

### detect_http_suspicious_ua.zeek

```shell
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: your-token-here" \
  -d '{
    "pcapPath": "/opt/zeek_runner/pcaps/http_suspicious_ua_test.pcap",
    "scriptPath": "/opt/zeek_runner/scripts/detect_http_suspicious_ua.zeek",
    "onlyNotice": true,
    "uuid": "test-detect_http_suspicious_ua",
    "taskID": "44444",
    "pcapID": "pcap-http-suspicious-ua",
    "scriptID": "script-detect-http-suspicious-ua"
  }' \
  http://localhost:18080/api/v1/analyze
```

### detect_http_webshell.zeek

```shell
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: your-token-here" \
  -d '{
    "pcapPath": "/opt/zeek_runner/pcaps/http_webshell_test.pcap",
    "scriptPath": "/opt/zeek_runner/scripts/detect_http_webshell.zeek",
    "onlyNotice": true,
    "uuid": "test-detect_http_webshell",
    "taskID": "555555",
    "pcapID": "pcap-http-webshell",
    "scriptID": "script-detect-http-webshell"
  }' \
  http://localhost:18080/api/v1/analyze
```

### detect_ssh_bruteforce.zeek

```shell
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: your-token-here" \
  -d '{
    "pcapPath": "/opt/zeek_runner/pcaps/ssh_bruteforce_test.pcap",
    "scriptPath": "/opt/zeek_runner/scripts/detect_ssh_bruteforce.zeek",
    "onlyNotice": true,
    "uuid": "test-detect_ssh_bruteforce",
    "taskID": "666666",
    "pcapID": "pcap-ssh-bruteforce",
    "scriptID": "script-detect-ssh-bruteforce"
  }' \
  http://localhost:18080/api/v1/analyze
```

### detect_ssh_file_transfer.zeek

```shell
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: your-token-here" \
  -d '{
    "pcapPath": "/opt/zeek_runner/pcaps/ssh_file_transfer_test.pcap",
    "scriptPath": "/opt/zeek_runner/scripts/detect_ssh_file_transfer.zeek",
    "onlyNotice": true,
    "uuid": "test-detect_ssh_file_transfer",
    "taskID": "77777777",
    "pcapID": "pcap-ssh-file-transfer",
    "scriptID": "script-detect-ssh-file-transfer"
  }' \
  http://localhost:18080/api/v1/analyze
```

### detect_syn_flood.zeek

```shell
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: your-token-here" \
  -d '{
    "pcapPath": "/opt/zeek_runner/pcaps/syn_flood_test.pcap",
    "scriptPath": "/opt/zeek_runner/scripts/detect_syn_flood.zeek",
    "onlyNotice": true,
    "uuid": "test-detect_syn_flood",
    "taskID": "8888888",
    "pcapID": "pcap-syn-flood",
    "scriptID": "script-detect-syn-flood"
  }' \
  http://localhost:18080/api/v1/analyze
```

### detect_slammer_worm.zeek

```shell
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: your-token-here" \
  -d '{
    "pcapPath": "/opt/zeek_runner/pcaps/slammer_worm_test.pcap",
    "scriptPath": "/opt/zeek_runner/scripts/detect_slammer_worm.zeek",
    "onlyNotice": true,
    "uuid": "test-detect_slammer_worm",
    "taskID": "100000",
    "pcapID": "pcap-slammer-worm",
    "scriptID": "script-detect-slammer-worm"
  }' \
  http://localhost:18080/api/v1/analyze
```

### detect_sqli_webshell.zeek

```shell
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: your-token-here" \
  -d '{
    "pcapPath": "/opt/zeek_runner/pcaps/sqli_webshell_test.pcap",
    "scriptPath": "/opt/zeek_runner/scripts/detect_sqli_webshell.zeek",
    "onlyNotice": true,
    "uuid": "test-detect_sqli_webshell",
    "taskID": "999999",
    "pcapID": "pcap-sqli-webshell",
    "scriptID": "script-detect-sqli-webshell"
  }' \
  http://localhost:18080/api/v1/analyze
```

### detect_anomalous_traffic.zeek

检测异常网络流量，使用 `generate_anomalous_traffic.py` 生成测试流量包：

```shell
# 1. 生成测试流量包
python scripts/generate_anomalous_traffic.py
# 输出: anomalous_traffic_test.pcap (约4MB，包含2000个2000字节数据包)

# 2. 测试脚本
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: your-token-here" \
  -d '{
    "pcapPath": "/opt/zeek_runner/pcaps/anomalous_traffic_test.pcap",
    "scriptPath": "/opt/zeek_runner/scripts/detect_anomalous_traffic.zeek",
    "onlyNotice": true,
    "uuid": "test-detect_anomalous_traffic",
    "taskID": "test_anomalous_traffic",
    "pcapID": "pcap-anomalous-traffic",
    "scriptID": "script-detect-anomalous-traffic"
  }' \
  http://localhost:18080/api/v1/analyze
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
    "pcapPath": "/opt/zeek_runner/pcaps/file_tampering_test.pcap",
    "scriptPath": "/opt/zeek_runner/scripts/detect_file_tampering.zeek",
    "onlyNotice": true,
    "uuid": "test-detect_file_tampering",
    "taskID": "test_file_tampering",
    "pcapID": "pcap-file-tampering",
    "scriptID": "script-detect-file-tampering"
  }' \
  http://localhost:18080/api/v1/analyze
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
    "pcapPath": "/opt/zeek_runner/pcaps/http_bruteforce_test.pcap",
    "scriptPath": "/opt/zeek_runner/scripts/detect_http_brute_force.zeek",
    "onlyNotice": true,
    "uuid": "test-detect_http_brute_force",
    "taskID": "test_http_brute_force",
    "pcapID": "pcap-http-brute-force",
    "scriptID": "script-detect-http-brute-force"
  }' \
  http://localhost:18080/api/v1/analyze
```

### detect_http_cmd_injection.zeek

检测HTTP命令注入攻击：

```shell
# 测试脚本
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: your-token-here" \
  -d '{
    "pcapPath": "/opt/zeek_runner/pcaps/http_cmd_injection_test.pcap",
    "scriptPath": "/opt/zeek_runner/scripts/detect_http_cmd_injection.zeek",
    "onlyNotice": true,
    "uuid": "test-detect_http_cmd_injection",
    "taskID": "22222",
    "pcapID": "pcap-http-cmd-injection",
    "scriptID": "script-detect-http-cmd-injection"
  }' \
  http://localhost:18080/api/v1/analyze
```

## 流量包生成脚本

项目提供了以下流量包生成脚本，用于测试对应的检测脚本：

| 生成脚本 | 用途 | 生成的流量包 |
|---------|------|-------------|
| `generate_anomalous_traffic.py` | 生成异常网络流量 | `anomalous_traffic_test.pcap` |
| `generate_file_tampering_traffic.py` | 生成文件篡改流量 | `file_tampering_test.pcap` |
| `generate_http_brute_force_traffic.py` | 生成HTTP暴力破解流量 | `http_bruteforce_test.pcap` |
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
    "pcapPath": "/opt/zeek_runner/pcaps/file_extract_test.pcap",
    "scriptPath": "/opt/zeek_runner/file_extract_script/extract_file.zeek",
    "outputDir": "/opt/zeek_runner/extracted/file_extract_test",
    "extractedFileMinSize": 0,
    "extractedFileMaxSize": 20,
    "uuid": "test-file-extract",
    "taskID": "test_file_extract",
    "pcapID": "pcap-ext-001"
  }' \
  http://localhost:18080/api/v1/extract
```

## Offline validation matrix

Small deterministic PCAPs are stored under `pcaps/` and can be regenerated with:

```shell
python3 scripts/test/generate_offline_test_pcaps.py
```

| Behavior | Script | Test pcap | Main signal | Notes |
|----------|--------|-----------|-------------|-------|
| Anomalous traffic | `detect_anomalous_traffic.zeek` | `anomalous_traffic_test.pcap` | `Anomalous_Traffic_Detected` | Default threshold is 4 MB per source in the pcap. |
| Bulk download | `detect_bulk_download.zeek` | `bulk_download_test.pcap` | `Bulk_Download_Detected` | Counts repeated archive/binary downloads. |
| DNS Flood / ANY | `detect_dns_flood.zeek` | `dns_flood_test.pcap` | `DNS_Query_Flood`, `DNS_Amplification_ANY` | Thresholds are `FLOOD_THRESHOLD`, `ANY_THRESHOLD`, `CHECK_INTERVAL`. |
| File tampering | `detect_file_tampering.zeek` | `file_tampering_test.pcap` | `File_Tampering_Detected` | Flags critical path access and suspicious file paths. |
| Firmware download hijack | `detect_firmware_download_hijack.zeek` | `firmware_download_hijack_test.pcap` | `Firmware_Replacement_Suspected`, `Firmware_Redirect_Hijack` | Flags insecure firmware download, suspicious source, redirect hijack, and changed response traits for the same firmware URL. |
| Firmware upgrade hijack | `detect_firmware_upgrade_hijack.zeek` | `firmware_upgrade_hijack_test.pcap` | `Firmware_Manifest_Hijack`, `Firmware_Rollback_Suspected` | Flags OTA/upgrade endpoint access, insecure manifest URLs, missing signature/hash, rollback, and firmware upload. |
| HTTP brute force | `detect_http_brute_force.zeek` | `http_bruteforce_test.pcap` | `HTTP_Brute_Force_Detected` | Counts login requests that receive 401/403 responses. |
| HTTP command injection | `detect_http_cmd_injection.zeek` | `http_cmd_injection_test.pcap` | command injection notice | Checks request URI payloads. |
| HTTP flood | `detect_http_flood.zeek` | `http_flood_test.pcap` | `HTTP_Flood_Detected` | Request threshold is `&redef`. |
| Suspicious UA | `detect_http_suspicious_ua.zeek` | `http_suspicious_ua_test.pcap` | suspicious UA notice | Checks scanners and scripted clients. |
| HTTP webshell | `detect_http_webshell.zeek` | `http_webshell_test.pcap` | webshell upload notice | Checks multipart upload filenames and content. |
| Intel hit | `detect_intel_feed_hit.zeek` | `intel_hit_test.pcap` | `intel.log`, detection hit | Matching is implemented by `custom/offline/intel_replay.zeek`. |
| Slammer worm | `detect_slammer_worm.zeek` | `slammer_worm_test.pcap` | Slammer notice | UDP/1434 payload signature. |
| SQLi webshell | `detect_sqli_webshell.zeek` | `sqli_webshell_test.pcap` | SQLi/webshell notice | Checks SQLi into outfile style payloads. |
| SSH brute force | `detect_ssh_bruteforce.zeek` | `ssh_bruteforce_test.pcap` | `SSH::Password_Guessing` | Uses Zeek SSH bruteforce policy. |
| SSH file transfer | `detect_ssh_file_transfer.zeek` | `ssh_file_transfer_test.pcap` | `Suspicious_SCP_Transfer` | Flags authenticated or port-22 bulk transfer over threshold. |
| SYN Flood | `detect_syn_flood.zeek` | `syn_flood_test.pcap` | `SynFlood::SynFlood` | `syn_flood_threshold` and `check_interval` are `&redef`. |
| File extraction | `file_extract_script/extract_file.zeek` | `file_extract_test.pcap` | extracted `firmware.bin` | Uses `custom/config_extract.zeek` and size env vars. |

The detection scripts no longer emit debug `print` output or synthetic notices. For small lab pcaps, override `&redef` thresholds in a wrapper script instead of lowering production defaults in the detector itself.
