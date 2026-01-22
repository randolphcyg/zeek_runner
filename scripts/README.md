
### detect_dns_flood.zeek

```shell
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "pcapPath": "/zeek_runner/pcaps/amp.dns.RRSIG.fragmented.pcap",
    "scriptPath": "/zeek_runner/scripts/detect_dns_flood.zeek",
    "onlyNotice": true,
    "uuid": "test-detect_dns_flood",
    "taskID": "11111"
  }' \
  http://localhost:8000/api/v1/analyze
```

### detect_http_cmd_injection.zeek

```shell
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "pcapPath": "/zeek_runner/pcaps/exploit.pcap",
    "scriptPath": "/zeek_runner/scripts/detect_http_cmd_injection.zeek",
    "onlyNotice": true,
    "uuid": "test-detect_http_cmd_injection",
    "taskID": "22222"
  }' \
  http://localhost:8000/api/v1/analyze
```

### detect_http_flood.zeek

```shell
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "pcapPath": "/zeek_runner/pcaps/HTTPDoSNovember2021.pcapng",
    "scriptPath": "/zeek_runner/scripts/detect_http_flood.zeek",
    "onlyNotice": true,
    "uuid": "test-detect_http_flood",
    "taskID": "333333"
  }' \
  http://localhost:8000/api/v1/analyze
```

### detect_http_suspicious_ua.zeek

```shell
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "pcapPath": "/zeek_runner/pcaps/ua.pcap",
    "scriptPath": "/zeek_runner/scripts/detect_http_suspicious_ua.zeek",
    "onlyNotice": true,
    "uuid": "test-detect_http_suspicious_ua",
    "taskID": "44444"
  }' \
  http://localhost:8000/api/v1/analyze
```

### detect_http_webshell.zeek

```shell
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "pcapPath": "/zeek_runner/pcaps/BTLOPortScan.pcap",
    "scriptPath": "/zeek_runner/scripts/detect_http_webshell.zeek",
    "onlyNotice": true,
    "uuid": "test-detect_http_webshell",
    "taskID": "555555"
  }' \
  http://localhost:8000/api/v1/analyze
```

### detect_ssh_bruteforce.zeek

```shell
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "pcapPath": "/zeek_runner/pcaps/sshguess.pcap",
    "scriptPath": "/zeek_runner/scripts/detect_ssh_bruteforce.zeek",
    "onlyNotice": true,
    "uuid": "test-detect_ssh_bruteforce",
    "taskID": "666666"
  }' \
  http://localhost:8000/api/v1/analyze
```

### detect_ssh_file_transfer.zeek

```shell
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "pcapPath": "/zeek_runner/pcaps/scp.pcapng",
    "scriptPath": "/zeek_runner/scripts/detect_ssh_file_transfer.zeek",
    "onlyNotice": true,
    "uuid": "test-detect_ssh_file_transfer",
    "taskID": "77777777"
  }' \
  http://localhost:8000/api/v1/analyze
```

### detect_syn_flood.zeek

```shell
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "pcapPath": "/zeek_runner/pcaps/SYNflood.pcap",
    "scriptPath": "/zeek_runner/scripts/detect_syn_flood.zeek",
    "onlyNotice": true,
    "uuid": "test-detect_syn_flood",
    "taskID": "8888888"
  }' \
  http://localhost:8000/api/v1/analyze
```

### detect_slammer_worm.zeek

```shell
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "pcapPath": "/zeek_runner/pcaps/slammer.pcap",
    "scriptPath": "/zeek_runner/scripts/detect_slammer_worm.zeek",
    "onlyNotice": true,
    "uuid": "test-detect_slammer_worm",
    "taskID": "100000"
  }' \
  http://localhost:8000/api/v1/analyze
```

### detect_sqli_webshell.zeek

```shell
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "pcapPath": "/zeek_runner/pcaps/dvwa-sqli-writeWebShell.pcap",
    "scriptPath": "/zeek_runner/scripts/detect_sqli_webshell.zeek",
    "onlyNotice": true,
    "uuid": "test-detect_sqli_webshell",
    "taskID": "999999"
  }' \
  http://localhost:8000/api/v1/analyze
```