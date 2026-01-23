# zeek + zeek-kafka + kafka = zeek_runner

## 依赖说明
```shell
# 验证 zeek-kafka 插件安装
RUN zeek -N Seiso::Kafka
# Seiso::Kafka - Writes logs to Kafka (dynamic, version 0.3.0)
# 显示0.3.0 是因为zeek-kafka库没有更改那个显示版本 实际上是新版本了

# 基于Seiso/Kafka release 1.2.0 增加支持kafka key和header的写入 额外字段不用加在数据中
https://github.com/randolphcyg/zeek-kafka/
```

## docker部署

#### 构建

```shell
# 更新proto
运行Makefile即可

# 基础镜像
docker pull golang:1.25-alpine --platform linux/amd64
docker pull zeek/zeek:8.1.0 --platform linux/amd64

docker build -t zeek_runner:latest . --platform linux/amd64
# 指定国内仓库
docker build --build-arg APT_MIRROR=http://mirrors.aliyun.com -t zeek_runner:latest . --platform linux/amd64
# 容器导出
docker save zeek_runner:latest  | gzip > zeek_runner.tar.gz
# 解压镜像
docker load -i zeek_runner.tar.gz
```

#### 运行

```shell
docker run -d \
  --name zeek_runner \
  -p 8000:8000 \
  -p 50051:50051 \
  -e KAFKA_BROKERS="192.168.2.6:9092" \
  -e ZEEK_CONCURRENT_TASKS=16 \
  -v /opt/zeek_runner/scripts:/opt/zeek_runner/scripts \
  -v /opt/zeek_runner/pcaps:/opt/zeek_runner/pcaps \
  -v /path/for/save/extracted/files:/path/for/save/extracted/files \
  -v /opt/zeek_runner/custom/config.zeek:/usr/local/zeek/share/zeek/base/custom/config.zeek \
  zeek_runner:latest
```

### 测试

```shell
# 测试检测恶意行为发送到kafka 仅notice日志
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "pcapPath": "/opt/zeek_runner/pcaps/sshguess.pcap",
    "scriptPath": "/opt/zeek_runner/scripts/detect_ssh_bruteforce.zeek",
    "onlyNotice": true,
    "uuid": "d3db5f67-c441-56a4-9591-c30c3abab24f",
    "taskID": "2333"
  }' \
  http://localhost:8000/api/v1/analyze
  
# 所有日志除notice
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "pcapPath": "/opt/zeek_runner/pcaps/sshguess.pcap",
    "scriptPath": "/opt/zeek_runner/scripts/detect_ssh_bruteforce.zeek",
    "onlyNotice": false,
    "uuid": "d3db5f67-c441-56a4-9591-c30c3abab24f",
    "taskID": "1212"
  }' \
  http://localhost:8000/api/v1/analyze
# 调用 /api/v1/version/zeek 接口
curl http://localhost:8000/api/v1/version/zeek

# 调用 /api/v1/version/zeek-kafka 接口
curl http://localhost:8000/api/v1/version/zeek-kafka
```

### 直接使用本机zeek测试
```shell
##### 测试 kafka 消息、环境变量取值、二次开发zeek-kafka组件功能是否生效
# config.zeek是自定义配置的 包含对kafka配置和消息的设置;本地测试时可以不指定，指定了会将消息发送到kafka,本地不生成log文件
# ONLY_NOTICE=true 环境变量设置为true只发送notice日志 为false发送所有日志(除notice)
# go程序中 config.zeek 不需要上层调用者赋值; 只需要给定pcap文件路径 脚本路径 onlyNotice三个参数;
ONLY_NOTICE=true SCRIPT_PATH=/xx/xx/scripts/detect_ssh_bruteforce.zeek \ 
PCAP_PATH=/xx/xx/pcaps/sshguess.pcap \
zeek -Cr ./pcaps/sshguess.pcap ./config.zeek ./scripts/detect_ssh_bruteforce.zeek

##### 仅本地测试

# SSH暴力破解攻击
zeek -Cr ./pcaps/sshguess.pcap \
./test.zeek ./scripts/detect_ssh_bruteforce.zeek

# DNS洪水攻击/放大攻击
zeek -Cr ./amp.dns.RRSIG.fragmented.pcap \
./test.zeek \
./scripts/detect_dns_flood.zeek

# 恶意User-Agent检测
zeek -Cr ./pcaps/ua.pcap \
./test.zeek \
./scripts/detect_http_suspicious_ua.zeek

# HTTP恶意文件上传(Webshell)
zeek -Cr ./pcaps/BTLOPortScan.pcap \
./test.zeek \
./scripts/detect_http_webshell.zeek

# HTTP拒绝服务攻击(CC攻击)
zeek -Cr ./pcaps/HTTPDoSNovember2021.pcapng \
./test.zeek \
./scripts/detect_http_flood.zeek

# TCP SYN洪水攻击
zeek -Cr ./pcaps/SYNflood.pcap \
./test.zeek \
./scripts/detect_syn_flood.zeek

# SSH异常大文件传输(SCP/SFTP)
zeek -Cr ./pcaps/scp.pcapng \
./test.zeek \
./scripts/detect_ssh_file_transfer.zeek

# Unix命令注入攻击
zeek -Cr ./pcaps/exploit.pcap \
./test.zeek \
./scripts/detect_http_cmd_injection.zeek


## 提取文件模式测试
EXTRACTED_FILE_PATH=/path/for/save/extracted/files \
EXTRACTED_FILE_MIN_SIZE=20 \
zeek -Cr ./file_extract_scripts/xxx.pcap \
./extract_http.zeek

EXTRACTED_FILE_PATH=/path/for/save/extracted/files \
EXTRACTED_FILE_MIN_SIZE=20 \
zeek -Cr ./xxx.pcap \
./extract_http.zeek

curl -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "extractedFilePath": "/path/for/save/extracted/files",
    "extractedFileMinSize": 20,
    "pcapPath": "/opt/zeek_runner/file_extract_scripts/xxx.pcap",
    "scriptPath": "/opt/zeek_runner/file_extract_scripts/extract_http.zeek",
    "uuid": "233",
    "taskID": "122"
  }' \
  http://localhost:8000/api/v1/analyze
```

### docker-compose部署
```shell
docker-compose up -d
docker-compose down
```