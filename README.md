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
docker pull golang:1.26-alpine --platform linux/amd64
docker pull zeek/zeek:8.1.1 --platform linux/amd64

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
  -e ZEEK_TIMEOUT_MINUTES=10 \
  -e RATE_LIMIT=2000 \
  -e RATE_LIMIT_WINDOW=60 \
  -e AUTH_TOKENS="token1,token2" \
  -v /opt/zeek_runner/scripts:/opt/zeek_runner/scripts \
  -v /opt/zeek_runner/pcaps:/opt/zeek_runner/pcaps \
  -v /path/for/save/extracted/files:/path/for/save/extracted/files \
  -v /opt/zeek_runner/custom/config.zeek:/usr/local/zeek/share/zeek/base/custom/config.zeek \
  zeek_runner:latest
```

#### 环境变量说明

| 环境变量                    | 默认值  | 说明                         |
|-------------------------|------|----------------------------|
| `ZEEK_CONCURRENT_TASKS` | 8    | 并发任务数                      |
| `ZEEK_TIMEOUT_MINUTES`  | 5    | 任务超时时间（分钟）                 |
| `KAFKA_BROKERS`         | -    | Kafka 地址                   |
| `REDIS_ADDR`            | -    | Redis 地址（异步任务必需） |
| `REDIS_PASSWORD`        | -    | Redis 密码                   |
| `REDIS_DB`              | 0    | Redis 数据库编号               |
| `RATE_LIMIT`            | 1000 | 限流请求数（每时间窗口）               |
| `RATE_LIMIT_WINDOW`     | 60   | 限流时间窗口（秒）                  |
| `AUTH_TOKENS`           | -    | 认证 Token 列表（逗号分隔），为空则不启用认证 |
| `CONFIG_FILE`           | -    | 配置文件路径（优先级高于环境变量） |

### 配置文件

支持 YAML 格式配置文件，**优先级高于环境变量**，适合生产环境部署：

#### 配置文件示例

```yaml
redis:
  addr: "redis:6379"
  password: "your-secure-password"
  db: 0

kafka:
  brokers: "192.168.2.6:9092"

pool:
  size: 16
  timeoutMinutes: 10

rateLimit:
  limit: 2000
  window: 60

auth:
  tokens:
    - "token1-change-me"
    - "token2-change-me"

server:
  http: ":8000"
  grpc: ":50051"
```

#### 使用配置文件

```shell
# 方式一：通过环境变量指定配置文件路径
docker run -d \
  --name zeek_runner \
  -e CONFIG_FILE="/opt/zeek_runner/config.yaml" \
  -v /opt/zeek_runner/config.yaml:/opt/zeek_runner/config.yaml \
  zeek_runner:latest

# 方式二：使用默认路径（自动检测）
# 服务会按顺序检测以下路径：
# 1. /etc/zeek_runner/config.yaml
# 2. /opt/zeek_runner/config.yaml
# 3. ./config.yaml
# 4. ./config/config.yaml
docker run -d \
  --name zeek_runner \
  -v /opt/zeek_runner/config.yaml:/opt/zeek_runner/config.yaml \
  zeek_runner:latest
```

#### 配置优先级

```
配置文件 > 环境变量 > 默认值
```

#### 安全建议

- **Redis 密码**：使用配置文件而非环境变量，避免密码泄露
- **配置文件权限**：设置 `chmod 600 config.yaml` 限制访问
- **Docker Secrets**：生产环境建议使用 Docker Secrets 或 Kubernetes Secrets

### 异步任务模式

服务支持两种任务执行模式：

#### 同步模式（默认）
- 上层服务下发任务后等待执行完成
- 适合实时性要求高、任务执行时间短的场景

#### 异步模式（需要 Redis）
- 上层服务下发任务后立即返回任务ID
- 服务后台执行任务，上层服务通过任务ID查询状态
- 适合批量任务、长时间执行任务的场景

```shell
# 启用异步模式需要配置 Redis
docker run -d \
  --name zeek_runner \
  -e REDIS_ADDR="redis:6379" \
  -e KAFKA_BROKERS="192.168.2.6:9092" \
  ... \
  zeek_runner:latest
```

### 文件提取去重

服务采用**双层去重架构**，最大化节省存储和 IO：

#### 架构设计

```
┌─────────────────────────────────────────────────────────────────┐
│  Zeek 层（任务内去重）                                            │
│  • 同一任务内相同 hash 文件只提取一次                               │
│  • 后续重复文件跳过提取，只记录元数据到 Kafka                        │
│  • 输出日志：DUPLICATE_IN_TASK: hash=xxx count=2                 │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  Go 层（跨任务去重，需要 Redis）                                   │
│  • 不同任务间相同 hash 文件只保留一份                               │
│  • 删除重复文件，更新 Redis 引用计数                                │
│  • 输出日志：duplicate file removed hash=xxx refCount=3          │
└─────────────────────────────────────────────────────────────────┘
```

#### 工作流程

**Zeek 层（任务内）**：
1. 文件开始提取时计算 SHA256 哈希
2. 检查任务内哈希表是否已存在
3. 如果存在：跳过提取，记录 `DUPLICATE_IN_TASK` 日志
4. 如果不存在：提取文件，注册哈希到任务表

**Go 层（跨任务）**：
1. Zeek 任务完成后，扫描提取目录
2. 计算每个文件的 SHA256 哈希
3. 查询 Redis 检查哈希是否已存在
4. 如果存在：删除文件，增加引用计数
5. 如果不存在：注册新文件到 Redis

#### 优势对比

| 场景 | 无去重 | Zeek 层去重 | 双层去重 |
|------|--------|-------------|----------|
| 任务内 100 次相同文件 | 提取 100 个 | 提取 1 个 | 提取 1 个 |
| 跨任务 10 次相同文件 | 提取 10 个 | 提取 10 个 | 提取 1 个 |
| 存储 IO | 100% | 1% | 1% |
| 持久化存储 | 100% | 100% | 1% |

#### 日志示例

```
# Zeek 层日志
FILE_EXTRACTED: file=malware.exe size=1024000 hash=abc123... mime=application/x-dosexec
DUPLICATE_IN_TASK: hash=abc123... task=task-001 count=2 existing=/path/malware.exe
TASK_SUMMARY: task=task-001 unique_files=5 total_duplicates=95

# Go 层日志
new file registered: file=malware.exe hash=abc123... size=1024000
duplicate file removed: file=malware.exe hash=abc123... original=/path/malware.exe refCount=2
```

#### 前置服务消费 Kafka

前置服务消费 Kafka 时可根据 hash 字段判断：

```json
{
  "ts": 1712138400.0,
  "id": {
    "orig_h": "192.168.1.100",
    "resp_h": "10.0.0.1"
  },
  "fuid": "Fabc123",
  "file": {
    "extracted": "/path/to/file.exe",
    "sha256": "abc123def456...",
    "mime_type": "application/x-dosexec"
  }
}
```

**处理逻辑**：
1. 检查 `file.extracted` 是否以 `DUPLICATE:` 开头
2. 如果是重复文件，使用 hash 查询已存在的文件路径
3. 如果是新文件，正常处理并记录 hash

### 配置热更新

服务支持通过 `SIGHUP` 信号进行配置热更新，无需重启服务：

```shell
# 更新环境变量后，发送信号重载配置
kill -HUP <pid>

# 或使用 docker
docker exec zeek_runner kill -HUP 1
```

**支持热更新的配置项**：
- `AUTH_TOKENS` - 认证令牌（立即生效）
- `RATE_LIMIT` - 限流阈值（新请求生效）
- `RATE_LIMIT_WINDOW` - 限流窗口（新请求生效）

**注意**：`ZEEK_CONCURRENT_TASKS`、`ZEEK_TIMEOUT_MINUTES` 和 `KAFKA_BROKERS` 需要重启服务才能生效。

### 测试

#### HTTP 接口测试

```shell
# 健康检查（无需认证）
curl http://localhost:8000/api/v1/healthz

# Prometheus 指标（无需认证）
curl http://localhost:8000/metrics

# 调用 /api/v1/version/zeek 接口（需要 User-Agent，配置 AUTH_TOKENS 后还需 Authorization）
curl -H "User-Agent: test" -H "Authorization: your-token" http://localhost:8000/api/v1/version/zeek

# 调用 /api/v1/version/zeek-kafka 接口
curl -H "User-Agent: test" -H "Authorization: your-token" http://localhost:8000/api/v1/version/zeek-kafka

# 测试检测恶意行为发送到kafka 仅notice日志
curl -X POST \
  -H "Content-Type: application/json" \
  -H "User-Agent: test" \
  -H "Authorization: your-token" \
  -d '{
    "pcapPath": "/opt/zeek_runner/pcaps/sshguess.pcap",
    "scriptPath": "/opt/zeek_runner/scripts/detect_ssh_bruteforce.zeek",
    "onlyNotice": true,
    "uuid": "d3db5f67-c441-56a4-9591-c30c3abab24f",
    "taskID": "2333",
    "pcapID": "pcap-001",
    "scriptID": "script-001"
  }' \
  http://localhost:8000/api/v1/analyze

# 异步分析接口（需要 Redis）- 立即返回任务ID
curl -X POST \
  -H "Content-Type: application/json" \
  -H "User-Agent: test" \
  -H "Authorization: your-token" \
  -d '{
    "pcapPath": "/opt/zeek_runner/pcaps/sshguess.pcap",
    "scriptPath": "/opt/zeek_runner/scripts/detect_ssh_bruteforce.zeek",
    "onlyNotice": true,
    "uuid": "d3db5f67-c441-56a4-9591-c30c3abab24f",
    "taskID": "2333",
    "pcapID": "pcap-001",
    "scriptID": "script-001"
  }' \
  http://localhost:8000/api/v1/analyze/async

# 查询任务状态
curl -H "User-Agent: test" -H "Authorization: your-token" \
  http://localhost:8000/api/v1/task/2333
  
# 所有日志除notice
curl -X POST \
  -H "Content-Type: application/json" \
  -H "User-Agent: test" \
  -H "Authorization: your-token" \
  -d '{
    "pcapPath": "/opt/zeek_runner/pcaps/sshguess.pcap",
    "scriptPath": "/opt/zeek_runner/scripts/detect_ssh_bruteforce.zeek",
    "onlyNotice": false,
    "uuid": "d3db5f67-c441-56a4-9591-c30c3abab24f",
    "taskID": "1212",
    "pcapID": "pcap-001",
    "scriptID": "script-001"
  }' \
  http://localhost:8000/api/v1/analyze

# Zeek 脚本语法检查 - 通过文件路径
curl -X POST \
  -H "Content-Type: application/json" \
  -H "User-Agent: test" \
  -H "Authorization: your-token" \
  -d '{
    "scriptPath": "/opt/zeek_runner/scripts/detect_ssh_bruteforce.zeek"
  }' \
  http://localhost:8000/api/v1/syntax-check

# Zeek 脚本语法检查 - 通过脚本内容
curl -X POST \
  -H "Content-Type: application/json" \
  -H "User-Agent: test" \
  -H "Authorization: your-token" \
  -d '{
    "scriptContent": "event connection_new(c: connection) { print c$id; }"
  }' \
  http://localhost:8000/api/v1/syntax-check
```

#### gRPC 接口测试

使用 `grpcurl` 工具进行测试（需要安装 grpcurl）：

```shell
# 安装 grpcurl
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

# 查看服务列表
grpcurl -plaintext localhost:50051 list

# 查看服务方法
grpcurl -plaintext localhost:50051 describe zeek_runner.ZeekAnalysisService

# 健康检查（需要 user-agent）
grpcurl -plaintext -H 'user-agent: test' localhost:50051 zeek_runner.ZeekAnalysisService/HealthCheck

# 如果配置了 AUTH_TOKENS，需要携带 authorization 头
grpcurl -plaintext -H 'user-agent: test' -H 'authorization: your-token' localhost:50051 zeek_runner.ZeekAnalysisService/HealthCheck

# 版本检查 - zeek
grpcurl -plaintext -H 'user-agent: test' -H 'authorization: your-token' -d '{"component": "zeek"}' localhost:50051 zeek_runner.ZeekAnalysisService/VersionCheck

# 版本检查 - zeek-kafka
grpcurl -plaintext -H 'user-agent: test' -H 'authorization: your-token' -d '{"component": "zeek-kafka"}' localhost:50051 zeek_runner.ZeekAnalysisService/VersionCheck

# 调用 zeek 分析 pcap
grpcurl -plaintext -H 'user-agent: test' -H 'authorization: your-token' -d '{
  "taskID": "2333",
  "uuid": "d3db5f67-c441-56a4-9591-c30c3abab24f",
  "onlyNotice": true,
  "pcapID": "pcap-001",
  "pcapPath": "/opt/zeek_runner/pcaps/sshguess.pcap",
  "scriptID": "script-001",
  "scriptPath": "/opt/zeek_runner/scripts/detect_ssh_bruteforce.zeek"
}' localhost:50051 zeek_runner.ZeekAnalysisService/Analyze

# 异步分析接口（需要 Redis）- 立即返回任务ID
grpcurl -plaintext -H 'user-agent: test' -H 'authorization: your-token' -d '{
  "taskID": "2334",
  "uuid": "d3db5f67-c441-56a4-9591-c30c3abab24f",
  "onlyNotice": true,
  "pcapID": "pcap-001",
  "pcapPath": "/opt/zeek_runner/pcaps/sshguess.pcap",
  "scriptID": "script-001",
  "scriptPath": "/opt/zeek_runner/scripts/detect_ssh_bruteforce.zeek"
}' localhost:50051 zeek_runner.ZeekAnalysisService/AsyncAnalyze

# 查询任务状态
grpcurl -plaintext -H 'user-agent: test' -H 'authorization: your-token' -d '{
  "taskID": "2334"
}' localhost:50051 zeek_runner.ZeekAnalysisService/GetTaskStatus

# Zeek 脚本语法检查 - 通过文件路径
grpcurl -plaintext -H 'user-agent: test' -H 'authorization: your-token' -d '{
  "script_path": "/opt/zeek_runner/scripts/detect_ssh_bruteforce.zeek"
}' localhost:50051 zeek_runner.ZeekAnalysisService/ZeekSyntaxCheck

# Zeek 脚本语法检查 - 通过脚本内容
grpcurl -plaintext -H 'user-agent: test' -H 'authorization: your-token' -d '{
  "script_content": "event connection_new(c: connection) { print c$id; }"
}' localhost:50051 zeek_runner.ZeekAnalysisService/ZeekSyntaxCheck
```

#### 使用 Go 客户端测试 gRPC

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
    "google.golang.org/grpc/metadata"
    pb "zeek_runner/api/pb"
)

func main() {
    conn, err := grpc.NewClient("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
    if err != nil {
        log.Fatalf("did not connect: %v", err)
    }
    defer conn.Close()

    client := pb.NewZeekAnalysisServiceClient(conn)
    
    // 创建带有认证信息的 context
    ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
    defer cancel()
    
    // 添加认证元数据
    md := metadata.New(map[string]string{
        "user-agent":    "go-client",
        "authorization": "your-token", // 如果配置了 AUTH_TOKENS
    })
    ctx = metadata.NewOutgoingContext(ctx, md)

    // 版本检查
    versionResp, err := client.VersionCheck(ctx, &pb.VersionCheckRequest{Component: "zeek"})
    if err != nil {
        log.Fatalf("could not check version: %v", err)
    }
    fmt.Printf("Zeek Version: %s\n", versionResp.Version)

    // 语法检查
    syntaxResp, err := client.ZeekSyntaxCheck(ctx, &pb.ZeekSyntaxCheckRequest{
        ScriptContent: "event connection_new(c: connection) { print c$id; }",
    })
    if err != nil {
        log.Fatalf("could not check syntax: %v", err)
    }
    fmt.Printf("Syntax Valid: %v\n", syntaxResp.Valid)

    // 分析 pcap
    analyzeResp, err := client.Analyze(ctx, &pb.AnalyzeRequest{
        TaskID:     "test-001",
        Uuid:       "test-uuid-001",
        OnlyNotice: true,
        PcapID:     "pcap-001",
        PcapPath:   "/opt/zeek_runner/pcaps/sshguess.pcap",
        ScriptID:   "script-001",
        ScriptPath: "/opt/zeek_runner/scripts/detect_ssh_bruteforce.zeek",
    })
    if err != nil {
        log.Fatalf("could not analyze: %v", err)
    }
    fmt.Printf("Analyze Response: %+v\n", analyzeResp)
}
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

## 单元测试

项目包含完整的单元测试覆盖核心逻辑：

```shell
# 运行所有单元测试
go test -v ./...

# 运行测试并显示覆盖率
go test -cover ./...

# 生成覆盖率报告
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
```

### 测试覆盖范围

| 测试文件 | 覆盖内容 |
|---------|---------|
| `config_test.go` | 配置管理、环境变量解析、并发访问 |
| `middleware_test.go` | 限流器逻辑、热更新参数、并发安全 |
| `handler_http_test.go` | HTTP 请求验证、参数校验、路径安全 |
| `handler_grpc_test.go` | gRPC 请求验证、参数校验 |
| `integration_test.go` | 集成测试（需要 Zeek 环境） |

### 集成测试

集成测试需要安装 Zeek 环境：

```shell
# 运行集成测试
go test -v -tags=integration ./...

# 在 Docker 容器中运行集成测试
docker exec zeek_runner go test -v -tags=integration ./...
```

集成测试会验证：
- 所有检测脚本的语法正确性
- Zeek 版本获取功能
- 脚本语法检查功能