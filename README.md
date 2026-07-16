# zeek_runner = zeek + kafka

## docker部署

#### 构建

```shell
# 更新proto
运行Makefile即可

# 使用 build.sh 构建（推荐）
# 默认构建原生架构
./build.sh

# 构建 Ubuntu 24.04 x86_64 (linux/amd64) 镜像
./build.sh --ubuntu
# 默认版本为 5.1，导出的 tar 加载后镜像 tag 为 zeek_runner:5.1

# 构建 Ubuntu 24.04 ARM64 (linux/arm64) 镜像
./build.sh --ubuntu-arm64

# 指定版本号
./build.sh --ubuntu --version 5.1

# 指定国内 apt 仓库
./build.sh --ubuntu --apt-mirror http://mirrors.aliyun.com

# 构建但不导出 tar.gz
./build.sh --ubuntu --no-save

# 清理构建产物
./build.sh --clean

# 查看所有选项
./build.sh --help
```

**手动 docker build（不推荐，建议使用 build.sh）**：

```shell
# 基础镜像
docker pull golang:1.26.5-alpine --platform linux/amd64
docker pull zeek/zeek:8.0.8 --platform linux/amd64

docker pull redis:8-alpine --platform linux/amd64
docker pull nginx:1.28-alpine --platform linux/amd64
docker pull jaegertracing/jaeger:2.17.0 --platform linux/amd64

docker build -t zeek_runner:5.1 . --platform linux/amd64
# 指定国内仓库
docker build --build-arg APT_MIRROR=http://mirrors.aliyun.com -t zeek_runner:5.1 . --platform linux/amd64
# 容器导出
docker save zeek_runner:5.1 | gzip > zeek_runner-5.1-amd64.tar.gz
docker save redis:8-alpine | gzip > redis.tar.gz
docker save nginx:1.28-alpine | gzip > nginx.tar.gz
docker save jaegertracing/jaeger:2.17.0 | gzip > jaeger.tar.gz

docker load -i zeek_runner-5.1-amd64.tar.gz
docker load -i redis.tar.gz
docker load -i nginx.tar.gz
docker load -i jaeger.tar.gz
```

#### 离线部署

适用于无外网的服务器环境，使用 `build.sh` 一键构建并导出镜像：

```shell
# 1. 在有网环境构建并导出镜像
chmod +x build.sh
./build.sh --ubuntu              # 构建 linux/amd64 镜像并导出 tar.gz
./build.sh --ubuntu --version 5.1  # 指定版本号

# 构建产物示例：
# zeek_runner-5.1-amd64.tar.gz   # 加载后镜像 tag 为 zeek_runner:5.1

# 2. 传输到目标服务器
scp zeek_runner-5.1-amd64.tar.gz user@server:/data/zeek_runner/

# 3. 在目标服务器加载镜像
docker load -i zeek_runner-5.1-amd64.tar.gz
# 加载后使用 zeek_runner:5.1 启动，架构信息只保留在 tar 文件名中

# 4. 编辑配置文件（设置 Redis 密码、Kafka 地址等）
sudo vi /data/zeek_runner/config.yaml

# 5. 启动服务
docker compose up -d
```

**其他依赖镜像导出**（如需离线部署 Redis、Nginx、Jaeger）：

```shell
docker save redis:8-alpine | gzip > redis.tar.gz
docker save nginx:1.28-alpine | gzip > nginx.tar.gz
docker save jaegertracing/jaeger:2.17.0 | gzip > jaeger.tar.gz
```

#### 运行

```shell
# 使用配置文件启动（推荐）
docker run -d \
  --name zeek_runner \
  -p 8000:8000 \
  -p 50051:50051 \
  -v /data/zeek_runner/config.yaml:/opt/zeek_runner/config.yaml:ro \
  -v /data/zeek_runner/rules:/opt/zeek_runner/rules:ro \
  -v /data/zeek_runner/archive:/opt/zeek_runner/archive \
  -v /data/zeek_runner/scripts:/data/zeek_runner/scripts:ro \
  -v /data/zeek_runner/pcaps:/data/zeek_runner/pcaps \
  -v /data/zeek_runner/extracted:/data/zeek_runner/extracted \
  -v /data/zeek_runner/custom/config.zeek:/usr/local/zeek/share/zeek/base/custom/config.zeek:ro \
  --log-driver json-file \
  --log-opt max-size=100m \
  --log-opt max-file=3 \
  zeek_runner:5.1

# 使用环境变量启动（不推荐，建议使用配置文件）
docker run -d \
  --name zeek_runner \
  -p 8000:8000 \
  -p 50051:50051 \
  -e KAFKA_BROKERS="192.168.2.6:9092" \
  -e AUTH_TOKENS="token1,token2" \
  -e BEHAVIOR_RULES_PATH=/opt/zeek_runner/rules/behavior_runtime.example.yaml \
  -v /data/zeek_runner/rules:/opt/zeek_runner/rules:ro \
  -v /data/zeek_runner/archive:/opt/zeek_runner/archive \
  -v /data/zeek_runner/scripts:/data/zeek_runner/scripts:ro \
  -v /data/zeek_runner/pcaps:/data/zeek_runner/pcaps \
  -v /data/zeek_runner/extracted:/data/zeek_runner/extracted \
  -v /data/zeek_runner/custom/config.zeek:/usr/local/zeek/share/zeek/base/custom/config.zeek:ro \
  zeek_runner:5.1
```

#### 日志配置

服务使用 `slog` 输出 JSON 格式日志到标准输出（stdout），Docker 自动收集并支持轮转：

```shell
# 日志轮转配置
--log-driver json-file \
--log-opt max-size=100m   # 单个日志文件最大 100MB
--log-opt max-file=3      # 保留最近 3 个日志文件

# 查看实时日志
docker logs -f zeek_runner

# 查看最近 100 行日志
docker logs --tail 100 zeek_runner

# 查看指定时间范围的日志
docker logs --since 2024-01-01T00:00:00 zeek_runner
```

**日志格式示例**：
```json
{
   "time": "2024-01-01T12:00:00.000Z",
   "level": "INFO",
   "msg": "service_started",
   "instance": "abc123-4567",
   "event": "startup",
   "http_addr": ":8000",
   "grpc_addr": ":50051"
}
```

#### Docker Compose 分布式部署

推荐使用 Docker Compose 部署多实例，支持负载均衡和故障转移。

```shell
# 启动所有服务（Redis + 3 个 zeek_runner 副本 + Nginx 负载均衡）
docker compose up -d

# 查看服务状态
docker compose ps

# 扩展副本数量
ZEEK_RUNNER_REPLICAS=5 docker compose up -d

# 查看日志
docker compose logs -f zeek_runner

# 单副本直连调试入口
docker compose -f docker-compose.yml -f docker-compose.debug.yml up -d
```

**架构说明**：

```
                    ┌─────────────────┐
                    │     Nginx       │
                    │  (负载均衡)      │
                    │  :18080/:50050  │
                    └────────┬────────┘
                             │
         ┌───────────────────┼───────────────────┐
         ▼                   ▼                   ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│  zeek_runner    │ │  zeek_runner    │ │  zeek_runner    │
│  :8000 / :50051 │ │  :8000 / :50051 │ │  :8000 / :50051 │
└────────┬────────┘ └────────┬────────┘ └────────┬────────┘
         │                   │                   │
         └───────────────────┼───────────────────┘
                             ▼
                    ┌─────────────────┐
                    │     Redis       │
                    │   (任务队列)     │
                    │      :6380      │
                    └─────────────────┘
```

**访问方式**：

| 服务 | 地址 |
|------|------|
| HTTP API (负载均衡) | `http://localhost:18080` |
| gRPC (负载均衡) | `localhost:50050` |
| 调试直连 HTTP | `http://localhost:18001`（需 `docker-compose.debug.yml`） |
| 调试直连 gRPC | `localhost:50051`（需 `docker-compose.debug.yml`） |

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
| `HTTP_HOST`             | `0.0.0.0` | HTTP 服务绑定地址 |
| `LISTEN_HTTP`           | `:8000` | HTTP 服务监听地址 |
| `HTTP_TIMEOUT`          | `60s` | HTTP 请求超时时间 |
| `GRPC_HOST`             | `0.0.0.0` | gRPC 服务绑定地址 |
| `LISTEN_GRPC`           | `:50051` | gRPC 服务监听地址 |
| `GRPC_TIMEOUT`          | `300s` | gRPC 请求超时时间 |
| `GRPC_MAX_RECV_MSG_SIZE` | `16777216` | gRPC 最大接收消息大小（字节） |
| `GRPC_MAX_SEND_MSG_SIZE` | `16777216` | gRPC 最大发送消息大小（字节） |
| `GRPC_ENABLE_REFLECTION` | `true` | 启用 gRPC 反射服务 |
| `GRPC_ENABLE_HEALTH_CHECK` | `true` | 启用 gRPC 健康检查 |
| `AUTH_TOKENS`           | -    | 认证 Token 列表（逗号分隔），为空则不启用认证 |
| `CONFIG_FILE`           | -    | 配置文件路径（优先级高于环境变量） |
| `BEHAVIOR_RULES_PATH`   | -    | 行为识别规则 YAML 路径 |
| `BEHAVIOR_ARCHIVE_ENABLED` | false | 是否启用命中载荷加密归档 |
| `BEHAVIOR_ARCHIVE_DIR`  | `/opt/zeek_runner/archive` | 归档存储目录 |
| `BEHAVIOR_ARCHIVE_KEY_HEX` | -    | AES-256 密钥（64 位十六进制字符串），启用归档时必需 |
| `BEHAVIOR_ARCHIVE_RETENTION_DAYS` | 30   | 归档保留天数 |

### 配置文件

支持 YAML 格式配置文件，**优先级高于环境变量**，适合生产环境部署：

#### 配置文件示例

```yaml
redis:
   addr: "redis:6380"
   password: "your-secure-password"
   db: 0

kafka:
   brokers: "192.168.2.6:9092"

pool:
   size: 16
   maxBlocking: 10000
   timeoutMinutes: 10

rateLimit:
   limit: 2000
   window: 60

http:
   host: "0.0.0.0"
   port: 8000
   timeout: "60s"
   authTokens:
      - "token1-change-me"
      - "token2-change-me"

grpc:
   host: "0.0.0.0"
   port: 50051
   timeout: "300s"
   maxRecvMsgSize: 16777216    # 16MB
   maxSendMsgSize: 16777216    # 16MB
   enableReflection: true      # 启用 gRPC 反射服务
   enableHealthCheck: true     # 启用健康检查
   authTokens:
      - "token1-change-me"
      - "token2-change-me"

file:
   extractPath: "/data/zeek_runner/extracted"
   minSizeKB: 20

behavior:
   rulesPath: "/opt/zeek_runner/rules/behavior_runtime.example.yaml"
   archiveEnabled: true
   archiveDir: "/opt/zeek_runner/archive"
   archiveKeyHex: "319aeb9e2163d8a97f06f761e3328c384f39e86a6d3c290113519a71578ac263"
   archiveRetention: 30
```

#### 配置参数说明

##### HTTP 配置

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `host` | string | `0.0.0.0` | HTTP 服务绑定地址 |
| `port` | int | `8000` | HTTP 服务端口 |
| `timeout` | string | `60s` | 请求超时时间 |
| `authTokens` | []string | `[]` | 认证 Token 列表，为空则不启用认证 |

##### gRPC 配置

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `host` | string | `0.0.0.0` | gRPC 服务绑定地址 |
| `port` | int | `50051` | gRPC 服务端口 |
| `timeout` | string | `300s` | 请求超时时间 |
| `maxRecvMsgSize` | int | `16777216` | 最大接收消息大小（字节），默认 16MB |
| `maxSendMsgSize` | int | `16777216` | 最大发送消息大小（字节），默认 16MB |
| `enableReflection` | bool | `true` | 启用 gRPC 反射服务（grpcurl 调试用） |
| `enableHealthCheck` | bool | `true` | 启用健康检查 |
| `authTokens` | []string | `[]` | 认证 Token 列表，为空则不启用认证 |

##### 环境变量对照表

| 环境变量 | 配置文件路径 | 说明 |
|---------|-------------|------|
| `HTTP_HOST` | `http.host` | HTTP 绑定地址 |
| `LISTEN_HTTP` | `http.port` | HTTP 端口 |
| `HTTP_TIMEOUT` | `http.timeout` | HTTP 超时 |
| `AUTH_TOKENS` | `http.authTokens` | HTTP 认证 Token |
| `GRPC_HOST` | `grpc.host` | gRPC 绑定地址 |
| `LISTEN_GRPC` | `grpc.port` | gRPC 端口 |
| `GRPC_TIMEOUT` | `grpc.timeout` | gRPC 超时 |
| `GRPC_MAX_RECV_MSG_SIZE` | `grpc.maxRecvMsgSize` | gRPC 最大接收消息大小 |
| `GRPC_MAX_SEND_MSG_SIZE` | `grpc.maxSendMsgSize` | gRPC 最大发送消息大小 |
| `GRPC_ENABLE_REFLECTION` | `grpc.enableReflection` | gRPC 反射服务开关 |
| `GRPC_ENABLE_HEALTH_CHECK` | `grpc.enableHealthCheck` | gRPC 健康检查开关 |

##### 行为识别配置

行为识别引擎使用本仓库内置的 `internal/upgradebehavior` 包加载本地规则 YAML，在 zeek_runner 侧完成 HTTP 原始流识别与命中载荷归档。Kafka 仅传输识别结果，不发送原始正文。

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `rulesPath` | string | - | 行为识别规则 YAML 路径；为空则不启动行为引擎 |
| `archiveEnabled` | bool | `false` | 是否启用命中载荷加密归档 |
| `archiveDir` | string | `/opt/zeek_runner/archive` | 归档存储目录 |
| `archiveKeyHex` | string | - | AES-256 密钥（64 位十六进制），启用归档时必需 |
| `archiveRetention` | int | `30` | 归档保留天数，过期对象定期清理 |

**启动检查**：规则加载失败（文件不存在、YAML 格式错误、规则集为空）会直接拒绝启动，不会以空规则集静默运行。

**归档安全**：加密密钥不可用时 `archiveStatus=failed`，不会降级为明文存储。归档引用 ID 由 `pcap_id|uid|tx_seq|payload_sha256|ruleID` 派生，同一事务重放不会产生重复归档。

**Docker 挂载**：规则文件和归档目录需挂载到容器内：

```shell
docker run -d \
  --name zeek_runner \
  -p 8000:8000 \
  -p 50051:50051 \
  -v /data/zeek_runner/config.yaml:/opt/zeek_runner/config.yaml:ro \
  -v /data/zeek_runner/rules:/opt/zeek_runner/rules:ro \
  -v /data/zeek_runner/archive:/opt/zeek_runner/archive \
  -v /data/zeek_runner/scripts:/opt/zeek_runner/scripts:ro \
  -v /data/zeek_runner/pcaps:/opt/zeek_runner/pcaps \
  -v /data/zeek_runner/extracted:/opt/zeek_runner/extracted \
  zeek_runner:5.1
```

开源版提供 `rules/behavior_runtime.example.yaml` 作为通用示例规则。生产部署可以直接挂载自定义后的同格式 YAML；runner 只读取该文件，不依赖外部仓库或 vendor 目录。发布后可通过 runner `GET /healthz` 中的 `ruleset_sha256` 校验当前加载的规则版本。

`/scripts/reload` 仅重载 Zeek 脚本，不重载行为规则。更新运行时规则文件需要重启 runner。

#### 使用配置文件

```shell
# 方式一：通过环境变量指定配置文件路径
docker run -d \
  --name zeek_runner \
  -p 8000:8000 \
  -p 50051:50051 \
  -e CONFIG_FILE="/opt/zeek_runner/config.yaml" \
  -v /data/zeek_runner/config.yaml:/opt/zeek_runner/config.yaml:ro \
  -v /data/zeek_runner/rules:/opt/zeek_runner/rules:ro \
  -v /data/zeek_runner/archive:/opt/zeek_runner/archive \
  -v /data/zeek_runner/scripts:/data/zeek_runner/scripts:ro \
  -v /data/zeek_runner/pcaps:/data/zeek_runner/pcaps \
  -v /data/zeek_runner/extracted:/data/zeek_runner/extracted \
  zeek_runner:5.1

# 方式二：使用默认路径（自动检测）
# 服务会按顺序检测以下路径：
# 1. /etc/zeek_runner/config.yaml
# 2. /data/zeek_runner/config.yaml
# 3. ./config.yaml
# 4. ./config/config.yaml
docker run -d \
  --name zeek_runner \
  -p 8000:8000 \
  -p 50051:50051 \
  -v /data/zeek_runner/config.yaml:/opt/zeek_runner/config.yaml:ro \
  -v /data/zeek_runner/rules:/opt/zeek_runner/rules:ro \
  -v /data/zeek_runner/archive:/opt/zeek_runner/archive \
  -v /data/zeek_runner/scripts:/data/zeek_runner/scripts:ro \
  -v /data/zeek_runner/pcaps:/data/zeek_runner/pcaps \
  -v /data/zeek_runner/extracted:/data/zeek_runner/extracted \
  zeek_runner:5.1
```

#### 配置优先级

```
配置文件 > 环境变量 > 默认值
```

#### 安全建议

- **Redis 密码**：使用配置文件而非环境变量，避免密码泄露
- **密码一致性**：确保 `config.yaml` 和 `docker-compose.yml` 中的 Redis 密码一致
- **归档密钥**：`behavior.archiveKeyHex` 是 AES-256 加密密钥，生产环境务必更换并通过 Docker Secrets 或 Kubernetes Secrets 注入，不要提交到代码仓库
- **配置文件权限**：设置 `chmod 600 config.yaml` 限制访问
- **Docker Secrets**：生产环境建议使用 Docker Secrets 或 Kubernetes Secrets

### OpenTelemetry 链路追踪

服务支持 OpenTelemetry 标准链路追踪，可与前置服务形成完整调用链。

#### 三种运行模式

| 模式 | 配置 | 适用场景 |
|------|------|----------|
| 禁用 | `enabled: false` | 不需要链路追踪 |
| 日志输出 | `enabled: true, endpoint: ""` | 生产环境（无额外资源） |
| 可视化 | `enabled: true, endpoint: "otel-collector:4317"` | 本地开发（需要 Jaeger） |

#### 配置示例

```yaml
otel:
   enabled: true
   endpoint: "otel-collector:4317"  # 留空则输出到日志
```

#### 生产环境部署

生产环境无需部署额外组件，Trace 数据输出到日志：

```yaml
# config.yaml
otel:
   enabled: true
   endpoint: ""  # 留空，输出到日志
```

日志输出示例：
```json
{
   "Name": "zeek_execution",
   "SpanContext": {
      "TraceID": "4bf92f3577b34da6a3ce929d0e0e4736",
      "SpanID": "00f067aa0ba902b7"
   },
   "Attributes": [
      {"Key": "task_id", "Value": {"Type": "STRING", "Value": "task-123"}}
   ],
   "Status": {"Code": "Error", "Description": "timeout"}
}
```

通过日志系统搜索 `TraceID` 即可追踪调用链。

#### 本地开发部署

本地开发可部署 Jaeger 可视化调用链：

```shell
# 启动本地开发环境（包含 Jaeger）
docker compose -f docker-compose.local.yml up -d

# 访问 Jaeger UI
open http://localhost:16686
```

**本地开发架构**：

```
┌─────────────┐    ┌─────────────────┐    ┌─────────────┐
│ zeek_runner │───▶│ otel-collector  │───▶│   Jaeger    │
│             │    │     :4317       │    │   :16686    │
└─────────────┘    └─────────────────┘    └─────────────┘
```

#### 资源消耗

| 组件 | 镜像大小 | 内存占用 |
|------|----------|----------|
| OTel Collector | ~50MB | ~100MB |
| Jaeger | ~80MB | ~200MB |
| **总计** | **~130MB** | **~300MB** |

#### 接入现有 OTel 基础设施

如果公司已有 OTel Collector，直接配置 endpoint：

```yaml
otel:
   enabled: true
   endpoint: "your-otel-collector:4317"
```

### 异步任务模式

服务支持两种任务执行模式：

#### 同步模式（默认）
- 上层服务下发任务后等待执行完成
- 适合实时性要求高、任务执行时间短的场景

#### 异步模式（需要 Redis）
- 上层服务通过 `AsyncAnalyzeBatch` 下发一个 pcap 的多个脚本后立即返回任务ID
- 服务后台从 Redis Stream 主动领取任务并按资源容量执行，上层服务通过任务ID查询状态
- 适合批量任务、长时间执行任务的场景
- **支持分布式部署**：多个实例共享 Redis Stream consumer group，副本按自身容量 pull job

```shell
# 启用异步模式需要配置 Redis（在 config.yaml 中配置）
docker run -d \
  --name zeek_runner \
  -p 8000:8000 \
  -p 50051:50051 \
  -v /data/zeek_runner/config.yaml:/opt/zeek_runner/config.yaml:ro \
  -v /data/zeek_runner/rules:/opt/zeek_runner/rules:ro \
  -v /data/zeek_runner/archive:/opt/zeek_runner/archive \
  -v /data/zeek_runner/scripts:/data/zeek_runner/scripts:ro \
  -v /data/zeek_runner/file_extract_script:/data/zeek_runner/file_extract_script:ro \
  -v /data/zeek_runner/pcaps:/data/zeek_runner/pcaps \
  -v /data/zeek_runner/extracted:/data/zeek_runner/extracted \
  zeek_runner:5.1
```

### 分布式部署

服务支持多实例部署，通过 Redis Stream 实现任务队列共享和 lease/reclaim：

#### 架构设计

```
┌─────────────────────────────────────────────────────────────────┐
│                      上层服务                                    │
│            (下发任务到任意实例)                                   │
└───────────────────────┬─────────────────────────────────────────┘
                        │
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│   实例 A      │ │   实例 B      │ │   实例 C      │
│  (消费者)     │ │  (消费者)     │ │  (消费者)     │
└──────┬───────┘ └──────┬───────┘ └──────┬───────┘
       │                │                │
       └────────────────┼────────────────┘
                        ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Redis Stream 控制面                            │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  zeek:task:stream →  batch job + uuids + pcap metadata  │   │
│  └─────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  zeek:task:{id}  →  {task metadata & status}            │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

#### 工作流程

1. **任务提交**：`AsyncAnalyzeBatch` 创建多个 subtask，并写入 `zeek:task:stream`
2. **任务领取**：各副本通过 `XREADGROUP/XAUTOCLAIM` 按容量主动领取 batch job
3. **任务执行**：同一 pcap 的可归因脚本合并为一次 `zeek -Cr pcap script...`
4. **状态输出**：subtask/parent final 事件写入 Kafka，失败时进入 Redis outbox 补发

#### 部署示例

使用 Docker Compose 部署，详见 `docker-compose.yml`；生产/NAS 环境可使用 `docker-compose.dev.yml`。

Compose 多副本部署：

```shell
ZEEK_RUNNER_REPLICAS=3 docker compose up -d
docker compose logs -f zeek_runner
```

单副本直连调试：

```shell
docker compose -f docker-compose.yml -f docker-compose.debug.yml up -d
curl http://localhost:18001/api/v1/healthz
grpcurl -plaintext localhost:50051 list
```

#### 负载均衡

- **自动负载均衡**：空闲实例自动从队列获取任务
- **故障转移**：实例宕机后，任务留在队列中被其他实例处理
- **容量扩展**：增加实例即可提升处理能力

#### 注意事项

1. **共享存储**：多实例需要共享 PCAP 文件和脚本目录
2. **文件提取**：提取文件目录也需要共享或使用分布式存储
3. **实例标识**：每个实例有唯一 ID，便于日志追踪

### 文件提取去重

服务采用**任务内去重策略**，防止批量下载场景下的重复文件浪费存储：

#### 设计原则

```
┌─────────────────────────────────────────────────────────────────┐
│  任务内去重（基于 Redis，过期时间 24 小时）                            │
│  • 同一任务内相同 hash 文件只保留一份                                │
│  • 后续重复文件跳过物理存储，增加引用计数                           │
│  • 不同任务之间的文件完全隔离，互不影响                             │
│  • 输出日志：duplicate file in task detected hash=xxx            │
└─────────────────────────────────────────────────────────────────┘
```

#### 为什么不用跨任务去重？

| 问题 | 跨任务去重 ❌ | 任务内去重 ✅ |
|------|--------------|--------------|
| 历史文件被清理 | 引用计数还在，但物理文件已删除 | 每个任务独立存储，不受影响 |
| Zeek 脚本更新 | 旧脚本提取的文件可能被新脚本覆盖 | 任务隔离，实验可重复 |
| 存储管理复杂 | 需要全局引用计数和垃圾回收 | 任务结束后文件可安全清理 |

#### 工作流程

1. **计算哈希**：Zeek 任务完成后，Go 层扫描提取目录，计算每个文件 SHA256
2. **任务内检查**：查询 Redis `zeek:file:task:{taskID}:hash:{hash}` 是否存在
3. **重复文件**：
   - 如果存在：跳过物理存储，增加 `ref_count`
   - 输出日志：`duplicate file in task detected`
4. **新文件**：
   - 注册到 Redis，设置 24 小时过期时间
   - 输出日志：`file registered in task`

#### Redis Key 结构

```
# 任务内去重（主要）
zeek:file:task:{taskID}:hash:{hash} → FileRecord JSON

# 路径反查（辅助）
zeek:file:path:{filePath} → hash
```

#### 优势对比

| 场景 | 无去重 | 任务内去重 |
|------|--------|------------|
| 任务内 100 次相同文件 | 提取 100 个 | 提取 1 个 ✅ |
| 不同任务相同文件 | 提取 N 个 | 提取 N 个（隔离）✅ |
| 批量下载流量包 | 浪费 100 倍空间 | 只存 1 份 ✅ |
| 历史文件清理 | 影响其他任务 | 互不影响 ✅ |
| 实验可重复性 | 可能被覆盖 | 完全隔离 ✅ |


#### 前置服务消费 Kafka

前置服务消费 Kafka 时可根据 `sha256` 字段判断文件是否重复：

```json
{
   "ts": 1712138400.0,
   "id": {
      "orig_h": "192.168.12.2380",
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
1. 正常处理每个文件，记录 `sha256` 和 `extracted` 路径
2. 如果同一任务内收到相同 `sha256`，说明是重复文件
3. 可根据需要选择保留最新路径或忽略

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

**单实例部署**（端口 8000）：
```shell
# 健康检查（无需认证）
curl http://localhost:8000/api/v1/healthz

# Prometheus 指标（无需认证）
curl http://localhost:8000/metrics

# 调用 /api/v1/version/zeek 接口（需要 User-Agent，配置 AUTH_TOKENS 后还需 Authorization）
curl -H "User-Agent: test" -H "Authorization: your-token" http://localhost:8000/api/v1/version/zeek
```

**分布式部署**（通过 Nginx 负载均衡，端口 18080）：
```shell
# 健康检查
curl http://localhost:18080/api/v1/healthz

# 版本检查
curl -H "User-Agent: test" -H "Authorization: your-token" http://localhost:18080/api/v1/version/zeek

# 单副本直连调试（需 docker-compose.debug.yml）
curl http://localhost:18001/api/v1/healthz
```

**完整测试命令**（单实例）：
```shell

# 测试检测恶意行为发送到kafka 仅notice日志
curl -X POST \
  -H "Content-Type: application/json" \
  -H "User-Agent: test" \
  -H "Authorization: your-token" \
  -d '{
    "pcapPath": "/data/zeek_runner/pcaps/ssh_bruteforce_test.pcap",
    "scriptPath": "/data/zeek_runner/scripts/detect_ssh_bruteforce.zeek",
    "onlyNotice": true,
    "uuid": "d3db5f67-c441-56a4-9591-c30c3abab24f",
    "taskID": "2333",
    "pcapID": "pcap-001",
    "scriptID": "script-001"
  }' \
  http://localhost:8000/api/v1/analyze

# 异步分析兼容接口（需要 Redis）- 单脚本会转为单脚本 batch
curl -X POST \
  -H "Content-Type: application/json" \
  -H "User-Agent: test" \
  -H "Authorization: your-token" \
  -d '{
    "pcapPath": "/data/zeek_runner/pcaps/ssh_bruteforce_test.pcap",
    "scriptPath": "/data/zeek_runner/scripts/detect_ssh_bruteforce.zeek",
    "onlyNotice": true,
    "uuid": "d3db5f67-c441-56a4-9591-c30c3abab24f",
    "taskID": "2333",
    "pcapID": "pcap-001",
    "scriptID": "script-001"
  }' \
  http://localhost:8000/api/v1/analyze/async

# 异步批量分析接口（推荐）通过 gRPC AsyncAnalyzeBatch 调用；
# HTTP /api/v1/analyze/async 保留为单脚本兼容入口。

# 查询任务状态
curl -H "User-Agent: test" -H "Authorization: your-token" \
  http://localhost:8000/api/v1/task/2333
  
# 所有日志除notice
curl -X POST \
  -H "Content-Type: application/json" \
  -H "User-Agent: test" \
  -H "Authorization: your-token" \
  -d '{
    "pcapPath": "/data/zeek_runner/pcaps/ssh_bruteforce_test.pcap",
    "scriptPath": "/data/zeek_runner/scripts/detect_ssh_bruteforce.zeek",
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
    "scriptPath": "/data/zeek_runner/scripts/detect_ssh_bruteforce.zeek"
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
```

**单实例部署**（端口 50051）：
```shell
# 查看服务列表
grpcurl -plaintext localhost:50051 list

# 健康检查
grpcurl -plaintext -H 'user-agent: test' -H 'authorization: your-token' \
  localhost:50051 zeek_runner.ZeekAnalysisService/HealthCheck

# 版本检查
grpcurl -plaintext -H 'user-agent: test' -H 'authorization: your-token' \
  -d '{"component": "zeek"}' \
  localhost:50051 zeek_runner.ZeekAnalysisService/VersionCheck
```

**分布式部署**（通过 Nginx 负载均衡，端口 50050）：
```shell
# 健康检查（负载均衡）
grpcurl -plaintext -H 'user-agent: test' -H 'authorization: your-token' \
  localhost:50050 zeek_runner.ZeekAnalysisService/HealthCheck

# 版本检查（负载均衡）
grpcurl -plaintext -H 'user-agent: test' -H 'authorization: your-token' \
  -d '{"component": "zeek"}' \
  localhost:50050 zeek_runner.ZeekAnalysisService/VersionCheck

# 单副本直连调试（需 docker-compose.debug.yml）
grpcurl -plaintext localhost:50051 list
```

**完整测试命令**（单实例）：
```shell

# 调用 zeek 分析 pcap
grpcurl -plaintext -H 'user-agent: test' -H 'authorization: your-token' -d '{
  "taskID": "2333",
  "uuid": "d3db5f67-c441-56a4-9591-c30c3abab24f",
  "onlyNotice": true,
  "pcapID": "pcap-001",
  "pcapPath": "/data/zeek_runner/pcaps/ssh_bruteforce_test.pcap",
  "scriptID": "script-001",
  "scriptPath": "/data/zeek_runner/scripts/detect_ssh_bruteforce.zeek"
}' localhost:50051 zeek_runner.ZeekAnalysisService/Analyze

# 异步分析兼容接口（需要 Redis）- 单脚本会转为单脚本 batch
grpcurl -plaintext -H 'user-agent: test' -H 'authorization: your-token' -d '{
  "taskID": "2334",
  "uuid": "d3db5f67-c441-56a4-9591-c30c3abab24f",
  "onlyNotice": true,
  "pcapID": "pcap-001",
  "pcapPath": "/data/zeek_runner/pcaps/ssh_bruteforce_test.pcap",
  "scriptID": "script-001",
  "scriptPath": "/data/zeek_runner/scripts/detect_ssh_bruteforce.zeek"
}' localhost:50051 zeek_runner.ZeekAnalysisService/AsyncAnalyze

# 异步批量分析接口（推荐）
grpcurl -plaintext -H 'user-agent: test' -H 'authorization: your-token' -d '{
  "taskID": "2334",
  "pcapID": "pcap-001",
  "pcapPath": "/data/zeek_runner/pcaps/ssh_bruteforce_test.pcap",
  "onlyNotice": true,
  "scripts": [
    {"uuid": "uuid-ssh", "scriptID": "DETECT_SSH_BRTFORCE_v1", "scriptPath": "/data/zeek_runner/scripts/detect_ssh_bruteforce.zeek", "runMode": "scan", "weight": 1},
    {"uuid": "uuid-syn", "scriptID": "DETECT_SYN_FLOOD_v1", "scriptPath": "/data/zeek_runner/scripts/detect_syn_flood.zeek", "runMode": "scan", "weight": 1}
  ]
}' localhost:50051 zeek_runner.ZeekAnalysisService/AsyncAnalyzeBatch

# 查询任务状态
grpcurl -plaintext -H 'user-agent: test' -H 'authorization: your-token' -d '{
  "taskID": "2334"
}' localhost:50051 zeek_runner.ZeekAnalysisService/GetTaskStatus

# Zeek 脚本语法检查 - 通过文件路径
grpcurl -plaintext -H 'user-agent: test' -H 'authorization: your-token' -d '{
  "script_path": "/data/zeek_runner/scripts/detect_ssh_bruteforce.zeek"
}' localhost:50051 zeek_runner.ZeekAnalysisService/ZeekSyntaxCheck

# Zeek 脚本语法检查 - 通过脚本内容
grpcurl -plaintext -H 'user-agent: test' -H 'authorization: your-token' -d '{
  "script_content": "event connection_new(c: connection) { print c$id; }"
}' localhost:50051 zeek_runner.ZeekAnalysisService/ZeekSyntaxCheck
```

#### 批量测试脚本

创建批量测试脚本验证负载均衡和分布式处理：

```shell
# 创建测试脚本 test_batch.sh
cat > test_batch.sh << 'EOF'
#!/bin/bash

TOKEN="token-dpi"
HTTP_URL="http://localhost:18080"
GRPC_URL="localhost:50050"

echo "=== 批量测试 HTTP 接口 ==="
for i in {1..10}; do
  curl -s -X POST \
    -H "Content-Type: application/json" \
    -H "User-Agent: test" \
    -H "Authorization: $TOKEN" \
    -d "{
      \"pcapPath\": \"/data/zeek_runner/pcaps/ssh_bruteforce_test.pcap\",
      \"scriptPath\": \"/data/zeek_runner/scripts/detect_ssh_bruteforce.zeek\",
      \"onlyNotice\": true,
      \"taskID\": \"test-$i\",
      \"uuid\": \"uuid-$i\",
      \"pcapID\": \"pcap-$i\",
      \"scriptID\": \"script-$i\"
    }" \
    "$HTTP_URL/api/v1/analyze/async" &
done
wait
echo "HTTP 批量测试完成"

echo ""
echo "=== 批量测试 gRPC 接口 ==="
for i in {1..10}; do
  grpcurl -plaintext \
    -H 'user-agent: test' \
    -H "authorization: $TOKEN" \
    -d "{
      \"taskID\": \"grpc-test-$i\",
      \"uuid\": \"grpc-uuid-$i\",
      \"onlyNotice\": true,
      \"pcapPath\": \"/data/zeek_runner/pcaps/ssh_bruteforce_test.pcap\",
      \"scriptPath\": \"/data/zeek_runner/scripts/detect_ssh_bruteforce.zeek\",
      \"pcapID\": \"pcap-$i\",
      \"scriptID\": \"script-$i\"
    }" \
    "$GRPC_URL" zeek_runner.ZeekAnalysisService/AsyncAnalyze &
done
wait
echo "gRPC 批量测试完成"

echo ""
echo "=== 查看任务状态 ==="
docker compose logs --tail=50 zeek_runner | grep -E "task|instance"
EOF

chmod +x test_batch.sh
./test_batch.sh
```

**观察负载均衡效果**：

```shell
# 查看各实例日志，确认任务被分配到不同实例
docker compose logs -f zeek_runner

# 输出示例：
# zeek_runner-zeek_runner-1 | {"level":"INFO","msg":"task","event":"started","taskID":"test-1","instance":"zeek_runner-1234"}
# zeek_runner-zeek_runner-2 | {"level":"INFO","msg":"task","event":"started","taskID":"test-2","instance":"zeek_runner-5678"}
# zeek_runner-zeek_runner-3 | {"level":"INFO","msg":"task","event":"started","taskID":"test-3","instance":"zeek_runner-9012"}
```

#### 多副本性能验证

使用性能测试脚本验证多副本对并发任务的帮助：

```shell
# 运行性能测试
chmod +x test_performance.sh
./test_performance.sh
```

**测试输出示例**：

```
==========================================
   多副本并发性能测试
==========================================

=== 提交 20 个异步任务 ===
任务提交完成，耗时: 2 秒

=== 各实例处理的任务数 ===
zeek_runner-zeek_runner-1: 7 个任务
zeek_runner-zeek_runner-2: 6 个任务
zeek_runner-zeek_runner-3: 7 个任务
总计: 20 个任务已开始处理

=== 各实例完成的任务数 ===
zeek_runner-zeek_runner-1: 7 个任务
zeek_runner-zeek_runner-2: 6 个任务
zeek_runner-zeek_runner-3: 7 个任务
总计: 20 个任务已完成

=== 多副本效果验证 ===
✅ zeek_runner-zeek_runner-1 处理了 7 个任务
✅ zeek_runner-zeek_runner-2 处理了 6 个任务
✅ zeek_runner-zeek_runner-3 处理了 7 个任务

✅ 多副本生效！3 个实例参与处理任务

优势说明：
  - 任务被均匀分配到多个实例
  - 单实例故障不影响整体服务
  - 可通过增加实例提升处理能力
```

**多副本优势对比**：

| 场景 | 单实例 | 3副本 |
|------|--------|-------|
| 并发任务数 | 8 (受限于 PoolSize) | 24 (3×8) |
| 故障恢复 | 服务中断 | 自动转移 |
| 处理能力 | 1x | ~3x |
| 扩展方式 | 升级配置 | 增加实例 |

**关键指标**：

1. **任务分布**：任务被均匀分配到各实例
2. **处理速度**：总处理时间显著缩短
3. **资源利用**：各实例 CPU/内存均衡使用
4. **容错能力**：单实例宕机不影响服务

### 直接使用本机zeek测试
```shell
##### 本地测试：仅验证 Zeek 脚本能解析 pcap 并生成本地 .log 文件
# Kafka 发送需要通过 Go 服务 API 触发，由 Go 读取 .log 后发布结构化事件
# ONLY_NOTICE=true 只输出 notice/intel/task_status 日志；false 输出完整日志
ONLY_NOTICE=true SCRIPT_PATH=/xx/xx/scripts/detect_ssh_bruteforce.zeek \
PCAP_PATH=/xx/xx/pcaps/ssh_bruteforce_test.pcap \
zeek -Cr ./pcaps/ssh_bruteforce_test.pcap \
./scripts/detect_ssh_bruteforce.zeek ./custom/config.zeek

##### 仅本地测试

# SSH暴力破解攻击
zeek -Cr ./pcaps/ssh_bruteforce_test.pcap \
./test.zeek ./scripts/detect_ssh_bruteforce.zeek

# DNS洪水攻击/放大攻击
zeek -Cr ./pcaps/dns_flood_test.pcap \
./test.zeek \
./scripts/detect_dns_flood.zeek

# 恶意User-Agent检测
zeek -Cr ./pcaps/http_suspicious_ua_test.pcap \
./test.zeek \
./scripts/detect_http_suspicious_ua.zeek

# HTTP恶意文件上传(Webshell)
zeek -Cr ./pcaps/http_webshell_test.pcap \
./test.zeek \
./scripts/detect_http_webshell.zeek

# HTTP拒绝服务攻击(CC攻击)
zeek -Cr ./pcaps/http_flood_test.pcap \
./test.zeek \
./scripts/detect_http_flood.zeek

# TCP SYN洪水攻击
zeek -Cr ./pcaps/syn_flood_test.pcap \
./test.zeek \
./scripts/detect_syn_flood.zeek

# SSH异常大文件传输(SCP/SFTP)
zeek -Cr ./pcaps/ssh_file_transfer_test.pcap \
./test.zeek \
./scripts/detect_ssh_file_transfer.zeek

# Unix命令注入攻击
zeek -Cr ./pcaps/http_cmd_injection_test.pcap \
./test.zeek \
./scripts/detect_http_cmd_injection.zeek


## 提取文件模式测试
EXTRACTED_FILE_PATH=/path/for/save/extracted/files \
MIN_FILE_SIZE_KB=20 \
MAX_FILE_SIZE_MB=200 \
zeek -Cr ./file_extract_script/xxx.pcap \
./extract_http.zeek

EXTRACTED_FILE_PATH=/path/for/save/extracted/files \
MIN_FILE_SIZE_KB=20 \
MAX_FILE_SIZE_MB=200 \
zeek -Cr ./xxx.pcap \
./extract_http.zeek

# 使用文件提取接口
curl -X POST \
  -H "Content-Type: application/json" \
  -H "User-Agent: test" \
  -H "Authorization: your-token" \
  -d '{
    "outputDir": "/path/for/save/extracted/files",
    "extractedFileMinSize": 20,
    "extractedFileMaxSize": 200,
    "pcapPath": "/data/zeek_runner/file_extract_script/xxx.pcap",
    "uuid": "233",
    "taskID": "122",
    "pcapID": "pcap-001"
  }' \
  http://localhost:8000/api/v1/extract

# 使用异步文件提取接口
curl -X POST \
  -H "Content-Type: application/json" \
  -H "User-Agent: test" \
  -H "Authorization: your-token" \
  -d '{
    "outputDir": "/path/for/save/extracted/files",
    "extractedFileMinSize": 20,
    "extractedFileMaxSize": 200,
    "pcapPath": "/data/zeek_runner/file_extract_script/xxx.pcap",
    "uuid": "233",
    "taskID": "122",
    "pcapID": "pcap-001"
  }' \
  http://localhost:8000/api/v1/extract/async
```

### Docker Compose 部署
```shell
# 默认环境
docker compose up -d
docker compose down

# 本地开发 Compose
docker compose -f docker-compose.local.yml up -d
docker compose -f docker-compose.local.yml down

# 生产/NAS Compose
ZEEK_RUNNER_REPLICAS=3 docker compose -f docker-compose.dev.yml up -d
ZEEK_RUNNER_REPLICAS=5 docker compose -f docker-compose.dev.yml up -d
docker compose -f docker-compose.dev.yml down
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

## 离线分析模式说明

当前服务只支持离线 pcap 分析。Go 服务负责 API、Redis Stream 调度、资源权重、超时、Kafka/Redis 状态和结果事件；主路径是一个 pcap 的多个可归因脚本合并为一次 Zeek batch：

```shell
zeek -Cr <pcapPath> <scriptPath1> <scriptPath2> ... /usr/local/zeek/share/zeek/base/custom/config.zeek
```

`AsyncAnalyze` 仍保留为兼容旧调用，内部会转为单脚本 batch；无法唯一归因的脚本会自动拆分为单脚本执行。

文件提取任务使用轻量配置：

```shell
zeek -Cr <pcapPath> /opt/zeek_runner/file_extract_script/extract_file.zeek /usr/local/zeek/share/zeek/base/custom/config_extract.zeek
```

实时流量分析后续应使用独立 Zeek node/cluster 或容器常驻进程，不复用当前一次一任务的 Go wrapper 模式。

### Offline custom 加载

| 入口 | 用途 | 加载内容 |
|------|------|----------|
| `custom/config.zeek` | 恶意行为检测、intel 命中 | runtime、task status、intel feeds、notice、offline intel replay |
| `custom/config_extract.zeek` | 文件提取 | runtime、task status |

Zeek 脚本将日志写入本地 `.log` 文件，zeek_runner Go 代码读取后发布结构化事件到 Kafka：

| Topic | 事件类型 | 说明 |
|-------|---------|------|
| `zeek_detection_events` | `subtask_hit` / `subtask_completed` / `subtask_failed` / `parent_completed` / `parent_failed` | 检测结果 |
| `zeek_verification_logs` | `verification_log` | 验证模式全量日志 |
| `zeek_extract_events` | `file_extracted` / `task_completed` / `task_failed` | 文件提取事件 |

### 可复现恶意行为样本

测试流量包已放在 `pcaps/`。容器内路径统一为 `/opt/zeek_runner/pcaps/<file>`，脚本路径为 `/opt/zeek_runner/scripts/<script>`。

| 行为 | 脚本 | pcap | 预期输出 |
|------|------|------|----------|
| 异常大流量 | `detect_anomalous_traffic.zeek` | `anomalous_traffic_test.pcap` | `Anomalous_Traffic_Detected` notice |
| 批量下载 | `detect_bulk_download.zeek` | `bulk_download_test.pcap` | `Bulk_Download_Detected` notice |
| DNS Flood/ANY 放大 | `detect_dns_flood.zeek` | `dns_flood_test.pcap` | `DNS_Query_Flood`、`DNS_Amplification_ANY` notice |
| 关键文件访问/篡改迹象 | `detect_file_tampering.zeek` | `file_tampering_test.pcap` | `File_Tampering_Detected` notice |
| HTTP 暴力破解 | `detect_http_brute_force.zeek` | `http_bruteforce_test.pcap` | `HTTP_Brute_Force_Detected` notice |
| HTTP 命令注入 | `detect_http_cmd_injection.zeek` | `http_cmd_injection_test.pcap` | `HTTP_Command_Injection` notice |
| HTTP Flood | `detect_http_flood.zeek` | `http_flood_test.pcap` | `HTTP_Flood_Detected` notice |
| 可疑 User-Agent | `detect_http_suspicious_ua.zeek` | `http_suspicious_ua_test.pcap` | suspicious UA notice |
| WebShell 上传 | `detect_http_webshell.zeek` | `http_webshell_test.pcap` | webshell upload notice |
| Intel 情报命中 | `detect_intel_feed_hit.zeek` | `intel_hit_test.pcap` | `intel.log` 命中 / `zeek_detection_events` subtask_hit |
| Slammer Worm | `detect_slammer_worm.zeek` | `slammer_worm_test.pcap` | Slammer notice |
| SQLi WebShell | `detect_sqli_webshell.zeek` | `sqli_webshell_test.pcap` | SQLi/webshell notice |
| SSH 暴力破解 | `detect_ssh_bruteforce.zeek` | `ssh_bruteforce_test.pcap` | `SSH::Password_Guessing` notice |
| SSH 大文件传输 | `detect_ssh_file_transfer.zeek` | `ssh_file_transfer_test.pcap` | `Suspicious_SCP_Transfer` notice |
| SYN Flood | `detect_syn_flood.zeek` | `syn_flood_test.pcap` | `notice.log` 中出现 `SynFlood::SynFlood` / `zeek_detection_events` subtask_hit |
| 文件提取 | `extract_file.zeek` | `file_extract_test.pcap` | `zeek_extract_events` 中出现提取文件事件，输出目录有 `firmware.bin` |

通用调用示例：

```shell
curl -X POST \
  -H "Content-Type: application/json" \
  -H "User-Agent: test" \
  -H "Authorization: your-token-here" \
  -d '{
    "pcapPath": "/opt/zeek_runner/pcaps/syn_flood_test.pcap",
    "scriptPath": "/opt/zeek_runner/scripts/detect_syn_flood.zeek",
    "onlyNotice": true,
    "uuid": "test-detect-syn-flood",
    "taskID": "test-detect-syn-flood",
    "pcapID": "pcap-syn-flood-test",
    "scriptID": "script-detect-syn-flood"
  }' \
  http://localhost:18080/api/v1/analyze
```

替换 `pcapPath`、`scriptPath`、`uuid`、`taskID`、`pcapID`、`scriptID` 即可验证表中其他行为。

如需重新生成测试包：

```shell
python3 scripts/test/generate_offline_test_pcaps.py
```

### 文件提取

文件提取脚本按 MIME 和后缀提取固件、二进制、压缩包、安装包、镜像等高价值文件。API 字段会传入 Zeek 环境变量：

| API 字段 | Zeek 环境变量 | 说明 |
|---------|---------------|------|
| `outputDir` | `EXTRACTED_FILE_PATH` | 提取输出目录 |
| `extractedFileMinSize` | `MIN_FILE_SIZE_KB` | 最小保留大小，KB |
| `extractedFileMaxSize` | `MAX_FILE_SIZE_MB` | 最大提取限制，MB |

提取任务使用 `custom/config_extract.zeek`，默认不加载 intel feeds/replay，减少离线提取开销。

调用示例：

```shell
curl -X POST \
  -H "Content-Type: application/json" \
  -H "User-Agent: test" \
  -H "Authorization: your-token-here" \
  -d '{
    "pcapPath": "/opt/zeek_runner/pcaps/file_extract_test.pcap",
    "scriptPath": "/opt/zeek_runner/file_extract_script/extract_file.zeek",
    "outputDir": "/opt/zeek_runner/extracted/file_extract_test",
    "extractedFileMinSize": 20,
    "extractedFileMaxSize": 200,
    "uuid": "test-file-extract",
    "taskID": "test-file-extract",
    "pcapID": "pcap-file-extract-test"
  }' \
  http://localhost:18080/api/v1/extract
```

### Intel 情报库

镜像内置 `Zeek-Intelligence-Feeds`。离线 pcap 中，Zeek 可能先看到流量、后完成 feed 加载，所以 `custom/offline/intel_replay.zeek` 会缓存 IP、DNS、HTTP URL、TLS SNI 等 observable，feed 加载完成后回放到 Intel 框架。无 feed 时直接跳过 replay；文件提取任务默认禁用 replay。
