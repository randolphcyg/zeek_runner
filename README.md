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
docker pull jaegertracing/jaeger:2.17.0 --platform linux/amd64

docker build -t zeek_runner:4.0 . --platform linux/amd64
# 指定国内仓库
docker build --build-arg APT_MIRROR=http://mirrors.aliyun.com -t zeek_runner:latest . --platform linux/amd64
# 容器导出
docker save zeek_runner:4.0  | gzip > zeek_runner.tar.gz
docker save redis:8-alpine | gzip > redis.tar.gz
docker save nginx:1.28-alpine | gzip > nginx.tar.gz
docker save jaegertracing/jaeger:2.17.0 | gzip > jaeger.tar.gz

docker load -i zeek_runner.tar.gz
docker load -i redis.tar.gz
docker load -i nginx.tar.gz
docker load -i jaeger.tar.gz
```

#### 离线部署

适用于无外网的服务器环境，一键打包所有镜像和配置：

```shell
# 1. 在有网环境执行打包脚本
chmod +x build_offline.sh
./build_offline.sh [版本号]

# 输出示例：
# offline_package/
# ├── zeek_runner_latest.tar.gz    # zeek_runner 镜像
# ├── redis.tar.gz                 # Redis 镜像
# ├── nginx.tar.gz                 # Nginx 镜像
# ├── docker-compose.yml           # 部署配置
# ├── nginx.conf                   # 负载均衡配置
# ├── config.yaml                  # 服务配置示例
# ├── deploy.sh                    # 部署脚本
# └── uninstall.sh                 # 卸载脚本

# 2.# 2. 传输到目标服务器
scp -r offline_package user@server:/data/zeek_runner/

# 3. 在目标服务器执行部署
cd /data/zeek_runner/
./deploy.sh

# 4. 编辑配置文件（设置 Redis 密码、Kafka 地址等）
sudo vi /data/zeek_runner/config.yaml

# 5. 重启服务
docker-compose restart
```

**离线包内容**：

| 文件 | 大小 | 说明 |
|------|------|------|
| zeek_runner_*.tar.gz | ~800MB | 服务镜像 |
| redis.tar.gz | ~30MB | Redis 镜像 |
| nginx.tar.gz | ~25MB | Nginx 镜像 |
| docker-compose.yml | - | 部署配置 |
| config.yaml | - | 服务配置 |
# 解压镜像
docker load -i zeek_runner.tar.gz
```

#### 运行

```shell
# 使用配置文件启动（推荐）
docker run -d \
  --name zeek_runner \
  -p 8000:8000 \
  -p 50051:50051 \
  -v /data/zeek_runner/config.yaml:/data/zeek_runner/config.yaml:ro \
  -v /data/zeek_runner/scripts:/data/zeek_runner/scripts \
  -v /data/zeek_runner/pcaps:/data/zeek_runner/pcaps \
  -v /data/zeek_runner/extracted:/data/zeek_runner/extracted \
  -v /data/zeek_runner/custom/config.zeek:/usr/local/zeek/share/zeek/base/custom/config.zeek \
  --log-driver json-file \
  --log-opt max-size=100m \
  --log-opt max-file=3 \
  zeek_runner:latest

# 使用环境变量启动（不推荐，建议使用配置文件）
docker run -d \
  --name zeek_runner \
  -p 8000:8000 \
  -p 50051:50051 \
  -e KAFKA_BROKERS="192.168.2.6:9092" \
  -e AUTH_TOKENS="token1,token2" \
  -v /data/zeek_runner/scripts:/data/zeek_runner/scripts \
  -v /data/zeek_runner/pcaps:/data/zeek_runner/pcaps \
  -v /data/zeek_runner/extracted:/data/zeek_runner/extracted \
  -v /data/zeek_runner/custom/config.zeek:/usr/local/zeek/share/zeek/base/custom/config.zeek \
  zeek_runner:latest
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

推荐使用 Docker Compose 部署多实例，支持负载均衡和故障转移：

```shell
# 启动所有服务（Redis + 3个zeek_runner实例 + Nginx负载均衡）
docker-compose up -d

# 查看服务状态
docker-compose ps

# 扩展实例数量（修改 docker-compose.yml 后）
docker-compose up -d --scale zeek_runner_1=2

# 查看日志
docker-compose logs -f zeek_runner_1
```

**架构说明**：

```
                    ┌─────────────────┐
                    │     Nginx       │
                    │  (负载均衡)      │
                    │  :80 / :50050   │
                    └────────┬────────┘
                             │
         ┌───────────────────┼───────────────────┐
         ▼                   ▼                   ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│  zeek_runner_1  │ │  zeek_runner_2  │ │  zeek_runner_3  │
│  :8001 / :50051 │ │  :8002 / :50052 │ │  :8003 / :50053 │
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
| HTTP API (负载均衡) | `http://localhost:80` |
| gRPC (负载均衡) | `localhost:50050` |
| 实例1 HTTP | `http://localhost:8001` |
| 实例2 HTTP | `http://localhost:8002` |
| 实例3 HTTP | `http://localhost:8003` |

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
  topic: "zeek_logs"

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

#### 使用配置文件

```shell
# 方式一：通过环境变量指定配置文件路径
docker run -d \
  --name zeek_runner \
  -p 8000:8000 \
  -p 50051:50051 \
  -e CONFIG_FILE="/data/zeek_runner/config.yaml" \
  -v /data/zeek_runner/config.yaml:/data/zeek_runner/config.yaml:ro \
  -v /data/zeek_runner/scripts:/data/zeek_runner/scripts \
  -v /data/zeek_runner/pcaps:/data/zeek_runner/pcaps \
  -v /data/zeek_runner/extracted:/data/zeek_runner/extracted \
  zeek_runner:latest

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
  -v /data/zeek_runner/config.yaml:/data/zeek_runner/config.yaml:ro \
  -v /data/zeek_runner/scripts:/data/zeek_runner/scripts \
  -v /data/zeek_runner/pcaps:/data/zeek_runner/pcaps \
  -v /data/zeek_runner/extracted:/data/zeek_runner/extracted \
  zeek_runner:latest
```

#### 配置优先级

```
配置文件 > 环境变量 > 默认值
```

#### 安全建议

- **Redis 密码**：使用配置文件而非环境变量，避免密码泄露
- **密码一致性**：确保 `config.yaml` 和 `docker-compose.yml` 中的 Redis 密码一致
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
docker-compose -f docker-compose.local.yml up -d

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
- 上层服务下发任务后立即返回任务ID
- 服务后台执行任务，上层服务通过任务ID查询状态
- 适合批量任务、长时间执行任务的场景
- **支持分布式部署**：多个实例共享 Redis 队列

```shell
# 启用异步模式需要配置 Redis（在 config.yaml 中配置）
docker run -d \
  --name zeek_runner \
  -p 8000:8000 \
  -p 50051:50051 \
  -v /data/zeek_runner/config.yaml:/data/zeek_runner/config.yaml:ro \
  -v /data/zeek_runner/scripts:/data/zeek_runner/scripts \
  -v /data/zeek_runner/pcaps:/data/zeek_runner/pcaps \
  -v /data/zeek_runner/extracted:/data/zeek_runner/extracted \
  zeek_runner:latest
```

### 分布式部署

服务支持多实例部署，通过 Redis 实现任务队列共享：

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
│                    Redis 任务队列                                │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  zeek:task:queue  →  [task1, task2, task3, ...]         │   │
│  └─────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  zeek:task:{id}  →  {task metadata & status}            │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

#### 工作流程

1. **任务提交**：任务推入 Redis 队列 (`RPUSH`)
2. **任务抢占**：各实例通过 `BLPOP` 原子性获取任务
3. **任务执行**：获取任务的实例执行分析
4. **状态更新**：执行结果写入 Redis

#### 部署示例

推荐使用 Docker Compose 部署，详见 `docker-compose.yml`。

手动部署多实例：

```shell
# 实例 1
docker run -d \
  --name zeek_runner_1 \
  -p 8001:8000 \
  -p 50051:50051 \
  -v /data/zeek_runner/config.yaml:/data/zeek_runner/config.yaml:ro \
  -v /data/zeek_runner/scripts:/data/zeek_runner/scripts \
  -v /data/zeek_runner/pcaps:/data/zeek_runner/pcaps \
  -v /data/zeek_runner/extracted:/data/zeek_runner/extracted \
  zeek_runner:latest

# 实例 2
docker run -d \
  --name zeek_runner_2 \
  -p 8002:8000 \
  -p 50052:50051 \
  -v /data/zeek_runner/config.yaml:/data/zeek_runner/config.yaml:ro \
  -v /data/zeek_runner/scripts:/data/zeek_runner/scripts \
  -v /data/zeek_runner/pcaps:/data/zeek_runner/pcaps \
  -v /data/zeek_runner/extracted:/data/zeek_runner/extracted \
  zeek_runner:latest

# 实例 3
docker run -d \
  --name zeek_runner_3 \
  -p 8003:8000 \
  -p 50053:50051 \
  -v /data/zeek_runner/config.yaml:/data/zeek_runner/config.yaml:ro \
  -v /data/zeek_runner/scripts:/data/zeek_runner/scripts \
  -v /data/zeek_runner/pcaps:/data/zeek_runner/pcaps \
  -v /data/zeek_runner/extracted:/data/zeek_runner/extracted \
  zeek_runner:latest
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

#### 日志示例

```json
// 新文件注册
{
  "time": "2026-04-10T14:56:59.041Z",
  "level": "INFO",
  "msg": "file registered in task",
  "hash": "d1c925edf5352cf1",
  "path": "/data/zeek/extracted/task-001/geektime-rust-master.zip",
  "taskID": "7f44ea95e57b9bb8416b55a93d01b315"
}

// 任务内重复文件
{
  "time": "2026-04-10T14:56:59.041Z",
  "level": "INFO",
  "msg": "duplicate file in task detected",
  "hash": "26ed3bde1930d8c5",
  "newPath": "/data/zeek/extracted/task-001/extract-1712541417.830875-SSL-FAjUIj3Y8rG4VuqAqc",
  "existingPath": "/data/zeek/extracted/task-001/extract-1712541417.830875-SSL-Fp2coG1XPb9TSjio1g",
  "taskID": "7f44ea95e57b9bb8416b55a93d01b315"
}
```

#### 前置服务消费 Kafka

前置服务消费 Kafka 时可根据 `sha256` 字段判断文件是否重复：

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

**分布式部署**（通过 Nginx 负载均衡，端口 80）：
```shell
# 健康检查
curl http://localhost:80/api/v1/healthz

# 版本检查
curl -H "User-Agent: test" -H "Authorization: your-token" http://localhost:80/api/v1/version/zeek

# 直接访问实例（调试用）
curl http://localhost:8001/api/v1/healthz  # 实例1
curl http://localhost:8002/api/v1/healthz  # 实例2
curl http://localhost:8003/api/v1/healthz  # 实例3
```

**完整测试命令**（单实例）：
```shell

# 调用 /api/v1/version/zeek-kafka 接口
curl -H "User-Agent: test" -H "Authorization: your-token" http://localhost:8000/api/v1/version/zeek-kafka

# 测试检测恶意行为发送到kafka 仅notice日志
curl -X POST \
  -H "Content-Type: application/json" \
  -H "User-Agent: test" \
  -H "Authorization: your-token" \
  -d '{
    "pcapPath": "/data/zeek_runner/pcaps/sshguess.pcap",
    "scriptPath": "/data/zeek_runner/scripts/detect_ssh_bruteforce.zeek",
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
    "pcapPath": "/data/zeek_runner/pcaps/sshguess.pcap",
    "scriptPath": "/data/zeek_runner/scripts/detect_ssh_bruteforce.zeek",
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
    "pcapPath": "/data/zeek_runner/pcaps/sshguess.pcap",
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

# 直接访问实例（调试用）
grpcurl -plaintext localhost:50051 list  # 实例1
grpcurl -plaintext localhost:50052 list  # 实例2
grpcurl -plaintext localhost:50053 list  # 实例3
```

**完整测试命令**（单实例）：
```shell

# 调用 zeek 分析 pcap
grpcurl -plaintext -H 'user-agent: test' -H 'authorization: your-token' -d '{
  "taskID": "2333",
  "uuid": "d3db5f67-c441-56a4-9591-c30c3abab24f",
  "onlyNotice": true,
  "pcapID": "pcap-001",
  "pcapPath": "/data/zeek_runner/pcaps/sshguess.pcap",
  "scriptID": "script-001",
  "scriptPath": "/data/zeek_runner/scripts/detect_ssh_bruteforce.zeek"
}' localhost:50051 zeek_runner.ZeekAnalysisService/Analyze

# 异步分析接口（需要 Redis）- 立即返回任务ID
grpcurl -plaintext -H 'user-agent: test' -H 'authorization: your-token' -d '{
  "taskID": "2334",
  "uuid": "d3db5f67-c441-56a4-9591-c30c3abab24f",
  "onlyNotice": true,
  "pcapID": "pcap-001",
  "pcapPath": "/data/zeek_runner/pcaps/sshguess.pcap",
  "scriptID": "script-001",
  "scriptPath": "/data/zeek_runner/scripts/detect_ssh_bruteforce.zeek"
}' localhost:50051 zeek_runner.ZeekAnalysisService/AsyncAnalyze

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
        PcapPath:   "/data/zeek_runner/pcaps/sshguess.pcap",
        ScriptID:   "script-001",
        ScriptPath: "/data/zeek_runner/scripts/detect_ssh_bruteforce.zeek",
    })
    if err != nil {
        log.Fatalf("could not analyze: %v", err)
    }
    fmt.Printf("Analyze Response: %+v\n", analyzeResp)
}
```

#### 批量测试脚本

创建批量测试脚本验证负载均衡和分布式处理：

```shell
# 创建测试脚本 test_batch.sh
cat > test_batch.sh << 'EOF'
#!/bin/bash

TOKEN="token-dpi"
HTTP_URL="http://localhost:80"
GRPC_URL="localhost:50050"

echo "=== 批量测试 HTTP 接口 ==="
for i in {1..10}; do
  curl -s -X POST \
    -H "Content-Type: application/json" \
    -H "User-Agent: test" \
    -H "Authorization: $TOKEN" \
    -d "{
      \"pcapPath\": \"/data/zeek_runner/pcaps/sshguess.pcap\",
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
      \"pcapPath\": \"/data/zeek_runner/pcaps/sshguess.pcap\",
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
docker-compose logs --tail=50 zeek_runner_1 zeek_runner_2 zeek_runner_3 | grep -E "task|instance"
EOF

chmod +x test_batch.sh
./test_batch.sh
```

**观察负载均衡效果**：

```shell
# 查看各实例日志，确认任务被分配到不同实例
docker-compose logs -f zeek_runner_1 zeek_runner_2 zeek_runner_3

# 输出示例：
# zeek_runner_1 | {"level":"INFO","msg":"task","event":"started","taskID":"test-1","instance":"zeek_runner_1-1234"}
# zeek_runner_2 | {"level":"INFO","msg":"task","event":"started","taskID":"test-2","instance":"zeek_runner_2-5678"}
# zeek_runner_3 | {"level":"INFO","msg":"task","event":"started","taskID":"test-3","instance":"zeek_runner_3-9012"}
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
zeek_runner_1: 7 个任务
zeek_runner_2: 6 个任务
zeek_runner_3: 7 个任务
总计: 20 个任务已开始处理

=== 各实例完成的任务数 ===
zeek_runner_1: 7 个任务
zeek_runner_2: 6 个任务
zeek_runner_3: 7 个任务
总计: 20 个任务已完成

=== 多副本效果验证 ===
✅ zeek_runner_1 处理了 7 个任务
✅ zeek_runner_2 处理了 6 个任务
✅ zeek_runner_3 处理了 7 个任务

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
    "pcapPath": "/data/zeek_runner/file_extract_scripts/xxx.pcap",
    "scriptPath": "/data/zeek_runner/file_extract_scripts/extract_http.zeek",
    "uuid": "233",
    "taskID": "122",
    "pcapID": "pcap-001",
    "scriptID": "script-001"
  }' \
  http://localhost:8000/api/v1/analyze
```

### docker-compose部署
```shell
docker-compose up -d
docker-compose down

本地
docker-compose -f docker-compose.local.yml up -d
docker-compose -f docker-compose.local.yml down
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