# 第一阶段：构建阶段
FROM golang:1.24.0 AS builder

LABEL stage=gobuilder

# 设置 Go 环境变量
ENV PATH="/usr/local/go/bin:${PATH}"

# 设置工作目录
WORKDIR /app

# 复制 Go 依赖文件并下载依赖
COPY go.mod go.sum ./
RUN go mod download

# 复制全部代码
COPY . .

# 构建 Go 应用
RUN CGO_ENABLED=0 go build -o zeek_runner .

# 使用官方的 Zeek 镜像作为基础
FROM zeek/zeek:7.1.0

# 设置环境变量，避免交互提示
ENV DEBIAN_FRONTEND=noninteractive

# 安装 Go 和 Kafka 插件依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    cmake \
    make \
    curl \
    unzip \
    build-essential \
    libpcap-dev \
    libssl-dev \
    librdkafka-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 下载并解压 zeek-kafka 插件
RUN curl -L -o /zeek-kafka.zip https://github.com/SeisoLLC/zeek-kafka/archive/refs/tags/v1.2.0.zip \
    && unzip /zeek-kafka.zip -d / \
    && mv /zeek-kafka-1.2.0 /zeek-kafka \
    && rm /zeek-kafka.zip \
    && cd /zeek-kafka \
    && ./configure \
    && make \
    && make install \
    && cd / \
    && rm -rf /zeek-kafka

# 设置工作目录
WORKDIR /app

# 复制编译好的二进制文件
COPY --from=builder /app/zeek_runner .

# 赋予二进制文件执行权限
RUN chmod +x zeek_runner

# 复制通用配置文件到 Zeek 脚本搜索路径
COPY init.zeek /app/

# 暴露 API 端口
EXPOSE 8000

# 启动服务
CMD ["./zeek_runner"]