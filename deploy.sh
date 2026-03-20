#!/bin/bash

# 设置环境变量
export ZEEK_WORKERS=4
export ZEEK_PACKET_QUEUE_SIZE=50000
export ZEEK_TIMEOUT_MINUTES=10
export ZEEK_MEMORY_LIMIT=2048
export ZEEK_WORKER_MEMORY_LIMIT=512

# 构建 Docker 镜像
#docker build -t zeek_runner:2.2 .

# 停止并删除旧容器（如果存在）
docker stop zeek_runner || true
docker rm zeek_runner || true

# 启动新容器
docker run -d \
    --name zeek_runner \
    -p 8000:8000 \
    -p 50051:50051 \
    -e KAFKA_BROKERS="192.168.11.186:9092" \
    -v /Users/randolph/go/netflow:/Users/randolph/go/netflow \
    -v /Users/randolph/go/malicious_behavior:/Users/randolph/go/malicious_behavior \
    -v /Users/randolph/goodjob/zeek_runner/custom/config.zeek:/usr/local/zeek/share/zeek/base/custom/config.zeek \
    zeek_runner:2.2

# 检查容器状态
docker ps | grep zeek_runner 