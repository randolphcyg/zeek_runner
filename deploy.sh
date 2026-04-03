#!/bin/bash

set -e

echo "=== Zeek Runner 部署脚本 ==="
echo ""

if [ "$1" = "compose" ]; then
    echo "使用 Docker Compose 部署..."
    docker-compose up -d
    echo ""
    echo "=== 服务状态 ==="
    docker-compose ps
    echo ""
    echo "=== 访问地址 ==="
    echo "HTTP API (负载均衡): http://localhost:80"
    echo "gRPC (负载均衡): localhost:50050"
    echo "Redis: localhost:6380"
else
    echo "单实例部署..."
    
    if [ ! -f config.yaml ]; then
        echo "错误: config.yaml 不存在"
        echo "请复制 config.example.yaml 并修改配置"
        exit 1
    fi
    
    docker run -d \
        --name zeek_runner \
        -p 8000:8000 \
        -p 50051:50051 \
        -v $(pwd)/pcaps:/opt/zeek_runner/pcaps \
        -v $(pwd)/scripts:/opt/zeek_runner/scripts \
        -v $(pwd)/extracted:/opt/zeek_runner/extracted \
        -v $(pwd)/custom/config.zeek:/usr/local/zeek/share/zeek/base/custom/config.zeek \
        -v $(pwd)/config.yaml:/opt/zeek_runner/config.yaml:ro \
        zeek_runner:latest
    
    echo ""
    echo "=== 服务状态 ==="
    docker ps | grep zeek_runner
    echo ""
    echo "=== 访问地址 ==="
    echo "HTTP API: http://localhost:8000"
    echo "gRPC: localhost:50051"
fi

echo ""
echo "=== 部署完成 ==="
