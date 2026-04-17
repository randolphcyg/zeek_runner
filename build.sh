#!/bin/bash
set -e

# 获取 Git 提交哈希
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# 获取当前时间
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# 版本号（使用 Git 提交哈希作为版本）
VERSION="5.0"

echo "========================================"
echo "  Zeek Runner 构建脚本"
echo "========================================"
echo "版本: $VERSION"
echo "Git 提交: $GIT_COMMIT"
echo "构建时间: $BUILD_TIME"
echo "========================================"

# 构建镜像
echo "正在构建 Docker 镜像..."
docker build \
  --build-arg VERSION="$VERSION" \
  --build-arg BUILD_TIME="$BUILD_TIME" \
  --build-arg GIT_COMMIT="$GIT_COMMIT" \
  -t zeek_runner:"$VERSION" \
  -t zeek_runner:latest \
  --platform linux/amd64 \
  . 

# 打包镜像
echo "正在打包镜像..."
docker save zeek_runner:latest | gzip > zeek_runner.tar.gz

echo "========================================"
echo "构建完成！"
echo "镜像文件: zeek_runner.tar.gz"
echo "========================================"