#!/bin/bash

set -e

VERSION=${1:-"latest"}
OUTPUT_DIR="./offline_package"

echo "=== 准备离线部署包 ==="
echo "版本: $VERSION"
echo "输出目录: $OUTPUT_DIR"

mkdir -p $OUTPUT_DIR

echo ""
echo "=== 1. 拉取基础镜像 ==="
docker pull redis:8-alpine --platform linux/amd64
docker pull nginx:1.28-alpine --platform linux/amd64

echo ""
echo "=== 2. 构建 zeek_runner 镜像 ==="
docker build -t zeek_runner:$VERSION . --platform linux/amd64

echo ""
echo "=== 3. 导出镜像 ==="
echo "导出 zeek_runner..."
docker save zeek_runner:$VERSION | gzip > $OUTPUT_DIR/zeek_runner_$VERSION.tar.gz

echo "导出 redis..."
docker save redis:8-alpine | gzip > $OUTPUT_DIR/redis.tar.gz

echo "导出 nginx..."
docker save nginx:1.28-alpine | gzip > $OUTPUT_DIR/nginx.tar.gz

echo ""
echo "=== 4. 复制配置文件 ==="
cp docker-compose.yml $OUTPUT_DIR/
cp nginx.conf $OUTPUT_DIR/
cp config.example.yaml $OUTPUT_DIR/config.yaml

echo ""
echo "=== 5. 创建部署脚本 ==="
cat > $OUTPUT_DIR/deploy.sh << 'EOF'
#!/bin/bash

set -e

echo "=== 加载镜像 ==="
docker load -i zeek_runner_*.tar.gz
docker load -i redis.tar.gz
docker load -i nginx.tar.gz

echo ""
echo "=== 创建目录结构 ==="
sudo mkdir -p /opt/zeek_runner/{pcaps,scripts,extracted,custom}
sudo mkdir -p /opt/zeek_runner/config

echo ""
echo "=== 复制配置文件 ==="
if [ ! -f /opt/zeek_runner/config.yaml ]; then
    sudo cp config.yaml /opt/zeek_runner/config.yaml
    echo "请编辑 /opt/zeek_runner/config.yaml 配置文件"
fi

if [ ! -f /opt/zeek_runner/custom/config.zeek ]; then
    echo "请将 Zeek 配置文件放到 /opt/zeek_runner/custom/config.zeek"
fi

echo ""
echo "=== 启动服务 ==="
docker-compose up -d

echo ""
echo "=== 查看服务状态 ==="
docker-compose ps

echo ""
echo "=== 部署完成 ==="
echo "HTTP API: http://localhost:80"
echo "gRPC: localhost:50050"
echo "Redis: localhost:6380"
echo ""
echo "=== 重要提示 ==="
echo "请修改以下配置："
echo "1. 编辑 config.yaml 中的 Redis 密码（与 docker-compose.yml 中一致）"
echo "2. 编辑 config.yaml 中的 Kafka 地址"
echo "3. 编辑 config.yaml 中的 AUTH_TOKENS"
EOF

chmod +x $OUTPUT_DIR/deploy.sh

echo ""
echo "=== 6. 创建卸载脚本 ==="
cat > $OUTPUT_DIR/uninstall.sh << 'EOF'
#!/bin/bash

echo "=== 停止服务 ==="
docker-compose down

echo ""
echo "=== 删除镜像 ==="
docker rmi zeek_runner:latest 2>/dev/null || true
docker rmi redis:8-alpine 2>/dev/null || true
docker rmi nginx:1.28-alpine 2>/dev/null || true

echo ""
echo "=== 清理数据 (可选) ==="
read -p "是否删除 Redis 数据? (y/N): " confirm
if [ "$confirm" = "y" ]; then
    docker volume rm zeek_runner_redis_data 2>/dev/null || true
fi

echo "卸载完成"
EOF

chmod +x $OUTPUT_DIR/uninstall.sh

echo ""
echo "=== 打包完成 ==="
echo ""
echo "离线包内容:"
ls -lh $OUTPUT_DIR/
echo ""
echo "总大小:"
du -sh $OUTPUT_DIR/
echo ""
echo "=== 部署步骤 ==="
echo "1. 将 $OUTPUT_DIR 目录传输到目标服务器"
echo "   scp -r $OUTPUT_DIR user@server:/opt/zeek_runner_offline/"
echo ""
echo "2. 在目标服务器执行:"
echo "   cd /opt/zeek_runner_offline"
echo "   ./deploy.sh"
echo ""
echo "3. 编辑配置文件:"
echo "   sudo vi /opt/zeek_runner/config.yaml"
