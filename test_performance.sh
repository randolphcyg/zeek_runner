#!/bin/bash

TOKEN="token-dpi"
TASK_COUNT=20

echo "=========================================="
echo "   多副本并发性能测试"
echo "=========================================="
echo ""

echo "=== 提交 $TASK_COUNT 个异步任务 ==="
echo "HTTP URL: http://localhost:80 (负载均衡)"
echo ""

start_time=$(date +%s)

for i in $(seq 1 $TASK_COUNT); do
    curl -s -X POST \
        -H "Content-Type: application/json" \
        -H "User-Agent: test" \
        -H "Authorization: $TOKEN" \
        -d "{
            \"pcapPath\": \"/opt/zeek_runner/pcaps/sshguess.pcap\",
            \"scriptPath\": \"/opt/zeek_runner/scripts/detect_ssh_bruteforce.zeek\",
            \"onlyNotice\": true,
            \"taskID\": \"perf-test-$i\",
            \"uuid\": \"perf-uuid-$i\",
            \"pcapID\": \"pcap-$i\",
            \"scriptID\": \"script-$i\"
        }" \
        "http://localhost:80/api/v1/analyze/async" > /dev/null &
done

wait
submit_end=$(date +%s)
echo "任务提交完成，耗时: $((submit_end - start_time)) 秒"
echo ""

echo "=== 等待任务执行 (30秒) ==="
sleep 30

echo ""
echo "=========================================="
echo "   测试结果统计"
echo "=========================================="
echo ""

echo "=== 各实例处理的任务数 ==="
total=0
for instance in zeek_runner_1 zeek_runner_2 zeek_runner_3; do
    count=$(docker-compose logs $instance 2>/dev/null | grep "perf-test" | grep "started" | wc -l | tr -d ' ')
    echo "$instance: $count 个任务"
    total=$((total + count))
done
echo "总计: $total 个任务已开始处理"
echo ""

echo "=== 各实例完成的任务数 ==="
completed=0
for instance in zeek_runner_1 zeek_runner_2 zeek_runner_3; do
    count=$(docker-compose logs $instance 2>/dev/null | grep "perf-test" | grep "completed" | wc -l | tr -d ' ')
    echo "$instance: $count 个任务"
    completed=$((completed + count))
done
echo "总计: $completed 个任务已完成"
echo ""

echo "=== 多副本效果验证 ==="
active_instances=0
for instance in zeek_runner_1 zeek_runner_2 zeek_runner_3; do
    count=$(docker-compose logs $instance 2>/dev/null | grep "perf-test" | grep "started" | wc -l | tr -d ' ')
    if [ "$count" -gt 0 ] 2>/dev/null; then
        active_instances=$((active_instances + 1))
        echo "✅ $instance 处理了 $count 个任务"
    fi
done

echo ""
if [ $active_instances -gt 1 ]; then
    echo "✅ 多副本生效！$active_instances 个实例参与处理任务"
    echo ""
    echo "优势说明："
    echo "  - 任务被均匀分配到多个实例"
    echo "  - 单实例故障不影响整体服务"
    echo "  - 可通过增加实例提升处理能力"
else
    echo "⚠️  只有 1 个实例处理任务"
    echo "   请检查 Redis 连接和队列配置"
fi

echo ""
echo "=== 查看详细日志 ==="
echo "docker-compose logs -f zeek_runner_1 zeek_runner_2 zeek_runner_3"
