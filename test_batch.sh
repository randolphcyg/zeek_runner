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
      \"pcapPath\": \"/opt/zeek_runner/pcaps/sshguess.pcap\",
      \"scriptPath\": \"/opt/zeek_runner/scripts/detect_ssh_bruteforce.zeek\",
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
      \"pcapPath\": \"/opt/zeek_runner/pcaps/sshguess.pcap\",
      \"scriptPath\": \"/opt/zeek_runner/scripts/detect_ssh_bruteforce.zeek\",
      \"pcapID\": \"pcap-$i\",
      \"scriptID\": \"script-$i\"
    }" \
    "$GRPC_URL" zeek_runner.ZeekAnalysisService/AsyncAnalyze &
done
wait
echo "gRPC 批量测试完成"

echo ""
echo "=== 查看任务状态 ==="
docker-compose logs --tail=50 zeek_runner_1 zeek_runner_2 zeek_runner_3 2>/dev/null | grep -E "task|instance" || echo "请手动查看日志: docker-compose logs -f"

echo ""
echo "=== 测试完成 ==="
echo "查看实时日志: docker-compose logs -f zeek_runner_1 zeek_runner_2 zeek_runner_3"
