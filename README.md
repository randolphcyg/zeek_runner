# go + zeek7.1.0 + Seiso/Kafka release 1.2.0 + librdkafka2.8.0 + kafka = zeek_runner

docker-compose部署
```shell
docker-compose up -d
docker-compose down
```

docker部署
```shell
docker pull golang:1.24.0
docker pull zeek/zeek:latest --platform linux/amd64

# 构建
sudo docker build --platform linux/amd64 -t zeek_runner:3.0 .
sudo docker build -t zeek_runner:3.0 .

docker build -t zeek_runner .
# 容器导出
sudo docker save zeek_runner:3.0  | gzip > zeek_runner_3_0.tar.gz
# 解压镜像
docker load -i zeek_runner_3_0.tar.gz

# 运行 一定保证宿主机挂载脚本和pcap文件路径和容器中一致，这样传给zeek脚本的路径可以轻松定位到宿主机文件位置！！！
docker run -d \
  --name zeek_runner \
  -p 8000:8000 \
  -v /opt/nas/scripts:/opt/nas/scripts \
  -v /opt/nas/pcaps:/opt/nas/pcaps \
  -v /opt/nas/logs:/opt/nas/logs \
  zeek_runner:3.0

# 测试检测恶意行为发送到kafka 仅notice日志
curl -X POST -d "pcap_file_path=/opt/nas/pcaps/bruteforce/sshguess.pcap&zeek_script_path=/opt/nas/scripts/bruteforce/brtforce.zeek" http://localhost:8000/analyze
  
# 调用 /version 接口
curl http://localhost:8000/version

# 调用 /check-zeek-kafka 接口
curl http://localhost:8000/check-zeek-kafka
```