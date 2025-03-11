# go + zeek7.1.0 + zeek-kafka(Custom enhanced version) + librdkafka2.8.0 + kafka = zeek_runner

## pcap流量包及zeek脚本说明
```shell
大部分流量包不上传了,省空间，可以去开源网站下载测试;

脚本从一些仓库找到并修改,后续还会修正和更新;

init.zeek脚本后续根据服务需要还会修正;

若有高并发需求时,可以通过拓展zeek节点和runner多副本增加并发;
```

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
```shell
# 基础镜像
docker pull golang:1.24.0 --platform linux/amd64
docker pull zeek/zeek:7.1.0 --platform linux/amd64

# 构建
docker build -f ./Dockerfile -t zeek_runner:1.0 .
sudo docker build -t zeek_runner:1.0 . --platform linux/amd64
# 容器导出
sudo docker save zeek_runner:1.0  | gzip > zeek_runner_1_0.tar.gz
# 解压镜像
docker load -i zeek_runner_1_0.tar.gz

# 运行 一定保证宿主机挂载脚本和pcap文件路径和容器中一致，这样传给zeek脚本的路径可以轻松定位到宿主机文件位置！！！
docker run -d \
  --name zeek_runner \
  -p 8000:8000 \
  -v /opt/zeek_runner/scripts:/app/scripts \
  -v /opt/zeek_runner/pcaps:/app/pcaps \
  -v /opt/zeek_runner/init.zeek:/app/init.zeek \
  zeek_runner:1.0

# 测试检测恶意行为发送到kafka 仅notice日志
curl -X POST -d "pcap_file_path=/opt/nas/pcaps/sshguess.pcap&zeek_script_path=/opt/nas/scripts/brtforce.zeek&only_notice=true&timestamp=2025-03-10T12:13:14Z" http://localhost:8000/analyze
# 所有日志除notice
curl -X POST -d "pcap_file_path=/opt/nas/pcaps/sshguess.pcap&zeek_script_path=/opt/nas/scripts/brtforce.zeek&only_notice=false&timestamp=2025-03-10T12:13:14Z" http://localhost:8000/analyze
# 调用 /version 接口
curl http://localhost:8000/version

# 调用 /check-zeek-kafka 接口
curl http://localhost:8000/check-zeek-kafka
```

## 直接使用本机zeek测试
```shell
bruteforce
# init.zeek是自定义配置的 包含对kafka配置和消息的设置;本地测试时可以不指定，指定了会将消息发送到kafka,本地不生成log文件
# ONLY_NOTICE=true 环境变量设置为true只发送notice日志 为false发送所有日志(除notice)
# go程序中 init.zeek 不需要上层调用者赋值; 只需要给定pcap文件路径 脚本路径 only_notice三个参数;
ONLY_NOTICE=true ZEEK_SCRIPT_PATH=/opt/nas/scripts/brtforce.zeek PCAP_FILE_PATH=/opt/nas/pcaps/sshguess.pcap zeek -Cr /opt/nas/pcaps/sshguess.pcap /Users/randolph/goodjob/zeek_runner/init.zeek /opt/nas/scripts/brtforce.zeek

# dns ddos
zeek -Cr /opt/nas/pcaps/amp.dns.RRSIG.fragmented.pcap \
/opt/nas/scripts/dns_ddos_script.zeek

# http dos
zeek -Cr /opt/nas/pcaps/HTTPDoSNovember2021.pcapng \
/opt/nas/scripts/http_dos.zeek

# synflood
zeek -Cr /opt/nas/pcaps/SYNflood.pcap \
/opt/nas/scripts/synflood_detection.zeek

# rfc_scp
zeek -Cr /opt/nas/pcaps/scp.pcapng \
/opt/nas/scripts/rfc_scp.zeek
```

## docker-compose部署
```shell
docker-compose up -d
docker-compose down
```