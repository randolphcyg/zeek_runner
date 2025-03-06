@load base/frameworks/notice
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/frameworks/netcontrol
@load base/protocols/ssh
@load base/frameworks/packet-filter
@load Seiso/Kafka  # 用于将 JSON 日志发送到 Kafka


# 为所有日志增加额外列

# 定义全局变量以存储脚本路径和 PCAP 文件路径
global script_path = getenv("ZEEK_SCRIPT_PATH");
global pcap_file_path = getenv("ZEEK_PCAP_FILE_PATH");

# 增加列
type Extension: record {
    script_path: string &log;
    pcap_file_path: string &log;
};

function add_extension(path: string): Extension
  {
  return Extension($script_path    = script_path,
                   $pcap_file_path      = pcap_file_path);
  }

redef Log::default_ext_func = add_extension;

redef LogAscii::use_json = T;
redef LogAscii::json_timestamps = JSON::TS_ISO8601;

# 配置 Kafka 相关信息
redef Kafka::topic_name = "zeek_notice_topic";
redef Kafka::tag_json = T;

# 默认日志写入器为 KafkaWriter
redef Log::default_writer = Log::WRITER_KAFKAWRITER;

redef Kafka::kafka_conf += {
    ["metadata.broker.list"] = "192.168.11.71:9092"
};

# 禁用除了notice之外其他日志
event zeek_init() {
    print fmt("Analyzing PCAP file: %s", pcap_file_path);
    print fmt("Using script file: %s", script_path);

    Log::disable_stream(Conn::LOG);
    Log::disable_stream(DNS::LOG);
    Log::disable_stream(HTTP::LOG);
    Log::disable_stream(NetControl::LOG);
    Log::disable_stream(NetControl::DROP_LOG);
    Log::disable_stream(PacketFilter::LOG);
    Log::disable_stream(SSH::LOG);
    # 如果你还有其他想禁用的日志流，可以继续添加类似的语句
}

# 设置通知策略
hook Notice::policy(n: Notice::Info) {
    add n$actions[Notice::ACTION_LOG];
}