@load Seiso/Kafka  # 用于将 JSON 日志发送到 Kafka

redef LogAscii::use_json = T;
redef LogAscii::json_timestamps = JSON::TS_ISO8601;
redef Log::default_writer = Log::WRITER_KAFKAWRITER; # 默认日志写入器为 KafkaWriter

# 配置 Kafka 相关信息
redef Kafka::tag_json = T;
redef Kafka::topic_name = "zeek_log";
redef Kafka::kafka_conf += {
    ["metadata.broker.list"] = "192.168.11.71:9092",
    ["compression.codec"] = "snappy"
};

# 获取环境变量 ONLY_NOTICE 的值
global only_notice = getenv("ONLY_NOTICE");
# 脚本路径和 PCAP 文件路径
global script_path = getenv("ZEEK_SCRIPT_PATH");
global pcap_file_path = getenv("PCAP_FILE_PATH");
global uuid = getenv("UUID");
global task_id = getenv("TASK_ID");

# 指定key 二次开发zeek-kafka库才有
redef Kafka::key_name = pcap_file_path;

# 初始化方法
event zeek_init() {
    # uuid
    if (uuid != "") {
        Kafka::headers["uuid"] = uuid;
    }
    # task_id
    if (task_id != "") {
        Kafka::headers["task_id"] = task_id;
    }
    # PCAP文件路径
    if (pcap_file_path != "") {
        Kafka::headers["pcap_file_path"] = pcap_file_path;
    }
    # 脚本路径
    if (script_path != "") {
        Kafka::headers["script_path"] = script_path;
    }

    # 根据环境变量的值决定加载哪个基础脚本
    if (only_notice == "true") {
        print fmt("##### output: only notice log");

        # 创建一个列表来存储需要禁用的日志流
        local streams_to_disable: set[Log::ID] = set();
        # 遍历所有活动的日志流 将非 notice 日志流添加到禁用列表中
        for (stream_id in Log::active_streams) {
            # 检查是否为 notice 日志流
            if (stream_id != Notice::LOG) {
                add streams_to_disable[stream_id];
            }
        }

        # 禁用在列表中的日志流
        for (stream_id in streams_to_disable) {
            print fmt("Disabling stream: %s", stream_id);
            Log::disable_stream(stream_id);
        }
    } else {
        print fmt("##### output: full logs");
        Log::disable_stream(Notice::LOG);
    }
}

# 设置通知策略
hook Notice::policy(n: Notice::Info) {
    add n$actions[Notice::ACTION_LOG];
}