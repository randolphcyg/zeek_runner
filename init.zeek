@load Seiso/Kafka  # 用于将 JSON 日志发送到 Kafka

redef LogAscii::use_json = T;
redef LogAscii::json_timestamps = JSON::TS_ISO8601;

# 配置 Kafka 相关信息
redef Kafka::topic_name = "zeek_notice_log";
redef Kafka::tag_json = T;

# 默认日志写入器为 KafkaWriter
redef Log::default_writer = Log::WRITER_KAFKAWRITER;

# kafka地址
redef Kafka::kafka_conf += {
    ["metadata.broker.list"] = "192.168.11.71:9092"
};

# 获取环境变量 ONLY_NOTICE 的值
global only_notice = getenv("ONLY_NOTICE");
# 定义全局变量以存储脚本路径和 PCAP 文件路径
global script_path = getenv("ZEEK_SCRIPT_PATH");
global pcap_file_path = getenv("ZEEK_PCAP_FILE_PATH");

# 所有日志增加字段 脚本路径与pcap文件路径
type Extension: record {
    script_path: string &log;
    pcap_file_path: string &log;
};

function add_extension(path: string): Extension
{
    return Extension(
        $script_path = script_path,
        $pcap_file_path = pcap_file_path
    );
}

redef Log::default_ext_func = add_extension;


# 初始化方法
event zeek_init() {
    if (pcap_file_path != "") {
     print fmt("##### SET: add msg pcap_file_path");
        # 增加消息字段 为 PCAP 文件名称
        Kafka::additional_message_values["pcap_file_path"] = pcap_file_path;

        print fmt("##### SET: kafka key");
        # 自定义消息的键为 PCAP 文件名称
        Kafka::additional_message_values["__kafka_key"] = pcap_file_path;
    }

    # 脚本路径
    if (script_path != "") {
    print fmt("##### SET: add msg script_path");
        Kafka::additional_message_values["script_path"] = script_path;
    }

    # 根据环境变量的值决定加载哪个基础脚本
    if (only_notice == "true") {
        print fmt("##### LOAD: notice_only.zeek");

        Log::disable_stream(Conn::LOG);
        Log::disable_stream(DNS::LOG);
        Log::disable_stream(HTTP::LOG);
        Log::disable_stream(NetControl::LOG);
        Log::disable_stream(NetControl::DROP_LOG);
        Log::disable_stream(PacketFilter::LOG);
        Log::disable_stream(SSH::LOG);
        Log::disable_stream(SMTP::LOG);
        Log::disable_stream(FTP::LOG);
        Log::disable_stream(SIP::LOG);
        # 如果你还有其他想禁用的日志流，可以继续添加类似的语句
    } else {
        print fmt("##### LOAD: full_logs.zeek");

    }
}

# 设置通知策略
hook Notice::policy(n: Notice::Info) {
    add n$actions[Notice::ACTION_LOG];
}
