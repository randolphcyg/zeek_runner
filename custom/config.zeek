@load Seiso/Kafka  # 用于将 JSON 日志发送到 Kafka

# 全局Kafka配置
redef Kafka::topic_name = "zeek_logs";  # 全局默认topic
redef Kafka::kafka_conf += {
    ["metadata.broker.list"] = getenv("KAFKA_BROKERS"),
    ["compression.codec"] = "snappy",
    ["batch.num.messages"] = "10000"  # 提高批处理效率
};
redef Kafka::json_timestamps = JSON::TS_ISO8601;

# 环境变量
global only_notice = getenv("ONLY_NOTICE");  # 是否只可能生成notice日志
global task_id = getenv("TASK_ID");  # TASK_ID
global uuid = getenv("UUID");  # UUID
global script_path = getenv("ZEEK_SCRIPT_PATH");  # 脚本路径
global pcap_file_path = getenv("PCAP_FILE_PATH");  # PCAP 文件路径

# 指定key 二次开发zeek-kafka库才有
redef Kafka::key_name = pcap_file_path;

# 自定义任务完成日志
export {
    module TaskStatus;
    redef enum Log::ID += { LOG };

    type Info: record {
        completed_time: string &log;
    };
}

# 初始化方法
event zeek_init() {
    # 自定义日志 任务状态
    Log::create_stream(TaskStatus::LOG, [$columns=TaskStatus::Info, $path="task_status"]);

    # 设置固定headers
    Kafka::headers["task_id"] = task_id;
    Kafka::headers["uuid"] = uuid;
    Kafka::headers["pcap_file_path"] = pcap_file_path;
    Kafka::headers["script_path"] = script_path;

    # 不同日志流发到不同topic
    for (stream_id in Log::active_streams) {
        # 移除默认的文件过滤器 关键：避免本地文件
        Log::remove_filter(stream_id, "default");

        local stream_name = Log::active_streams[stream_id]$path;
        local filter_config: Log::Filter;

        # 配置不同日志流的 Kafka 过滤器
        if (stream_id == Notice::LOG) {
            filter_config = [
                $name = "kafka-notice",
                $writer = Log::WRITER_KAFKAWRITER,
                $config = table(["topic_name"] = "zeek_notice")
            ];
        } else if (stream_id == TaskStatus::LOG) {
            filter_config = [
                $name = "kafka-task-status",
                $writer = Log::WRITER_KAFKAWRITER,
                $config = table(["topic_name"] = "zeek_task_status")
            ];
        } else {  # 其他所有日志
            filter_config = [
                $name = "kafka-default",
                $writer = Log::WRITER_KAFKAWRITER,
                $config = table(["topic_name"] = Kafka::topic_name)
            ];
        }
        Log::add_filter(stream_id, filter_config);
    }

    # 是否只输出 notice、TaskStatus 日志
    if (only_notice == "true") {
        local streams_to_disable: set[Log::ID] = set();
        for (id in Log::active_streams) {
            if (id != Notice::LOG && id != TaskStatus::LOG) {
                add streams_to_disable[id];
            }
        }

        for (id in streams_to_disable) {
            Log::disable_stream(id);
        }
    } else {
        Log::disable_stream(Notice::LOG);
    }
}

# 设置通知策略
hook Notice::policy(n: Notice::Info) {
    add n$actions[Notice::ACTION_LOG];
}

# 任务完成事件
event zeek_done() {
    local formatted_time = strftime("%Y-%m-%dT%H:%M:%S+08:00", current_time());
    local log_info = TaskStatus::Info(
        $completed_time = formatted_time
    );
    Log::write(TaskStatus::LOG, log_info);
}