@load Seiso/Kafka

# -------------------------------------------------------------------------
# 1. 全局配置
# -------------------------------------------------------------------------
redef Kafka::topic_name = "zeek_logs";
redef Kafka::kafka_conf += {
    ["metadata.broker.list"] = getenv("KAFKA_BROKERS"),
    ["compression.codec"] = "snappy",
    ["batch.num.messages"] = "10000"
};
redef Kafka::json_timestamps = JSON::TS_ISO8601;

# 环境变量
global taskID = getenv("TASK_ID");
global uuid = getenv("UUID");
global onlyNotice = getenv("ONLY_NOTICE");
global pcapID = getenv("PCAP_ID");
global pcapPath = getenv("PCAP_PATH");
global scriptID = getenv("SCRIPT_ID");
global scriptPath = getenv("SCRIPT_PATH");

redef Kafka::key_name = pcapPath;

# -------------------------------------------------------------------------
# 2. 自定义日志定义
# -------------------------------------------------------------------------
export {
    module TaskStatus;
    redef enum Log::ID += { LOG };

    type Info: record {
        completedTime: string &log;
    };
}

# -------------------------------------------------------------------------
# 3. 核心逻辑封装函数
# -------------------------------------------------------------------------
function configure_kafka_stream(id: Log::ID) {
    # 1. 移除默认 Filter (避免写本地)
    # 注意：如果该流没有 default filter，这行也不会报错
    Log::remove_filter(id, "default");

    # 2. 处理 onlyNotice 逻辑
    if (onlyNotice == "true" && id != Notice::LOG && id != TaskStatus::LOG) {
        Log::disable_stream(id);
        return;
    }

    # 3. 确定 Topic
    local topic = Kafka::topic_name;
    if (id == Notice::LOG) {
        topic = "zeek_notice";
    } else if (id == TaskStatus::LOG) {
        topic = "zeek_task_status";
    } else if (id == Files::LOG) {
        topic = "zeek_extract_files";
    }

    # 4. 添加 Kafka Filter
    local filter_name = fmt("kafka-%s", id);
    local filter_config: Log::Filter = [
        $name = filter_name,
        $writer = Log::WRITER_KAFKAWRITER,
        $config = table(["topic_name"] = topic)
    ];
    Log::add_filter(id, filter_config);
}

# -------------------------------------------------------------------------
# 4. 初始化逻辑 (使用低优先级确保在其他脚本之后运行)
# -------------------------------------------------------------------------
# 使用 priority -10 确保在大多数标准脚本加载完流之后再执行配置
event zeek_init() &priority=-10 {
    # A. 恢复 Header 配置
    if (taskID != "") { Kafka::headers["taskID"] = taskID; }
    if (uuid != "") { Kafka::headers["uuid"] = uuid; }
    if (pcapID != "") { Kafka::headers["pcapID"] = pcapID; }
    if (pcapPath != "") { Kafka::headers["pcapPath"] = pcapPath; }
    if (scriptID != "") { Kafka::headers["scriptID"] = scriptID; }
    if (scriptPath != "") { Kafka::headers["scriptPath"] = scriptPath; }
    if (onlyNotice == "true") { Kafka::headers["onlyNotice"] = onlyNotice; }

    # B. 创建 TaskStatus 流
    Log::create_stream(TaskStatus::LOG, [$columns=TaskStatus::Info, $path="task_status"]);

    # C. 安全遍历逻辑 (修复 iterator invalidation)
    # 1. 先创建一个临时集合，把当前的流ID存下来
    local streams_to_process: set[Log::ID];
    for (id in Log::active_streams) {
        add streams_to_process[id];
    }

    # 2. 遍历临时集合进行配置
    # 这样修改 active_streams 本身就不会影响循环了
    for (id in streams_to_process) {
        configure_kafka_stream(id);
    }
}

# -------------------------------------------------------------------------
# 5. 运行时逻辑
# -------------------------------------------------------------------------
hook Notice::policy(n: Notice::Info) {
    add n$actions[Notice::ACTION_LOG];
}

event zeek_done() {
    local log_info = TaskStatus::Info(
        $completedTime = strftime("%Y-%m-%dT%H:%M:%SZ", current_time())
    );
    Log::write(TaskStatus::LOG, log_info);
}