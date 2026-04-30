redef Kafka::topic_name = "zeek_logs";

redef Kafka::kafka_conf += {
    ["bootstrap.servers"] = getenv("KAFKA_BROKERS"),
    ["metadata.broker.list"] = getenv("KAFKA_BROKERS"),
    ["compression.codec"] = "snappy",
    ["batch.num.messages"] = "1000",
    ["queue.buffering.max.ms"] = "1",
    ["queue.buffering.max.messages"] = "500000",
};

redef Kafka::json_timestamps = JSON::TS_ISO8601;
redef Kafka::max_wait_on_shutdown = to_count(
    getenv("KAFKA_MAX_WAIT_ON_SHUTDOWN") != "" ? getenv("KAFKA_MAX_WAIT_ON_SHUTDOWN") : "10000"
);
redef Kafka::key_name = taskID;

function configure_kafka_stream(id: Log::ID)
    {
    local is_extract_mode = (getenv("EXTRACTED_FILE_PATH") != "");
    local is_detect_mode = (onlyNotice == "true");

    if ( is_extract_mode )
        {
        if ( id != TaskStatus::LOG && id != Intel::LOG )
            {
            Log::disable_stream(id);
            return;
            }
        }
    else if ( is_detect_mode )
        {
        if ( id != Notice::LOG && id != TaskStatus::LOG && id != Intel::LOG )
            {
            Log::disable_stream(id);
            return;
            }
        }

    local topic = Kafka::topic_name;

    if ( id == Notice::LOG )
        topic = "zeek_raw_notice";
    else if ( id == Intel::LOG )
        topic = "zeek_raw_intel";
    else if ( id == TaskStatus::LOG && is_extract_mode )
        topic = "zeek_raw_task_status";

    if ( id in Log::active_streams )
        {
        local filter_name = fmt("kafka-%s", id);
        local filter_config: Log::Filter = [
            $name = filter_name,
            $writer = Log::WRITER_KAFKAWRITER,
            $config = table(["topic_name"] = topic)
        ];
        Log::add_filter(id, filter_config);
        }
    }

function ensure_intel_kafka_stream()
    {
    if ( intel_kafka_filter_added )
        return;

    local filter_config: Log::Filter = [
        $name = "kafka-intel-late-bind",
        $writer = Log::WRITER_KAFKAWRITER,
        $config = table(["topic_name"] = "zeek_raw_intel")
    ];

    Log::add_filter(Intel::LOG, filter_config);
    intel_kafka_filter_added = T;
    }

function ensure_notice_kafka_stream()
    {
    if ( Notice::LOG !in Log::active_streams )
        return;

    local filter_name = "kafka-notice-late-bind";
    if ( filter_name in Log::get_filter_names(Notice::LOG) )
        return;

    local filter_config: Log::Filter = [
        $name = filter_name,
        $writer = Log::WRITER_KAFKAWRITER,
        $config = table(["topic_name"] = "zeek_raw_notice")
    ];

    Log::add_filter(Notice::LOG, filter_config);
    }

function ensure_files_kafka_stream()
    {
    if ( Files::LOG !in Log::active_streams )
        return;

    local filter_name = "kafka-files-late-bind";
    if ( filter_name in Log::get_filter_names(Files::LOG) )
        return;

    local filter_config: Log::Filter = [
        $name = filter_name,
        $writer = Log::WRITER_KAFKAWRITER,
        $config = table(["topic_name"] = "zeek_raw_task_status")
    ];

    Log::add_filter(Files::LOG, filter_config);
    }

event zeek_init() &priority=10
    {
    Kafka::headers["analysisMode"] = current_analysis_mode();
    Kafka::headers["producer"] = "zeek_raw";
    Kafka::headers["eventVersion"] = "1.0";

    Log::create_stream(TaskStatus::LOG, [$columns=TaskStatus::Info, $path="task_status"]);

    local active_stream_ids: set[Log::ID] = set();
    for ( id in Log::active_streams )
        add active_stream_ids[id];

    for ( id in active_stream_ids )
        configure_kafka_stream(id);
    }

event zeek_done()
    {
    local log_info = TaskStatus::Info(
        $completedTime = strftime("%Y-%m-%dT%H:%M:%SZ", current_time())
    );

    Log::write(TaskStatus::LOG, log_info);
    }
