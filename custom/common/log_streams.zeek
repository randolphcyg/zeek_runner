# Zeek 日志流管理。
# 原始日志不再通过 Kafka 插件写入旧 Topic（zeek_raw_notice / zeek_logs 等）。
# 所有结构化事件由 zeek_runner Go 代码读取 .log 文件后发布到新 Topic：
#   - zeek_detection_events  (subtask_hit, subtask_completed, parent_completed 等)
#   - zeek_verification_logs (验证模式全量日志)
#   - zeek_extract_events    (文件提取事件)
# 此文件仅保留日志流管理逻辑（按模式禁用不需要的日志流）和兼容函数签名。

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
    }

# 兼容旧脚本调用，不再添加 Kafka filter
function ensure_intel_kafka_stream()
    {
    intel_kafka_filter_added = T;
    }

function ensure_notice_kafka_stream()
    {
    }

function ensure_files_kafka_stream()
    {
    }

event zeek_init() &priority=10
    {
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
