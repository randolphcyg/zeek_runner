redef LogAscii::use_json = T;
redef LogAscii::json_timestamps = JSON::TS_ISO8601;

# 初始化方法
event zeek_init() {
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
        # print fmt("Disabling stream: %s", stream_id);
        # Log::disable_stream(stream_id);
    }
}

# 设置通知策略
hook Notice::policy(n: Notice::Info) {
    add n$actions[Notice::ACTION_LOG];
}