# http_user_agent.zeek
@load base/protocols/http

# 定义可疑的 User-Agent 列表
global suspicious_agents = ["curl", "wget", "python-requests", "masscan"];

# 定义通知类型
redef enum Notice::Type += {
    Suspicious_User_Agent
};

# 使用正确的 http_request 事件原型
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
    # 调试输出：打印 HTTP 请求的基本信息
    print fmt("HTTP Request: Method=%s, URI=%s, Version=%s", method, original_URI, version);

    # 检查 c$http 记录是否存在
    if ( c?$http ) {
        print fmt("c$http record: %s", c$http);

        # 检查 User-Agent 是否属于已知的恶意工具
        if ( c$http?$user_agent ) {  # 检查是否存在 user_agent 字段
            local user_agent = to_lower(c$http$user_agent);  # 获取 User-Agent 信息并转换为小写
            print fmt("User-Agent: %s", user_agent);  # 调试输出：打印 User-Agent

            for ( agent in suspicious_agents ) {
                if ( agent in user_agent ) {  # 检查 User-Agent 是否包含可疑字符串
                    print fmt("Suspicious User-Agent detected from %s: %s", c$id$orig_h, user_agent);
                    # 标记为恶意 User-Agent 请求
                    NOTICE([$note=Suspicious_User_Agent,
                            $msg=fmt("Suspicious User-Agent detected: %s", user_agent),
                            $conn=c]);
                }
            }
        } else {
            print "No User-Agent found in HTTP request.";  # 调试输出：未找到 User-Agent
        }
    } else {
        print "No c$http record found.";  # 调试输出：未找到 c$http 记录
    }
}