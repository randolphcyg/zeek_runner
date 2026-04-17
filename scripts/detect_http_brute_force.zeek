# 脚本唯一标识符 - 不要修改此ID
const SCRIPT_ID = "DETECT_HTTP_BRUTE_FORCE_v1";

# 恶意行为检测脚本配置
# 行为类型：HTTP暴力破解攻击
# 行为分类：认证攻击
# 行为描述：检测短时间内多次HTTP登录失败的暴力破解尝试

@load base/protocols/http
@load base/frameworks/notice

module HTTPBruteForce;

export {
    redef enum Notice::Type += {
        ## 当检测到HTTP暴力破解尝试时触发
        HTTP_Brute_Force_Detected
    };

    ## 触发告警的失败次数阈值
    const failure_threshold: count = 5 &redef;

    ## 时间窗口（秒）
    const time_window: interval = 60sec &redef;

    ## 常见的登录路径列表
    const login_paths: set[string] = {
        "/login",
        "/signin",
        "/auth",
        "/login.php",
        "/signin.php",
        "/auth.php",
        "/wp-login.php",
        "/admin",
        "/admin/login",
        "/admin/signin",
        "/admin/auth"
    } &redef;

    ## 记录每个IP的登录失败信息
    type FailureInfo: record {
        failure_count: count;
        first_attempt: time;
        last_attempt: time;
    };

    ## 存储每个IP的失败信息
    global failure_info: table[addr] of FailureInfo = { };
}

# 检查是否为登录路径
function is_login_path(uri: string): bool {
    return uri in login_paths;
}

# 事件: HTTP请求
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
    # 打印HTTP请求信息
    print fmt("HTTP请求: 方法 %s URI %s 版本 %s 源IP %s 目标IP %s", method, original_URI, version, c$id$orig_h, c$id$resp_h);
    
    # 检查是否为登录路径
    if ( is_login_path(original_URI) ) {
        local src_ip = c$id$orig_h;
        local now = network_time();
        
        # 更新失败信息
        if ( src_ip in failure_info ) {
            # 检查是否在时间窗口内
            if ( now - failure_info[src_ip]$first_attempt <= time_window ) {
                failure_info[src_ip]$failure_count += 1;
                failure_info[src_ip]$last_attempt = now;
            } else {
                # 超出时间窗口，重置计数
                failure_info[src_ip] = FailureInfo($failure_count=1, $first_attempt=now, $last_attempt=now);
            }
        } else {
            # 首次失败
            failure_info[src_ip] = FailureInfo($failure_count=1, $first_attempt=now, $last_attempt=now);
        }
        
        # 打印失败信息
        print fmt("HTTP登录失败: 主机 %s URI %s 失败次数 %d", src_ip, original_URI, failure_info[src_ip]$failure_count);
        
        # 检查是否超过阈值
        if ( failure_info[src_ip]$failure_count >= failure_threshold ) {
            local msg = fmt("检测到HTTP暴力破解尝试: 主机 %s 登录失败 %d 次，目标URL %s，时间窗口 %s", 
                           src_ip, failure_info[src_ip]$failure_count, original_URI, time_window);
            NOTICE([$note=HTTP_Brute_Force_Detected,
                    $msg=msg,
                    $src=src_ip]);
            print fmt("HTTP暴力破解告警: %s", msg);
        }
    }
}

# 事件: 连接结束时检查失败次数
event connection_state_remove(c: connection) {
    local src_ip = c$id$orig_h;
    
    # 检查是否有登录失败记录
    if ( src_ip in failure_info && failure_info[src_ip]$failure_count >= failure_threshold ) {
        local msg = fmt("检测到HTTP暴力破解尝试: 主机 %s 登录失败 %d 次，时间窗口 %s", 
                       src_ip, failure_info[src_ip]$failure_count, time_window);
        NOTICE([$note=HTTP_Brute_Force_Detected,
                $msg=msg,
                $src=src_ip]);
        print fmt("HTTP暴力破解告警: %s", msg);
    }
}

