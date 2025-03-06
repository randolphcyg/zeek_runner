# This script detects potential Denial of Service (DoS) attacks
module HTTPDOS;

# Define the thresholds for each indicator
const HTTP_THRESHOLD: count = 100;
const TIME_WINDOW: interval = 10sec;

redef enum Notice::Type += {
    HTTPDos
};

# 存储每个源 IP 的请求计数和时间戳
global http_request_count: table[addr] of count = {};
global http_request_time: table[addr] of time = {};

function generate_http_dos_notice(c: connection, stats: http_stats_rec) {
    local client_ip = c$id$orig_h;

    # 使用 in 操作符判断表中是否存在该键
    if (!(client_ip in http_request_count)) {
        http_request_count[client_ip] = 1;
        http_request_time[client_ip] = network_time();
    } else {
        # 手动增加计数值
        http_request_count[client_ip] = http_request_count[client_ip] + 1;
        if (http_request_count[client_ip] > HTTP_THRESHOLD && network_time() - http_request_time[client_ip] < TIME_WINDOW) {
            NOTICE([
                $note = HTTPDos,
                $msg = fmt("Potential HTTP DOS detected from %s to %s", c$id$orig_h, c$id$resp_h),
                $conn = c,
                $uid = c$uid
            ]);
            # 重置计数和时间
            http_request_count[client_ip] = 0;
            http_request_time[client_ip] = network_time();
        }
    }
}

event http_stats(c: connection, stats: http_stats_rec) {
    # Check for an HTTP flood attack
    generate_http_dos_notice(c, stats);
}