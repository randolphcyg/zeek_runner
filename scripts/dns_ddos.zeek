# Define a new module named "DDosAttacks"
module DDosAttacks;

# Add a new type of notice to the existing set of notice types
redef enum Notice::Type += {
    DNSDDoSAmplification
};

# 定义一个全局变量，用于存储要检测的域名列表
global monitored_domains: set[string] = { "peacecorps.gov", "pizzaseo.com" };

# Define a function named "generate_ddos_notice"
function generate_ddos_notice(c: connection, query: string) {
    # Remove any whitespace from the DNS query string
    local query1: string = strip(query);

    # 检查查询的域名是否在监控列表中
    if (query1 in monitored_domains) {
        # Generate a new notice of type DNSDDoSAmplification if the query matches
        NOTICE([$note = DNSDDoSAmplification,
            $msg = fmt("Possible DNS DDoS Amplification Attack"),
            $conn = c,
            $uid = c$uid
        ]);
    }
    else {
        # 这里直接返回，不生成非攻击情况下的通知和日志
        return;
    }
}

# Define an event handler for DNS requests
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count, original_query: string) {
    # Call the "generate_ddos_notice" function with the connection object and DNS query string as parameters
    generate_ddos_notice(c, query);
}

# Define an event handler for DNS query replies
event dns_query_reply(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count, original_query: string) {
    # Call the "generate_ddos_notice" function with the connection object and DNS query string as parameters
    generate_ddos_notice(c, query);
}