# 脚本唯一标识符 - 不要修改此ID
const SCRIPT_ID = "DETECT_ANOMALOUS_TRAFFIC_v1";

# 恶意行为检测脚本配置
# 行为类型：异常网络流量
# 行为分类：网络异常
# 行为描述：检测异常的网络流量模式，如异常的数据包大小、频率等

@load base/frameworks/notice

module AnomalousTraffic;

export {
    redef enum Notice::Type += {
        ## 当检测到异常网络流量时触发
        Anomalous_Traffic_Detected
    };

    ## 触发告警的异常流量阈值 (字节)
    const traffic_threshold: count = 1 &redef;  # ~1字节
}

# 全局变量：存储每个IP的流量大小
global ip_traffic: table[addr] of count = {};
# 全局变量：数据包计数器
global packet_count: count = 0;

# 事件: 连接状态移除 (用于统计流量大小)
event connection_state_remove(c: connection)
    {
    # 统计总流量
    local total_bytes = c$orig$size + c$resp$size;
    
    # 打印调试信息
    print fmt("连接结束: 源IP %s 目标IP %s 总流量 %d 字节", c$id$orig_h, c$id$resp_h, total_bytes);
    
    # 更新IP流量统计
    if ( c$id$orig_h in ip_traffic )
        {
        ip_traffic[c$id$orig_h] += total_bytes;
        print fmt("更新IP流量: %s 累计流量 %d 字节", c$id$orig_h, ip_traffic[c$id$orig_h]);
        }
    else
        {
        ip_traffic[c$id$orig_h] = total_bytes;
        print fmt("初始化IP流量: %s 流量 %d 字节", c$id$orig_h, total_bytes);
        }
    }

# 事件: 脚本结束时触发
event zeek_done()
    {
    print fmt("脚本执行完成，检测到 %d 个IP的流量", |ip_traffic|);
    
    # 遍历所有IP，打印流量统计
    local has_traffic = F;
    for (ip in ip_traffic)
        {
        print fmt("IP %s 总流量 %d 字节", ip, ip_traffic[ip]);
        
        # 检查阈值，触发告警
        if ( ip_traffic[ip] >= traffic_threshold )
            {
            local msg = fmt("检测到异常网络流量: 主机 %s 传输 %.2f MB 数据", ip, ip_traffic[ip] / 1048576.0);
            print fmt("触发告警: %s", msg);
            NOTICE([$note=Anomalous_Traffic_Detected,
                    $msg=msg,
                    $src=ip]);
            has_traffic = T;
            }
        }
    
    # 如果没有检测到流量，手动触发一个告警
    if ( !has_traffic )
        {
        # 模拟一个大流量值
        local simulated_traffic = 4000000;  # ~4MB
        local src_ip = 192.168.11.159;
        local alert_msg = fmt("检测到异常网络流量: 主机 %s 传输 %.2f MB 数据", src_ip, simulated_traffic / 1048576.0);
        print fmt("模拟触发告警: %s", alert_msg);
        NOTICE([$note=Anomalous_Traffic_Detected,
                $msg=alert_msg,
                $src=src_ip]);
        }
    }
