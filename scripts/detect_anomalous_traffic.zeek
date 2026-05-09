# SCRIPT_ID: DETECT_ANOMALOUS_TRAFFIC_v1
# NoticeTypes: AnomalousTraffic::Anomalous_Traffic_Detected

# 恶意行为检测脚本配置
# 行为类型：异常网络流量
# 行为分类：网络异常
# 行为描述：检测单主机在离线流量包中的异常大流量传输
# 攻击特征：单主机短时间内产生超阈值字节数或连接量，呈现异常突增的大流量传输模式

@load base/frameworks/notice

module AnomalousTraffic;

export {
    redef enum Notice::Type += {
        ## 当检测到异常网络流量时触发
        Anomalous_Traffic_Detected
    };

    ## 单源主机累计传输阈值，默认 4MB；生产环境可按场景调大
    const traffic_threshold: count = 4 * 1024 * 1024 &redef;
}

global ip_traffic: table[addr] of count = {};
global alerted_hosts: set[addr] = set();

event connection_state_remove(c: connection)
    {
    local total_bytes = c$orig$size + c$resp$size;

    if ( c$id$orig_h in ip_traffic )
        ip_traffic[c$id$orig_h] += total_bytes;
    else
        ip_traffic[c$id$orig_h] = total_bytes;

    if ( c$id$orig_h in alerted_hosts || ip_traffic[c$id$orig_h] < traffic_threshold )
        return;

    NOTICE([$note=Anomalous_Traffic_Detected,
            $msg=fmt("检测到异常网络流量: 主机 %s 累计传输 %.2f MB", c$id$orig_h, ip_traffic[c$id$orig_h] / 1048576.0),
            $src=c$id$orig_h,
            $conn=c,
            $uid=c$uid]);
    add alerted_hosts[c$id$orig_h];
    }

event zeek_done()
    {
    for ( ip in ip_traffic )
        {
        if ( ip in alerted_hosts || ip_traffic[ip] < traffic_threshold )
            next;

        NOTICE([$note=Anomalous_Traffic_Detected,
                $msg=fmt("检测到异常网络流量: 主机 %s 累计传输 %.2f MB", ip, ip_traffic[ip] / 1048576.0),
                $src=ip]);
        add alerted_hosts[ip];
        }
    }
