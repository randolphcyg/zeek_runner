# SCRIPT_ID: DETECT_SLAMMER_v1
# NoticeTypes: Detect_Slammer::Slammer_Worm_Activity

# 恶意行为检测脚本配置
# 行为类型：SQL Slammer蠕虫/UDP Flood
# 行为分类：蠕虫病毒/拒绝服务
# 行为描述：检测针对UDP1434端口的异常流量，识别Slammer蠕虫的经典特征
# 攻击特征：针对UDP 1434端口出现高频小包传播流量，符合SQL Slammer蠕虫扫描与扩散行为

@load base/frameworks/notice

module Detect_Slammer;

export {
    redef enum Notice::Type += { Slammer_Worm_Activity };
    const target_port: port = 1434/udp;
}

event new_packet(c: connection, p: pkt_hdr) {
    if ( ! c?$id ) return;
    if ( c$id$resp_p == target_port ) {
        NOTICE([
            $note = Slammer_Worm_Activity,
            $msg = "检测到疑似 SQL Slammer 蠕虫流量",
            $sub = fmt("Target Port: 1434/UDP, Src: %s", c$id$orig_h),
            $conn = c,
            $uid = c$uid
        ]);
    }
}
