# SCRIPT_ID: DETECT_SYN_FLOOD_v1
# NoticeTypes: SynFlood::SynFlood

# 恶意行为检测脚本配置
# 行为类型：TCP SYN洪水攻击
# 行为分类：拒绝服务攻击(DoS)
# 行为描述：检测源IP发送大量SYN包但未建立连接的行为(Half-open connections)
# 攻击特征：短时间内大量SYN包未完成三次握手，半开连接数量异常升高

@load base/frameworks/sumstats
@load base/frameworks/notice

module SynFlood;

export {
    redef enum Notice::Type += { SynFlood };
    const syn_flood_threshold: double = 100.0 &redef;
    const check_interval: interval = 10sec &redef;
}

event zeek_init() {
    local r1 = SumStats::Reducer($stream="syn.flood", $apply=set(SumStats::SUM));
    SumStats::create([
        $name="syn-flood-detect",
        $epoch=check_interval,
        $reducers=set(r1),
        $threshold=syn_flood_threshold,
        $threshold_val(key: SumStats::Key, result: SumStats::Result): double = { return result["syn.flood"]$sum; },
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {
            NOTICE([
                $note=SynFlood,
                $msg=fmt("检测到 SYN Flood 攻击: 源 IP %s", key$host),
                $src=key$host
            ]);
        }
    ]);
}

event new_packet(c: connection, p: pkt_hdr) {
    if ( ! c?$id ) return;
    # 检查是否为 TCP SYN 包 (Flags: SYN=1, ACK=0)
    if ( p?$tcp && p$tcp$flags == 2 ) {
        SumStats::observe("syn.flood", SumStats::Key($host=c$id$orig_h), SumStats::Observation($num=1));
    }
}
