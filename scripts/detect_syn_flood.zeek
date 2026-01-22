# 脚本唯一标识符 - 不要修改此ID
# 此ID用于在数据库中唯一标识此脚本，即使脚本内容更新也不会改变
const SCRIPT_ID = "DETECT_SYN_FLOOD_v1";

# 恶意行为检测脚本配置
# 行为类型：TCP SYN 洪水攻击
# 行为分类：拒绝服务攻击 (DoS)
# 行为描述：检测源 IP 发送大量 SYN 包但未建立连接的行为 (Half-open connections)

@load base/frameworks/sumstats
@load base/frameworks/notice

module SynFlood;

export {
    redef enum Notice::Type += { SynFlood };
    const syn_flood_threshold: double = 20.0; # 调试阈值
    const check_interval: interval = 5sec;
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