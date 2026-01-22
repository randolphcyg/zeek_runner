# 脚本唯一标识符 - 不要修改此ID
# 此ID用于在数据库中唯一标识此脚本，即使脚本内容更新也不会改变
const SCRIPT_ID = "DETECT_DNS_FLOOD_v1";

# 恶意行为检测脚本配置
# 行为类型：DNS 洪水攻击 / 放大攻击
# 行为分类：拒绝服务攻击 (DoS)
# 行为描述：检测高频 DNS 查询、响应风暴及 ANY 类型放大攻击特征

@load base/frameworks/notice
@load base/frameworks/sumstats
@load base/protocols/dns

module DNS_DDoS;

export {
    redef enum Notice::Type += { DNS_Query_Flood, DNS_Response_Flood, DNS_Amplification_ANY };
    const FLOOD_THRESHOLD: double = 5.0; # 调试阈值
    const ANY_THRESHOLD: double = 2.0;   # 调试阈值
    const CHECK_INTERVAL: interval = 5sec;
}

event zeek_init() {
    local r1 = SumStats::Reducer($stream="dns.req.flood", $apply=set(SumStats::SUM));
    SumStats::create([
        $name="dns-req-flood", $epoch=CHECK_INTERVAL, $reducers=set(r1), $threshold=FLOOD_THRESHOLD,
        $threshold_val(key: SumStats::Key, result: SumStats::Result): double = { return result["dns.req.flood"]$sum; },
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {
            NOTICE([$note=DNS_Query_Flood, $msg=fmt("检测到 DNS 查询洪水: 源IP %s 发送了 %.0f 次查询", key$host, result["dns.req.flood"]$sum), $src=key$host]);
        }
    ]);

    local r2 = SumStats::Reducer($stream="dns.resp.flood", $apply=set(SumStats::SUM));
    SumStats::create([
        $name="dns-resp-flood", $epoch=CHECK_INTERVAL, $reducers=set(r2), $threshold=FLOOD_THRESHOLD,
        $threshold_val(key: SumStats::Key, result: SumStats::Result): double = { return result["dns.resp.flood"]$sum; },
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {
            NOTICE([$note=DNS_Response_Flood, $msg=fmt("检测到 DNS 响应洪水: 目标IP %s 收到了 %.0f 次响应", key$host, result["dns.resp.flood"]$sum), $src=key$host]);
        }
    ]);

    local r3 = SumStats::Reducer($stream="dns.amp.any", $apply=set(SumStats::SUM));
    SumStats::create([
        $name="dns-any-detect", $epoch=CHECK_INTERVAL, $reducers=set(r3), $threshold=ANY_THRESHOLD,
        $threshold_val(key: SumStats::Key, result: SumStats::Result): double = { return result["dns.amp.any"]$sum; },
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {
            NOTICE([$note=DNS_Amplification_ANY, $msg=fmt("检测到 DNS 放大攻击特征 (ANY): 源IP %s", key$host), $src=key$host]);
        }
    ]);
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count, original_query: string) {
    SumStats::observe("dns.req.flood", SumStats::Key($host=c$id$orig_h), SumStats::Observation($num=1));
    if ( qtype == 255 ) SumStats::observe("dns.amp.any", SumStats::Key($host=c$id$orig_h), SumStats::Observation($num=1));
}

event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count) {
    if ( msg$QR ) {
        local victim = is_orig ? c$id$orig_h : c$id$resp_h;
        SumStats::observe("dns.resp.flood", SumStats::Key($host=victim), SumStats::Observation($num=1));
    }
}