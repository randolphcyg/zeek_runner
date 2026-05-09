# SCRIPT_ID: DETECT_HTTP_FLOOD_v1
# NoticeTypes: HTTP_DoS::HTTP_CC_Attack

# 恶意行为检测脚本配置
# 行为类型：HTTP拒绝服务攻击(CC攻击)
# 行为分类：拒绝服务攻击
# 行为描述：检测高频HTTP请求，基于短时间内的请求计数统计
# 攻击特征：同一源地址或目标在短时间窗口内出现超阈值HTTP请求频率，疑似CC压测或拒绝服务攻击

@load base/frameworks/notice
@load base/frameworks/sumstats
@load base/protocols/http

module HTTP_DoS;

export {
    redef enum Notice::Type += { HTTP_CC_Attack };
    const HTTP_THRESHOLD: double = 100.0 &redef;
    const CHECK_INTERVAL: interval = 10sec &redef;
}

event zeek_init() {
    local r1 = SumStats::Reducer($stream="http.flood", $apply=set(SumStats::SUM));
    SumStats::create([
        $name="http-flood-detect", $epoch=CHECK_INTERVAL, $reducers=set(r1), $threshold=HTTP_THRESHOLD,
        $threshold_val(key: SumStats::Key, result: SumStats::Result): double = { return result["http.flood"]$sum; },
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {
            NOTICE([
                $note = HTTP_CC_Attack,
                $msg = fmt("检测到 HTTP CC/DoS 攻击: 源IP %s 在短时间内发送了 %.0f 次请求", key$host, result["http.flood"]$sum),
                $src = key$host
            ]);
        }
    ]);
}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
    SumStats::observe("http.flood", SumStats::Key($host=c$id$orig_h), SumStats::Observation($num=1));
}
