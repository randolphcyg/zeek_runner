# 脚本唯一标识符 - 不要修改此ID
# 此ID用于在数据库中唯一标识此脚本，即使脚本内容更新也不会改变
const SCRIPT_ID = "DETECT_HTTP_FLOOD_v1";

# 恶意行为检测脚本配置
# 行为类型：HTTP拒绝服务攻击(CC攻击)
# 行为分类：拒绝服务攻击
# 行为描述：检测高频HTTP请求，基于短时间内的请求计数统计

@load base/frameworks/notice
@load base/frameworks/sumstats
@load base/protocols/http

module HTTP_DoS;

export {
    redef enum Notice::Type += { HTTP_CC_Attack };
    const HTTP_THRESHOLD: double = 5.0;
    const CHECK_INTERVAL: interval = 5sec;
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