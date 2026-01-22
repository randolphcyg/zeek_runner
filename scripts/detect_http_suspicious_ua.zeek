# 脚本唯一标识符 - 不要修改此ID
# 此ID用于在数据库中唯一标识此脚本，即使脚本内容更新也不会改变
const SCRIPT_ID = "DETECT_HTTP_UA_FINAL_v1";

# 恶意行为检测脚本配置
# 行为类型：恶意 User-Agent 检测
# 行为分类：Web 攻击 / 扫描探测
# 行为描述：检测 HTTP 请求头中使用已知黑客工具 (Sqlmap, Nmap 等) 的 User-Agent，采用抗截断流式检测

@load base/protocols/http
@load base/frameworks/notice

module Detect_HTTP_UA;

export {
    redef enum Notice::Type += { Suspicious_User_Agent };
    const suspicious_agents: set[string] = {
        "curl", "wget", "python-requests", "masscan",
        "sqlmap", "nmap", "nikto", "gobuster", "hydra",
        "zgrab", "morfeus", "jorgee", "zmap", "acas",
        "nessus", "openvas", "pangolin"
    };
}

event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if ( ! is_orig ) return;
    if ( name == "USER-AGENT" ) {
        local ua = to_lower(value);
        for ( agent in suspicious_agents ) {
            if ( agent in ua ) {
                NOTICE([
                    $note = Suspicious_User_Agent,
                    $msg = fmt("检测到可疑的用户代理 (扫描器/攻击工具): %s", ua),
                    $sub = fmt("Matched Keyword: %s", agent),
                    $conn = c,
                    $uid = c$uid
                ]);
                break;
            }
        }
    }
}