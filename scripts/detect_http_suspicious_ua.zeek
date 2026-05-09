# SCRIPT_ID: DETECT_HTTP_UA_v1
# NoticeTypes: Detect_HTTP_UA::Suspicious_User_Agent

# 恶意行为检测脚本配置
# 行为类型：恶意User-Agent检测
# 行为分类：Web攻击/扫描探测
# 行为描述：检测HTTP请求头中使用已知黑客工具(Sqlmap, Nmap等)的User-Agent，采用抗截断流式检测
# 攻击特征：User-Agent包含sqlmap、nmap、masscan、curl、wget等扫描器、自动化工具或攻击框架标识

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
