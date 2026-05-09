# SCRIPT_ID: DETECT_HTTP_CMD_INJECT_v1
# NoticeTypes: UnixCommand::UnixCommandInjection

# 恶意行为检测脚本配置
# 行为类型：Unix命令注入攻击
# 行为分类：Web攻击/命令执行
# 行为描述：检测HTTP URI及Header中包含的Shellshock及常见Unix系统命令特征
# 攻击特征：HTTP参数或请求头中出现Shellshock、系统命令、命令连接符、敏感文件读取等注入载荷

@load base/frameworks/notice
@load base/protocols/http

module UnixCommand;

export {
    redef enum Notice::Type += { UnixCommandInjection };
    type Sig: record { regex: pattern; name: string; };
    type SigVec: vector of Sig;

    global sigs = SigVec(
        [$regex = /\(\)\s*\{\s*:;\s*\};/, $name = "Shellshock"],
        [$regex = /(\/bin\/sh|\/bin\/bash|cmd\.exe)/, $name = "System Shell"],
        [$regex = /(cat%20\/etc\/passwd|\/etc\/shadow|cat \/etc\/passwd)/, $name = "Sensitive File Access"],
        [$regex = /\.\.\/\.\.\//, $name = "Directory Traversal"],
        [$regex = /(;|\||`|\$|\(|\)|%0a|%0d).*?(wget|curl|nc|netcat|ping|whoami|id)/, $name = "Command Chaining"]
    );
}

function check_injection(c: connection, value: string, source_type: string) {
    for (i in sigs) {
        local sig = sigs[i];
        if (sig$regex in value) {
            NOTICE([
                $note = UnixCommandInjection,
                $msg = fmt("检测到 Unix 命令注入尝试: %s (签名: %s)", source_type, sig$name),
                $sub = fmt("Payload: %s", value),
                $conn = c,
                $uid = c$uid
            ]);
            break;
        }
    }
}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
    check_injection(c, unescaped_URI, "HTTP URI");
    if (original_URI != unescaped_URI) check_injection(c, original_URI, "HTTP URI (Original)");
}

event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if ( is_orig ) check_injection(c, value, fmt("HTTP Header (%s)", name));
}
