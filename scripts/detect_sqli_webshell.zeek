# 脚本唯一标识符 - 不要修改此ID
# 此ID用于在数据库中唯一标识此脚本，即使脚本内容更新也不会改变
const SCRIPT_ID = "DETECT_SQLI_WEBSHELL_v1";

# 恶意行为检测脚本配置
# 行为类型：SQL注入写入文件
# 行为分类：Web攻击/数据库攻击
# 行为描述：检测利用SQL注入漏洞(INTO OUTFILE)尝试在服务器写入Webshell的高危行为

@load base/protocols/http
@load base/frameworks/notice

module Detect_SQLi_Webshell;

export {
    redef enum Notice::Type += { SQLi_Write_File };
}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
    local uri = to_lower(unescaped_URI);

    if ( "into outfile" in uri || "into dumpfile" in uri ) {
        NOTICE([
            $note = SQLi_Write_File,
            $msg = "检测到 SQL 注入尝试写入文件 (Webshell Upload)",
            $sub = fmt("Payload: %s", original_URI),
            $conn = c,
            $uid = c$uid
        ]);
    } else if ( "union select" in uri ) {
        NOTICE([
            $note = SQLi_Write_File,
            $msg = "检测到 SQL 注入 (UNION SELECT)",
            $sub = fmt("Payload: %s", original_URI),
            $conn = c,
            $uid = c$uid
        ]);
    }
}