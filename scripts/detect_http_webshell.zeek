# 脚本唯一标识符 - 不要修改此ID
# 此ID用于在数据库中唯一标识此脚本，即使脚本内容更新也不会改变
const SCRIPT_ID = "DETECT_HTTP_WEBSHELL_v1";

# 恶意行为检测脚本配置
# 行为类型：HTTP 恶意文件上传 (Webshell)
# 行为分类：Web 攻击 / 权限维持
# 行为描述：检测通过 HTTP POST/PUT 上传的可疑 MIME 类型文件或高危后缀脚本

@load base/frameworks/notice
@load base/protocols/http
@load base/frameworks/files

module HTTP_Upload;

export {
    redef enum Notice::Type += { Suspicious_File_Upload };
    const suspicious_mimes: set[string] = { "application/x-dosexec", "application/x-executable", "text/x-php", "application/x-php", "text/x-ruby", "text/x-perl", "text/x-shellscript", "application/java-archive", "application/jsp" };
    const suspicious_exts: set[string] = { "php", "php5", "phtml", "jsp", "jspx", "asp", "aspx", "exe", "sh", "pl", "py", "war" };
}

event file_sniff(f: fa_file, meta: fa_metadata) {
    if ( ! meta?$mime_type ) return;
    local mime = meta$mime_type;

    for ( cid, c in f$conns ) {
        if ( ! c?$http ) next;
        if ( c$http$method != "POST" && c$http$method != "PUT" ) next;

        local is_suspicious = F;
        local reason = "";
        local fname = "<unknown>";
        if ( f?$info && f$info?$filename ) fname = f$info$filename;
        else if ( f?$source ) fname = f$source;

        if ( mime in suspicious_mimes ) {
            is_suspicious = T;
            reason = fmt("Detected Suspicious MIME: %s", mime);
        }
        if ( ! is_suspicious && fname != "<unknown>" ) {
            local parts = split_string(fname, /\./);
            if ( |parts| > 1 ) {
                local ext = to_lower(parts[|parts|-1]);
                if ( ext in suspicious_exts ) {
                    is_suspicious = T;
                    reason = fmt("Detected Suspicious Extension: .%s", ext);
                }
            }
        }

        if ( is_suspicious ) {
            NOTICE([$note=Suspicious_File_Upload, $msg=fmt("检测到可疑 Web 文件上传: %s", reason), $sub=fmt("Filename: %s", fname), $conn=c, $uid=c$uid]);
            break;
        }
    }
}