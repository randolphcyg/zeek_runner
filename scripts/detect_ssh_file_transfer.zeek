# 脚本唯一标识符 - 不要修改此ID
# 此ID用于在数据库中唯一标识此脚本，即使脚本内容更新也不会改变
const SCRIPT_ID = "DETECT_SSH_FILE_TRANSFER_v1";

# 恶意行为检测脚本配置
# 行为类型：SSH异常大文件传输(SCP/SFTP)
# 行为分类：数据泄露/流量异常
# 行为描述：检测已认证SSH连接中的异常单向大数据流，识别疑似数据窃取行为
# 攻击特征：已认证SSH会话中出现超过阈值的单向大流量传输，疑似SCP/SFTP数据外传

@load base/frameworks/notice
@load base/protocols/ssh

module SSH_SCP;

export {
    redef enum Notice::Type += { Suspicious_SCP_Transfer };
    const TRANSFER_THRESHOLD: count = 1024 * 1024 &redef;
}

global auth_ssh_conns: set[string];

function is_ssh_connection(c: connection): bool {
    if ( c$id$resp_p == 22/tcp ) return T;
    if ( c?$service && "ssh" in c$service ) return T;
    return F;
}

event ssh_auth_successful(c: connection, auth_method_none: bool) {
    add auth_ssh_conns[c$uid];
}

event connection_state_remove(c: connection) {
    if ( c$uid !in auth_ssh_conns && ! is_ssh_connection(c) ) return;
    if ( c$uid in auth_ssh_conns ) delete auth_ssh_conns[c$uid];

    local bytes_orig = c$orig$size;
    local bytes_resp = c$resp$size;
    local is_suspicious = F;
    local direction = "";
    local size_mb = 0.0;

    if ( bytes_orig > TRANSFER_THRESHOLD ) {
        is_suspicious = T;
        direction = "Upload (Client->Server)";
        size_mb = bytes_orig / 1024.0 / 1024.0;
    } else if ( bytes_resp > TRANSFER_THRESHOLD ) {
        is_suspicious = T;
        direction = "Download (Server->Client)";
        size_mb = bytes_resp / 1024.0 / 1024.0;
    }

    if ( is_suspicious ) {
        NOTICE([
            $note = Suspicious_SCP_Transfer,
            $msg = fmt("检测到 SSH 隧道内的大文件传输 (疑似 SCP/SFTP): %s", direction),
            $sub = fmt("Size: %.2f MB, Threshold: %d Bytes", size_mb, TRANSFER_THRESHOLD),
            $src = c$id$orig_h,
            $dst = c$id$resp_h,
            $conn = c,
            $uid = c$uid
        ]);
    }
}
