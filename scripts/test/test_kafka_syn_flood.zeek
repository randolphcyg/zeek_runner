# 脚本唯一标识符 - 不要修改此ID
# 此ID用于在数据库中唯一标识此脚本，即使脚本内容更新也不会改变
const SCRIPT_ID = "DETECT_SYN_FLOOD_v1";

# 恶意行为检测脚本配置
# 行为类型：TCP SYN洪水攻击
# 行为分类：拒绝服务攻击(DoS)
# 行为描述：检测源IP发送大量SYN包但未建立连接的行为(Half-open connections)

@load base/frameworks/notice

module SynFlood;

export {
    redef enum Notice::Type += { SynFlood };
}

event new_connection(c: connection) {
    # 直接为每个连接生成notice
    if ( c?$id ) {
        NOTICE([
            $note=SynFlood,
            $msg=fmt("检测到 SYN Flood 攻击: 源 IP %s", c$id$orig_h),
            $src=c$id$orig_h
        ]);
    }
}

和generate_syn_flood.py配合用来测试kafka消息写入是否出现漏写 现在看不会 一百万消息都很轻松 该脚本应该如何修改个合适的名字归档放在项目中