# 脚本唯一标识符 - 不要修改此ID
# 此ID用于在数据库中唯一标识此脚本，即使脚本内容更新也不会改变
const SCRIPT_ID = "DETECT_SSH_BRTFORCE_v1";

# 恶意行为检测脚本配置
# 行为类型：SSH暴力破解攻击
# 行为分类：暴力破解
# 行为描述：检测针对SSH服务的频繁登录尝试，限制密码猜测次数
# 攻击特征：同一来源对SSH服务发起连续认证尝试并超过密码猜测阈值，呈现暴力破解行为

@load protocols/ssh/detect-bruteforcing

# 离线样本可通过单独 redef 覆盖，默认保持更接近生产的阈值
redef SSH::password_guesses_limit = 10;
redef SSH::guessing_timeout = 30 mins;

# 定义 Hook，当检测到暴力破解时触发
hook Notice::policy(n: Notice::Info) {
    if ( n$note == SSH::Password_Guessing ) {
        # 离线分析模式：仅记录日志
        add n$actions[Notice::ACTION_LOG];
    }
}
