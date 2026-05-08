# 脚本唯一标识符 - 不要修改此ID
# 此ID用于在数据库中唯一标识此脚本，即使脚本内容更新也不会改变
const SCRIPT_ID = "DETECT_INTEL_FEED_HIT_v3";

# 恶意行为检测脚本配置
# 行为类型：威胁情报命中
# 行为分类：情报验证
# 行为描述：基于离线威胁情报回放逻辑检测流量中命中的恶意IP、域名或URL指标
# 攻击特征：流量实体与威胁情报中的恶意IP、域名、URL或文件哈希指标发生匹配

event zeek_init()
	{
	# The actual offline Intel matching is implemented in
	# custom/offline/intel_replay.zeek, which is loaded through
	# custom/config.zeek by the Go service. This script exists as a
	# dedicated entry marker so the task can request an "Intel validation"
	# run without duplicating replay logic in per-task scripts.
	}
