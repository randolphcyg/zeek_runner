# 脚本唯一标识符 - 不要修改此ID
const SCRIPT_ID = "DETECT_BULK_DOWNLOAD_v1";

# 恶意行为检测脚本配置
# 行为类型：批量下载恶意文件
# 行为分类：恶意文件获取
# 行为描述：检测单IP短时间内高频下载文件，尤其固件/可执行文件

@load base/frameworks/notice
@load base/frameworks/sumstats
@load base/frameworks/files

module BulkDownload;

export {
    redef enum Notice::Type += {
        ## 当短时间内下载大量特定文件时触发
        Bulk_File_Download,
        ## 当短时间内产生极大下载流量时触发
        High_Volume_Download
    };

    ## 触发【文件数量】告警的阈值 (例如 50 个文件)
    const file_count_threshold: double = 50.0 &redef;

    ## 触发【流量大小】告警的字节数阈值 (例如 100MB = 100 * 1024 * 1024 字节)
    const byte_count_threshold: double = 104857600.0 &redef;

    ## 检测的时间窗口 (在分析 pcap 时，Zeek 会自动使用 pcap 的时间戳)
    const observation_window: interval = 5 mins &redef;

    ## 关注的下载文件 MIME 类型集合。
    ## 过滤掉常见的网页图片/JS/CSS，只关注有"批量下载"风险的数据类型。
    ## 如果想统计所有类型文件，可以将这个 set 清空。
    const watch_mime_types: set[string] = {
        "application/pdf",
        "application/zip",
        "application/x-dosexec",
        "application/x-gzip",
        "application/x-tar",
        "application/vnd.ms-excel",
        "application/msword"
    } &redef;
}

event zeek_init()
    {
    # ---------------- 1. 文件数量检测模块 ----------------
    local r_files: SumStats::Reducer = [$stream="bulk.download.files", $apply=set(SumStats::SUM)];
    SumStats::create([$name="detect_bulk_files",
                      $epoch=observation_window,
                      $reducers=set(r_files),
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                          {
                          return result["bulk.download.files"]$sum;
                          },
                      $threshold=file_count_threshold,
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                          {
                          local msg = fmt("主机 %s 在 %s 内下载了 %.0f 个敏感类型文件", key$host, observation_window, result["bulk.download.files"]$sum);
                          NOTICE([$note=Bulk_File_Download,
                                  $msg=msg,
                                  $src=key$host]);
                          }]);

    # ---------------- 2. 流量大小检测模块 ----------------
    local r_bytes: SumStats::Reducer = [$stream="bulk.download.bytes", $apply=set(SumStats::SUM)];
    SumStats::create([$name="detect_bulk_bytes",
                      $epoch=observation_window,
                      $reducers=set(r_bytes),
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                          {
                          return result["bulk.download.bytes"]$sum;
                          },
                      $threshold=byte_count_threshold,
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                          {
                          local msg = fmt("主机 %s 在 %s 内下载了 %.2f MB 数据", key$host, observation_window, result["bulk.download.bytes"]$sum / 1048576.0);
                          NOTICE([$note=High_Volume_Download,
                                  $msg=msg,
                                  $src=key$host]);
                          }]);
    }

# 事件: 连接状态移除 (用于统计下载的字节数)
event connection_state_remove(c: connection)
    {
    # c$resp$size 表示响应方(服务器)发送给发起方(客户端)的 payload 数据大小
    if ( c$resp$size > 0 )
        {
        # 将流量归属于发起连接的主机 (通常是下载者)
        SumStats::observe("bulk.download.bytes", [$host=c$id$orig_h], [$num=c$resp$size]);
        }
    }

# 事件: 文件状态移除 (用于统计下载的文件数量)
event file_state_remove(f: fa_file)
    {
    if ( ! f?$info ) return;

    # 如果定义了关注的 MIME 类型，则进行过滤。
    # 这可以防止用户正常打开一个包含上百张图片的网页时触发告警。
    if ( f$info?$mime_type && |watch_mime_types| > 0 && f$info$mime_type !in watch_mime_types )
        return;

    # 在 Zeek 8.x 中，通过遍历传输该文件的所有网络连接来提取下载者 IP
    local downloaders: set[addr];

    # f$conns 是一个记录了所有传输该文件的连接表 (table[conn_id] of connection)
    for ( cid, c in f$conns )
        {
        # 通常情况下，发起网络请求的一端 (orig_h，即客户端) 就是下载者
        add downloaders[c$id$orig_h];
        }

    # 遍历去重后的下载者 IP，并上报给 SumStats 进行阈值统计
    for ( rx in downloaders )
        {
        SumStats::observe("bulk.download.files", [$host=rx], [$num=1]);
        }
    }