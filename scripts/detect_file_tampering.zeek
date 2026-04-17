# 脚本唯一标识符 - 不要修改此ID
const SCRIPT_ID = "DETECT_FILE_TAMPERING_v1";

# 恶意行为检测脚本配置
# 行为类型：文件篡改
# 行为分类：系统安全
# 行为描述：检测文件被恶意修改的行为，包括关键系统文件的变更

@load base/frameworks/notice
@load base/frameworks/files
@load base/utils/patterns

module FileTampering;

export {
    redef enum Notice::Type += {
        ## 当检测到关键文件被修改时触发
        File_Tampering_Detected,
        ## 当检测到可疑的文件修改模式时触发
        Suspicious_File_Modification
    };

    ## 关注的关键文件路径集合 (Unix/Linux)
    const critical_files_unix: set[string] = {
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/ssh/sshd_config",
        "/etc/hosts",
        "/etc/resolv.conf"
    } &redef;

    ## 关注的关键文件路径集合 (Windows)
    const critical_files_windows: set[string] = {
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\Windows\\System32\\config\\SYSTEM",
        "C:\\Windows\\System32\\config\\SOFTWARE",
        "C:\\Windows\\System32\\config\\SAM",
        "C:\\Windows\\System32\\winlogon.exe",
        "C:\\Windows\\System32\\user32.dll"
    } &redef;

    ## 关注的关键文件目录集合 (Unix/Linux)
    const critical_dirs_unix: set[string] = {
        "/etc/",
        "/usr/bin/",
        "/usr/sbin/",
        "/bin/",
        "/sbin/"
    } &redef;

    ## 关注的关键文件目录集合 (Windows)
    const critical_dirs_windows: set[string] = {
        "C:\\Windows\\System32\\",
        "C:\\Windows\\SysWOW64\\",
        "C:\\Program Files\\",
        "C:\\Program Files (x86)\\"
    } &redef;

    ## 可疑的文件扩展名
    const suspicious_extensions: set[string] = {
        ".exe",
        ".dll",
        ".sys",
        ".bat",
        ".sh",
        ".ps1",
        ".vbs",
        ".pdf",
        ".zip",
        ".iso",
        ".lnk",
        ".dat",
        ".cmd"
    } &redef;

    ## 可疑的域名和 IP
    const suspicious_domains: set[string] = {
        "allertmnemonkik.com",
        "turelomi.hair",
        "lezhidov.cloud",
        "qzmeat.cyou",
        "fepopeguc.com",
        "firebasestorage.googleapis.com"
    } &redef;

    const suspicious_ips: set[addr] = {
        162.33.177.186,
        103.208.85.127,
        94.140.115.3,
        5.230.74.203,
        199.127.60.47,
        185.173.34.36
    } &redef;

    ## 可疑的路径模式
    const suspicious_paths: set[string] = {
        "/download/",
        "/AppData/Roaming/",
        "/AppData/Local/",
        "/OwSq1IMH1D/",
        "/uploads/",
        "/admin/",
        "/install/"
    } &redef;

    ## 可疑的文件名模式
    const suspicious_filenames: set[string] = {
        "setup.exe",
        "install.exe",
        "update.exe",
        "loader.exe",
        "payload.exe",
        "dropper.exe",
        "download.exe",
        "sg.exe",
        "file.exe"
    } &redef;

    ## 合法的文件修改时间段 (24小时制)
    # const allowed_modification_hours: interval = 9hr to 18hr &redef;

    ## 文件修改频率阈值 (单位：秒)
    const modification_frequency_threshold: interval = 30secs &redef;

    ## 存储文件修改时间的表
    global file_modification_times: table[string] of time &redef;
}

# 辅助函数: 检查文件是否为可疑文件
function is_suspicious_file(file_path: string): bool
    {
    # 检查文件扩展名
    for ( ext in suspicious_extensions )
        {
        if ( ends_with(file_path, ext) )
            return T;
        }
    return F;
}

# 事件: HTTP 请求
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
    {
    # 打印 HTTP 请求信息（调试用）
    print(fmt("HTTP Request: %s %s from %s to %s", method, unescaped_URI, c$id$orig_h, c$id$resp_h));
    
    # 检查 URI 是否包含关键文件路径
    if ( unescaped_URI == "/etc/passwd" || unescaped_URI == "/etc/shadow" || unescaped_URI == "/Windows/System32/winlogon.exe" )
        {
        local critical_msg = fmt("检测到关键文件下载请求: %s", unescaped_URI);
        print(fmt("ALERT: %s", critical_msg));
        NOTICE([$note=File_Tampering_Detected,
                $msg=critical_msg,
                $src=c$id$orig_h,
                $dst=c$id$resp_h]);
        }
    
    # 检查 URI 是否在关键目录中
    if ( starts_with(unescaped_URI, "/etc/") || starts_with(unescaped_URI, "/Windows/System32/") )
        {
        local dir_msg = fmt("检测到关键目录文件下载请求: %s", unescaped_URI);
        print(fmt("ALERT: %s", dir_msg));
        NOTICE([$note=Suspicious_File_Modification,
                $msg=dir_msg,
                $src=c$id$orig_h,
                $dst=c$id$resp_h]);
        }
    
    # 检查是否访问可疑路径
    for ( path in suspicious_paths )
        {
        if ( unescaped_URI == path || starts_with(unescaped_URI, path) )
            {
            local path_msg = fmt("检测到访问可疑路径: %s", unescaped_URI);
            print(fmt("ALERT: %s", path_msg));
            NOTICE([$note=Suspicious_File_Modification,
                    $msg=path_msg,
                    $src=c$id$orig_h,
                    $dst=c$id$resp_h]);
            }
        }
    
    # 检查是否为可疑域名
    if ( c$id$resp_h in suspicious_ips )
        {
        local ip_msg = fmt("检测到访问可疑 IP: %s", c$id$resp_h);
        print(fmt("ALERT: %s", ip_msg));
        NOTICE([$note=Suspicious_File_Modification,
                $msg=ip_msg,
                $src=c$id$orig_h,
                $dst=c$id$resp_h]);
        }
    
    # 检查是否为可疑文件类型
    for ( ext in suspicious_extensions )
        {
        if ( ends_with(unescaped_URI, ext) )
            {
            local ext_msg = fmt("检测到下载可疑文件类型: %s", unescaped_URI);
            print(fmt("ALERT: %s", ext_msg));
            NOTICE([$note=Suspicious_File_Modification,
                    $msg=ext_msg,
                    $src=c$id$orig_h,
                    $dst=c$id$resp_h]);
            }
        }
    
    # 检查是否为可疑文件名
    for ( filename in suspicious_filenames )
        {
        if ( unescaped_URI == filename || ends_with(unescaped_URI, "/" + filename) )
            {
            local filename_msg = fmt("检测到下载可疑文件名: %s", unescaped_URI);
            print(fmt("ALERT: %s", filename_msg));
            NOTICE([$note=Suspicious_File_Modification,
                    $msg=filename_msg,
                    $src=c$id$orig_h,
                    $dst=c$id$resp_h]);
            }
        }
}

# 事件: 文件状态移除 (用于检测文件修改)
event file_state_remove(f: fa_file)
    {
    if ( ! f?$info ) return;

    # 构建文件路径
    local file_path = f$id;

    # 检测文件修改频率
    if ( file_path in file_modification_times )
        {
        local time_diff = current_time() - file_modification_times[file_path];
        if ( time_diff < modification_frequency_threshold )
            {
            # 遍历所有传输该文件的连接
            for ( cid, c in f$conns )
                {
                local freq_msg = fmt("文件修改频率异常: %s (时间间隔: %s)", file_path, time_diff);
                NOTICE([$note=Suspicious_File_Modification,
                        $msg=freq_msg,
                        $src=c$id$orig_h,
                        $dst=c$id$resp_h]);
                }
            }
        }

    # 更新文件修改时间
    file_modification_times[file_path] = current_time();

    # 检查文件修改时间是否在合法时间段内
    local current_time_val = current_time();
    local current_hour = strftime("%H", current_time_val);
    if ( current_hour < "09" || current_hour > "18" )
        {
        # 非工作时间的文件修改需要特别关注
        if ( is_suspicious_file(file_path) )
            {
            # 遍历所有传输该文件的连接
            for ( cid, c in f$conns )
                {
                local time_msg = fmt("非工作时间修改可疑文件: %s", file_path);
                NOTICE([$note=Suspicious_File_Modification,
                        $msg=time_msg,
                        $src=c$id$orig_h,
                        $dst=c$id$resp_h]);
                }
            }
        }

    # 检查是否为关键文件 (Unix/Linux)
    if ( file_path in critical_files_unix )
        {
        # 遍历所有传输该文件的连接
        for ( cid, c in f$conns )
            {
            local unix_msg = fmt("Unix/Linux关键文件被修改: %s", file_path);
            NOTICE([$note=File_Tampering_Detected,
                    $msg=unix_msg,
                    $src=c$id$orig_h,
                    $dst=c$id$resp_h]);
            }
        return;
        }

    # 检查是否为关键文件 (Windows)
    if ( file_path in critical_files_windows )
        {
        # 遍历所有传输该文件的连接
        for ( cid, c in f$conns )
            {
            local win_msg = fmt("Windows关键文件被修改: %s", file_path);
            NOTICE([$note=File_Tampering_Detected,
                    $msg=win_msg,
                    $src=c$id$orig_h,
                    $dst=c$id$resp_h]);
            }
        return;
        }

    # 检查文件路径是否在Unix/Linux关键目录中
    for ( dir in critical_dirs_unix )
        {
        if ( starts_with(file_path, dir) )
            {
            # 检查是否为可疑扩展名
            if ( is_suspicious_file(file_path) )
                {
                # 遍历所有传输该文件的连接
                for ( cid, c in f$conns )
                    {
                    local unix_dir_msg = fmt("Unix/Linux关键目录中的可疑文件被修改: %s", file_path);
                    NOTICE([$note=File_Tampering_Detected,
                            $msg=unix_dir_msg,
                            $src=c$id$orig_h,
                            $dst=c$id$resp_h]);
                    }
                return;
                }
            }
        }

    # 检查文件路径是否在Windows关键目录中
    for ( dir in critical_dirs_windows )
        {
        if ( starts_with(file_path, dir) )
            {
            # 检查是否为可疑扩展名
            if ( is_suspicious_file(file_path) )
                {
                # 遍历所有传输该文件的连接
                for ( cid, c in f$conns )
                    {
                    local win_dir_msg = fmt("Windows关键目录中的可疑文件被修改: %s", file_path);
                    NOTICE([$note=File_Tampering_Detected,
                            $msg=win_dir_msg,
                            $src=c$id$orig_h,
                            $dst=c$id$resp_h]);
                    }
                return;
                }
            }
        }
    }

# 事件: 系统启动时初始化
event zeek_init()
    {
    # 初始化文件修改时间表
    file_modification_times = { };
    
    # 输出初始化信息
    print("FileTampering detection initialized");
    print("Monitoring critical files and directories...");
    print("Monitoring suspicious domains and IPs...");
}