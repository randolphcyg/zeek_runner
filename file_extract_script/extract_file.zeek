@load base/frameworks/files
@load base/utils/files

module CustomExtraction;

# 从环境变量读取配置，提供默认值保底
global extract_dir = getenv("EXTRACTED_FILE_PATH") == "" ? "./extract_files" : getenv("EXTRACTED_FILE_PATH");

# 默认值: 1KB最小, 200MB最大
global min_file_size = 1024;
global max_file_size = 209715200;

# 设置 Zeek 原生提取的输出目录
redef FileExtract::prefix = extract_dir;

# 配置最大提取体积限制
redef FileExtract::default_limit = max_file_size;

# ==========================================
# 1. 拦截名单：MIME 类型与文件后缀
# ==========================================
const TARGET_MIME_TYPES: set[string] = {
    # 固件与二进制 (跨架构)
    "application/octet-stream",       # 泛指二进制流 (多数 bin 固件均识别为此类)
    "application/x-executable",       # Linux ELF (常见于工控/路由器固件)
    "application/macbinary",          # macOS 二进制
    "application/x-mach-binary",      # Mach-O
    "application/x-elf",             # ELF 可执行文件
    
    # Windows 安装包与可执行文件
    "application/x-dosexec",          # PE 文件 (exe, dll, sys)
    "application/x-msdownload",       # Windows 可执行/安装程序
    "application/x-msi",              # MSI 安装包
    "application/vnd.microsoft.portable-executable",  # PE 文件
    
    # 移动端及 Linux 安装包
    "application/vnd.android.package-archive", # Android APK
    "application/x-debian-package",            # Debian/Ubuntu DEB
    "application/x-redhat-package-manager",    # RedHat RPM
    "application/x-rpm",                      # RPM 包
    
    # 常见的打包格式 (固件常常被打包)
    "application/zip",
    "application/x-gzip",
    "application/x-tar",
    "application/x-rar",
    "application/x-7z-compressed",
    "application/x-bzip2",
    "application/x-compress",
    "application/x-lzma",
    "application/x-xz",
    "application/x-zstd",
    
    # 嵌入式与工业文件系统
    "application/x-squashfs",
    "application/x-cpio",
    "application/x-romfs",
    "application/x-cramfs",
    "application/x-iso9660-image",
    
    # 裸机与微控制器对象文件
    "application/x-object",
    "application/x-sharedlib"  # .so 库文件
} &redef;

# 新增：目标文件后缀名单（兜底机制）
const TARGET_EXTENSIONS: set[string] = {
    # 1. 通用二进制与内存转储 (极高频)
    "bin", "img", "rom", "dump", "flash", "fw", "firmware",
    
    # 2. 嵌入式文件系统与磁盘镜像
    "squashfs", "jffs2", "yaffs2", "ubifs", "ubi",
    "cramfs", "romfs", "ext2", "ext3", "ext4", "cpio", "vmdk", "qcow2",
    
    # 3. 微控制器(MCU)与 RTOS 烧录格式
    "hex", "s19", "mot", "dfu", "uf2", "axf", "elf", "ko", "so", "ota", "mcu",
    
    # 4. 网络设备与 IoT 专属格式
    "trx", "chk", "dlf", "bix", "ipk", "ros", "npk", "ccx", "pkg", "stk",
    
    # 5. 常规安装包与归档文件
    "apk", "deb", "rpm", "msi", "exe", "dll", "sys", "dmg", "pkg",
    "tar", "gz", "tgz", "zip", "rar", "7z", "bz2", "xz", "zst"
} &redef;

# ==========================================
# 2. 辅助函数：提取协议层或 HTTP URI 中的文件名
# ==========================================
function get_filename_from_stream(f: fa_file): string {
    local fname = "";
    
    # 首选：Zeek 原生解析出的协议文件名 (支持 FTP, SMB, SMTP, HTTP Content-Disposition)
    if ( f$info?$filename && f$info$filename != "" ) {
        fname = f$info$filename;
    } 
    # 备选：从 HTTP URI 中推断
    else if ( f?$http && f$http?$uri ) {
        # 从 HTTP URI 中截取文件名
        local uri_parts = split_string(f$http$uri, /\?/);
        if ( |uri_parts| > 0 ) {
            local path_parts = split_string(uri_parts[0], /\//);
            if ( |path_parts| > 0 ) {
                fname = path_parts[|path_parts|-1];
            }
        }
    }
    
    return to_lower(fname);
}

function generate_safe_name(f: fa_file): string {
    local fname = get_filename_from_stream(f);
    if ( fname == "" || fname == "/" ) {
        fname = fmt("binary_stream_%s", f$id);
    }
    
    # 清理非法字符，防止路径穿越或系统报错
    fname = gsub(fname, /[\/\\:*?"<>|]/, "_");
    
    return fname;
}

# ==========================================
# 3. 按需触发提取 (双重校验拦截逻辑)
# ==========================================
event file_sniff(f: fa_file, meta: fa_metadata) {
    local should_extract = F;
    local reason = "";

    # 校验 1：MIME 类型是否在目标名单中
    if ( meta?$mime_type ) {
        local mime = to_lower(meta$mime_type);
        if ( mime in TARGET_MIME_TYPES ) {
            should_extract = T;
            reason = fmt("MIME Match: %s", mime);
        }
    }

    # 校验 2：如果 MIME 未命中（或者根本没有 MIME），进行后缀兜底探测
    if ( !should_extract ) {
        local fname = get_filename_from_stream(f);
        if ( fname != "" ) {
            local ext_parts = split_string(fname, /\./);
            if ( |ext_parts| > 1 ) {
                local ext = ext_parts[|ext_parts|-1];
                if ( ext in TARGET_EXTENSIONS ) {
                    should_extract = T;
                    reason = fmt("Extension Fallback Match: .%s", ext);
                }
            }
        }
    }

    # 执行提取逻辑
    if ( should_extract ) {
        Files::add_analyzer(f, Files::ANALYZER_EXTRACT);
        print fmt("[+] Trigger Extraction: %s (Reason: %s, Protocol: %s)", f$id, reason, f$source);
    }
}

# ==========================================
# 4. 提取完成后的整理与丢弃逻辑
# ==========================================
event file_state_remove(f: fa_file) {
    # 检查是否真的被提取了 (防止未满足 sniffing 条件的文件进来)
    if ( !f$info?$extracted ) return;

    local orig_path = fmt("%s/%s", FileExtract::prefix, f$info$extracted);

    # 提取后的大小校验
    if ( f?$total_bytes ) {
        # 丢弃过小的文件
        if ( f$total_bytes < min_file_size ) {
            # 标记为 discard，交由上层 Go 服务异步删除
            local small_discard_path = fmt("%s.discard", orig_path);
            rename(orig_path, small_discard_path);
            print fmt("[-] Discarded (Too Small): %s -> %s", f$total_bytes, small_discard_path);
            return;
        }
        
        # 丢弃过大的文件 (防止磁盘/内存耗尽)
        if ( f$total_bytes > max_file_size ) {
            # 标记为 discard，交由上层 Go 服务异步删除
            local large_discard_path = fmt("%s.too_large", orig_path);
            rename(orig_path, large_discard_path);
            print fmt("[-] Discarded (Too Large): %s -> %s", f$total_bytes, large_discard_path);
            return;
        }
    }

    # 生成安全的文件名，并拼上 f$id 防止并发覆盖 (例如多次下载同名文件)
    local safe_name = generate_safe_name(f);
    local final_name = fmt("%s-%s", f$id, safe_name);
    local final_path = fmt("%s/%s", FileExtract::prefix, final_name);

    # 重命名文件
    if ( rename(orig_path, final_path) ) {
        f$info$extracted = final_path; # 更新 Zeek 日志中的路径记录
        
        local log_msg = fmt("[*] Extraction Success: %s", final_path);
        if ( f$info?$mime_type ) log_msg += fmt(" | Type: %s", f$info$mime_type);
        if ( f?$total_bytes ) log_msg += fmt(" | Size: %d Bytes", f$total_bytes);
        print log_msg;
    } else {
        print fmt("[!] Rename Failed: %s", orig_path);
    }
}
