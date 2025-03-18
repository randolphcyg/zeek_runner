@load frameworks/files/extract-all-files
@load base/utils/files

global extracted_file_path = getenv("EXTRACTED_FILE_PATH");  # 文件存储路径
global extracted_file_min_size = getenv("EXTRACTED_FILE_MIN_SIZE");  # 最小文件大小（KB）
redef FileExtract::prefix = extracted_file_path;  # 文件提取前缀路径
const MIN_FILE_SIZE = 1 * 1024;  # 定义最小文件大小（KB）

event zeek_init() {
    Kafka::headers["extracted_file_path"] = FileExtract::prefix;
}

# 允许提取的 MIME 类型列表
const ALLOWED_MIME_TYPES = set(
    "application/zip",
    "application/x-zip-compressed",
    "application/x-rar-compressed",
    "application/octet-stream",
    "application/x-msdownload",
    "application/x-dosexec",
);
# MIME 类型映射表
const mime_mappings: table[string] of string = {
    ["application/zip"] = ".zip",
    ["application/x-zip-compressed"] = ".zip",
    ["application/x-rar-compressed"] = ".rar",
    ["application/octet-stream"] = ".bin",
    ["application/ocsp-response"] = ".ocsp",
    ["application/x-x509-ca-cert"] = ".crt",
    ["application/x-msdownload"] = ".exe",
    ["application/x-dosexec"] = ".exe"
} &redef;

# 简单的 URL 解码函数
function url_decode(s: string): string {
    local result = gsub(s, /\%20/, " ");
    result = gsub(result, /\%2E/, ".");
    result = gsub(result, /\%2D/, "-");
    result = gsub(result, /\%5F/, "_");
    result = gsub(result, /\+/, " ");
    return result;
}

# 提取文件扩展名函数
function get_extension(name: string): string {
    local parts = split_string(name, /\./);
    if (|parts| > 1) {
        return "." + parts[|parts|-1];
    }
    return "";
}

# 获取文件类型扩展名函数
function get_mime_extension(f: fa_file): string {
    if (!f?$info ||!f$info?$mime_type) {
        return "";
    }

    local mime_type = to_lower(f$info$mime_type);
    return mime_type in mime_mappings? mime_mappings[mime_type] : "";
}

# 获取 HTTP 文件名函数
function get_http_filename(f: fa_file): string {
    local filename = "";
    local final_name = "";

    # 1. 从 URI 获取文件名
    if (f$http?$uri) {
        local uri = f$http$uri;
        local uri_parts = split_string(uri, /\//);
        if (|uri_parts| > 0) {
            filename = uri_parts[|uri_parts|-1];
            # 处理 URL 参数
            local query_parts = split_string(filename, /\?/);
            filename = query_parts[0];
            # URL 解码
            filename = url_decode(filename);
        }
    }

    # 2. 检查文件名有效性
    if (filename!= "" && filename!= "/" &&
        filename!= "index.html" && filename!= "index.htm") {
        final_name = filename;
    } else {
        # 3. 如果没有有效文件名，使用其他信息构建文件名
        local prefix = "download";
        if (f$http?$host) {
            prefix = f$http$host;
        }

        if (f$http?$uri) {
            local uri_hash = md5_hash(f$http$uri);
            final_name = fmt("%s_%s", prefix, uri_hash);
        } else {
            final_name = fmt("%s_%s", prefix, f$id);
        }
    }

    # 4. 处理文件扩展名
    local ext = get_extension(final_name);
    if (ext == "") {
        # 尝试从 MIME 类型获取扩展名
        ext = get_mime_extension(f);
        if (ext!= "") {
            final_name = fmt("%s%s", final_name, ext);
        }
    }

    return final_name;
}

# 生成文件名函数
function generate_filename(f: fa_file): string {
    local fname = "";

    if (f?$http) {
        # 跳过错误响应
        if (f$http?$status_code &&
            (f$http$status_code == 404 || f$http$status_code == 301 ||
             f$http$status_code == 400 || f$http$status_code == 403)) {
            return "";
        }

        fname = get_http_filename(f);
    }

    if (fname == "") {
        return "";
    }

    # 清理文件名中的非法字符
    fname = gsub(fname, /[\/\\:*?"<>|]/, "_");

    return fname;
}

# 文件状态移除事件处理函数
event file_state_remove(f: fa_file) {
    if (!f?$http) {
        return;
    }

    # 检查文件大小
    if (!f?$total_bytes || f$total_bytes <= MIN_FILE_SIZE * 1024) {
        return;
    }

    if (f?$info && f$info?$mime_type) {
        local mime_type = f$info$mime_type;
        if (mime_type!in ALLOWED_MIME_TYPES) {
            return;
        }
    }

    # 生成文件名
    local new_filename = generate_filename(f);
    if (new_filename == "") {
        return;
    }

    # 检查文件类型和后缀
    local ext = get_extension(new_filename);
    local mime_ext = get_mime_extension(f);
    if (ext == "" && mime_ext == "") {
        return;
    }

    local size = f$total_bytes;
    local msg = fmt("File extraction completed: %s bytes", size);
    if (f?$info && f$info?$mime_type) {
        msg += fmt(", MIME type: %s", f$info$mime_type);
    }
    if (f$http?$uri) {
        msg += fmt(", URI: %s", f$http$uri);
    }
    print msg;

    local old_path = fmt("%s/%s", FileExtract::prefix, f$info$extracted);
    local new_path = fmt("%s/%s", FileExtract::prefix, new_filename);
    if (rename(old_path, new_path)) {
        f$info$extracted = new_path;
        print fmt("File renamed successfully: %s -> %s", old_path, new_path);
    } else {
        print fmt("Failed to rename file: %s", old_path);
    }
}

# 文件嗅探事件处理函数
event file_sniff(f: fa_file, meta: fa_metadata) {
    # 记录文件类型信息
    if (f?$info && f$info?$mime_type) {
        # 排除特定的证书类型
        if (f$info$mime_type == "application/x-x509-user-cert" ||
            f$info$mime_type == "application/x-x509-ca-cert" ||
            f$info$mime_type == "application/ocsp-response") {
            return;
        }

        local msg = fmt("File type detected: %s", f$info$mime_type);
        if (f?$total_bytes) {
            print "####### file_sniff type type type";
            msg += fmt(", size: %s bytes", f$total_bytes);
        }
        print msg;
    }
}