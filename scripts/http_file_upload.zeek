# http_file_upload.zeek

# 定义可疑文件扩展名
global suspicious_extensions = [".php", ".exe", ".jsp", ".asp", ".sh"];

# 定义通知类型
redef enum Notice::Type += {
    Suspicious_File_Upload
};

# 使用正确的 http_request 事件原型
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
    if ( method == "POST" ) {
        # 检查上传文件的扩展名
        for ( ext in suspicious_extensions ) {
            # 使用 `strstr` 检查 URI 中是否包含可疑的文件扩展名
            if ( strstr(original_URI, ext) != 0 ) {
                print fmt("Suspicious file upload detected from %s: %s", c$id$orig_h, original_URI);
                # 标记为恶意文件上传
                NOTICE([$note=Suspicious_File_Upload,
                        $msg=fmt("Suspicious file upload attempt: %s", original_URI),
                        $conn=c]);
                break;  # 找到第一个匹配的就停止检查
            }
        }
    }
}