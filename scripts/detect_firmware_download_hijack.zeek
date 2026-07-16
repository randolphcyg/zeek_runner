# SCRIPT_ID: DETECT_FIRMWARE_DOWNLOAD_HIJACK_v1
# NoticeTypes: FirmwareDownloadHijack::Firmware_Download_Observed, FirmwareDownloadHijack::Firmware_Insecure_Download, FirmwareDownloadHijack::Firmware_Suspicious_Source, FirmwareDownloadHijack::Firmware_Redirect_Hijack, FirmwareDownloadHijack::Firmware_Replacement_Suspected

# 恶意行为检测脚本配置
# 行为类型：固件下载替换/下载劫持
# 行为分类：固件供应链安全
# 行为描述：检测固件下载流量中的明文下载、可疑来源、异常跳转以及同一固件资源被替换的行为
# 攻击特征：固件文件通过HTTP明文传输、下载源命中可疑域名/IP、升级下载被重定向到异常地址、同一固件URL返回不同大小或MIME

@load base/frameworks/notice
@load base/protocols/http
@load base/frameworks/files

module FirmwareDownloadHijack;

export {
    redef enum Notice::Type += {
        Firmware_Download_Observed,
        Firmware_Insecure_Download,
        Firmware_Suspicious_Source,
        Firmware_Redirect_Hijack,
        Firmware_Replacement_Suspected
    };

    const firmware_extensions: set[string] = {
        ".bin",
        ".img",
        ".fw",
        ".trx",
        ".chk",
        ".pkg",
        ".upd",
        ".sig",
        ".manifest",
        ".json"
    } &redef;

    const firmware_path_tokens: set[string] = {
        "/firmware",
        "/fw/",
        "/ota",
        "/upgrade",
        "/update",
        "/updates/",
        "/download/firmware"
    } &redef;

    const firmware_mime_types: set[string] = {
        "application/octet-stream",
        "application/x-firmware",
        "application/x-binary",
        "application/x-gzip",
        "application/zip",
        "application/json",
        "text/plain"
    } &redef;

    const trusted_firmware_hosts: set[string] = {} &redef;

    const suspicious_firmware_hosts: set[string] = {
        "bad-update.local",
        "malware-update.local",
        "evil-firmware.local"
    } &redef;

    const suspicious_firmware_ips: set[addr] = {
        203.0.113.66,
        198.51.100.77
    } &redef;

    global request_uri: table[string] of string &default="";
    global request_method: table[string] of string &default="";
    global request_host: table[string] of string &default="";
    global response_mime: table[string] of string &default="";
    global response_length: table[string] of string &default="";
    global response_location: table[string] of string &default="";
    global response_code: table[string] of count &default=0;
    global firmware_request: set[string];
    global checked_response: set[string];
    global seen_firmware_signature: table[string] of string &default="";
}

function is_firmware_uri(uri: string): bool
    {
    local u = to_lower(uri);

    for ( ext in firmware_extensions )
        {
        if ( ends_with(u, ext) || ext in u )
            return T;
        }

    for ( token in firmware_path_tokens )
        {
        if ( token in u )
            return T;
        }

    return F;
    }

function host_is_trusted(host: string): bool
    {
    if ( host == "" )
        return F;

    if ( host in trusted_firmware_hosts )
        return T;

    for ( trusted in trusted_firmware_hosts )
        {
        if ( ends_with(host, "." + trusted) )
            return T;
        }

    return F;
    }

function host_is_suspicious(host: string): bool
    {
    if ( host == "" )
        return F;

    if ( host in suspicious_firmware_hosts )
        return T;

    for ( suspicious in suspicious_firmware_hosts )
        {
        if ( ends_with(host, "." + suspicious) )
            return T;
        }

    return F;
    }

function location_is_suspicious(location: string): bool
    {
    local loc = to_lower(location);

    if ( loc == "" )
        return F;

    if ( /^http:\/\// in loc )
        return T;

    for ( suspicious in suspicious_firmware_hosts )
        {
        if ( suspicious in loc )
            return T;
        }

    return F;
    }

function firmware_key(host: string, uri: string): string
    {
    return fmt("%s%s", host, uri);
    }

function firmware_signature(mime: string, length: string): string
    {
    return fmt("mime=%s length=%s", mime, length);
    }

function check_firmware_response(c: connection, code: count)
    {
    if ( c$uid !in firmware_request )
        return;

    local host = request_host[c$uid];
    local uri = request_uri[c$uid];
    local mime = response_mime[c$uid];
    local length = response_length[c$uid];
    local location = response_location[c$uid];
    local key = firmware_key(host, uri);
    local sig = firmware_signature(mime, length);

    NOTICE([$note=Firmware_Download_Observed,
            $msg=fmt("检测到固件相关下载: host=%s uri=%s", host, uri),
            $sub=sig,
            $conn=c,
            $uid=c$uid]);

    if ( c$id$resp_p == 80/tcp )
        {
        NOTICE([$note=Firmware_Insecure_Download,
                $msg=fmt("固件通过HTTP明文下载: host=%s uri=%s", host, uri),
                $sub=sig,
                $conn=c,
                $uid=c$uid]);
        }

    if ( host_is_suspicious(host) || c$id$resp_h in suspicious_firmware_ips || ( |trusted_firmware_hosts| > 0 && ! host_is_trusted(host) ) )
        {
        NOTICE([$note=Firmware_Suspicious_Source,
                $msg=fmt("固件下载源异常: host=%s server=%s uri=%s", host, c$id$resp_h, uri),
                $sub=sig,
                $conn=c,
                $uid=c$uid]);
        }

    if ( code >= 300 && code < 400 && location_is_suspicious(location) )
        {
        NOTICE([$note=Firmware_Redirect_Hijack,
                $msg=fmt("固件下载出现可疑跳转: host=%s uri=%s", host, uri),
                $sub=fmt("Location: %s", location),
                $conn=c,
                $uid=c$uid]);
        }

    if ( key in seen_firmware_signature && seen_firmware_signature[key] != sig )
        {
        NOTICE([$note=Firmware_Replacement_Suspected,
                $msg=fmt("同一固件资源返回内容特征变化: host=%s uri=%s", host, uri),
                $sub=fmt("previous=%s current=%s", seen_firmware_signature[key], sig),
                $conn=c,
                $uid=c$uid]);
        }
    else if ( key !in seen_firmware_signature )
        {
        seen_firmware_signature[key] = sig;
        }
    }

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
    {
    request_method[c$uid] = method;
    request_uri[c$uid] = unescaped_URI;

    if ( is_firmware_uri(unescaped_URI) || is_firmware_uri(original_URI) )
        add firmware_request[c$uid];
    }

event http_header(c: connection, is_orig: bool, name: string, value: string)
    {
    local lname = to_lower(name);

    if ( is_orig && lname == "host" )
        request_host[c$uid] = to_lower(value);

    if ( ! is_orig && lname == "content-type" )
        {
        local mime = to_lower(value);
        response_mime[c$uid] = mime;

        if ( mime in firmware_mime_types && is_firmware_uri(request_uri[c$uid]) )
            add firmware_request[c$uid];
        }

    if ( ! is_orig && lname == "content-length" )
        response_length[c$uid] = value;

    if ( ! is_orig && lname == "location" )
        response_location[c$uid] = value;
    }

event http_reply(c: connection, version: string, code: count, reason: string)
    {
    response_code[c$uid] = code;
    }

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
    {
    if ( is_orig || c$uid in checked_response )
        return;

    add checked_response[c$uid];
    check_firmware_response(c, response_code[c$uid]);
    }
