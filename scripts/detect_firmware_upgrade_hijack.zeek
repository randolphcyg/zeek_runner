# SCRIPT_ID: DETECT_FIRMWARE_UPGRADE_HIJACK_v1
# NoticeTypes: FirmwareUpgradeHijack::Firmware_Upgrade_Endpoint, FirmwareUpgradeHijack::Firmware_Insecure_Upgrade, FirmwareUpgradeHijack::Firmware_Manifest_Hijack, FirmwareUpgradeHijack::Firmware_Signature_Missing, FirmwareUpgradeHijack::Firmware_Rollback_Suspected, FirmwareUpgradeHijack::Firmware_Upload_Observed

# 恶意行为检测脚本配置
# 行为类型：固件升级劫持/OTA劫持
# 行为分类：固件供应链安全
# 行为描述：检测固件升级接口、OTA manifest 中的明文下载源、签名缺失、版本回滚以及固件上传升级行为
# 攻击特征：升级接口返回HTTP固件URL、manifest缺少签名/校验字段、版本号回退、管理接口上传固件包

@load base/frameworks/notice
@load base/protocols/http
@load base/frameworks/files

module FirmwareUpgradeHijack;

export {
    redef enum Notice::Type += {
        Firmware_Upgrade_Endpoint,
        Firmware_Insecure_Upgrade,
        Firmware_Manifest_Hijack,
        Firmware_Signature_Missing,
        Firmware_Rollback_Suspected,
        Firmware_Upload_Observed
    };

    const upgrade_path_tokens: set[string] = {
        "/ota",
        "/upgrade",
        "/update",
        "/firmware",
        "/check_update",
        "/check-update",
        "/api/update",
        "/api/firmware",
        "/cgi-bin/upgrade",
        "/goform/upgrade"
    } &redef;

    const firmware_extensions: set[string] = {
        ".bin",
        ".img",
        ".fw",
        ".trx",
        ".chk",
        ".pkg",
        ".upd"
    } &redef;

    const manifest_mime_types: set[string] = {
        "application/json",
        "text/json",
        "text/plain",
        "application/xml",
        "text/xml"
    } &redef;

    const suspicious_manifest_hosts: set[string] = {
        "bad-update.local",
        "malware-update.local",
        "evil-firmware.local"
    } &redef;

    const max_manifest_bytes: count = 8192 &redef;

    global request_uri: table[string] of string &default="";
    global request_method: table[string] of string &default="";
    global request_host: table[string] of string &default="";
    global response_mime: table[string] of string &default="";
    global response_body: table[string] of string &default="";
    global upgrade_request: set[string];
    global latest_version_by_host: table[string] of string &default="";
}

function uri_has_token(uri: string, tokens: set[string]): bool
    {
    local u = to_lower(uri);

    for ( token in tokens )
        {
        if ( token in u )
            return T;
        }

    return F;
    }

function is_firmware_uri(uri: string): bool
    {
    local u = to_lower(uri);

    for ( ext in firmware_extensions )
        {
        if ( ends_with(u, ext) || ext in u )
            return T;
        }

    return F;
    }

function is_upgrade_uri(uri: string): bool
    {
    return uri_has_token(uri, upgrade_path_tokens);
    }

function body_has_suspicious_host(body: string): bool
    {
    for ( host in suspicious_manifest_hosts )
        {
        if ( host in body )
            return T;
        }

    return F;
    }

function extract_major_version(text: string): count
    {
    local lower = to_lower(text);

    if ( /v?[0-9]+\.[0-9]+/ !in lower && /version/ !in lower )
        return 0;

    if ( /(^|[^0-9])9\.[0-9]+/ in lower ) return 9;
    if ( /(^|[^0-9])8\.[0-9]+/ in lower ) return 8;
    if ( /(^|[^0-9])7\.[0-9]+/ in lower ) return 7;
    if ( /(^|[^0-9])6\.[0-9]+/ in lower ) return 6;
    if ( /(^|[^0-9])5\.[0-9]+/ in lower ) return 5;
    if ( /(^|[^0-9])4\.[0-9]+/ in lower ) return 4;
    if ( /(^|[^0-9])3\.[0-9]+/ in lower ) return 3;
    if ( /(^|[^0-9])2\.[0-9]+/ in lower ) return 2;
    if ( /(^|[^0-9])1\.[0-9]+/ in lower ) return 1;

    return 0;
    }

function inspect_manifest(c: connection)
    {
    if ( c$uid !in upgrade_request )
        return;

    local body = to_lower(response_body[c$uid]);
    local uri = request_uri[c$uid];
    local host = request_host[c$uid];
    local key = fmt("%s%s", c$id$orig_h, host);

    if ( body == "" )
        return;

    if ( "http://" in body && is_firmware_uri(body) )
        {
        NOTICE([$note=Firmware_Manifest_Hijack,
                $msg=fmt("升级manifest包含明文固件下载地址: host=%s uri=%s", host, uri),
                $sub=body,
                $conn=c,
                $uid=c$uid]);
        }

    if ( body_has_suspicious_host(body) )
        {
        NOTICE([$note=Firmware_Manifest_Hijack,
                $msg=fmt("升级manifest指向可疑固件下载源: host=%s uri=%s", host, uri),
                $sub=body,
                $conn=c,
                $uid=c$uid]);
        }

    if ( is_firmware_uri(body) && "sha256" !in body && "sha512" !in body && "signature" !in body && "sig" !in body )
        {
        NOTICE([$note=Firmware_Signature_Missing,
                $msg=fmt("升级manifest缺少固件签名或哈希字段: host=%s uri=%s", host, uri),
                $sub=body,
                $conn=c,
                $uid=c$uid]);
        }

    local current_major = extract_major_version(body);
    if ( current_major > 0 )
        {
        local previous_major = 0;
        if ( key in latest_version_by_host )
            previous_major = to_count(latest_version_by_host[key]);

        if ( previous_major > 0 && current_major < previous_major )
            {
            NOTICE([$note=Firmware_Rollback_Suspected,
                    $msg=fmt("检测到固件版本回滚迹象: previous=%s current=%s", latest_version_by_host[key], current_major),
                    $sub=fmt("host=%s uri=%s", host, uri),
                    $conn=c,
                    $uid=c$uid]);
            }

        if ( current_major > previous_major )
            latest_version_by_host[key] = fmt("%s", current_major);
        }
    }

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
    {
    request_method[c$uid] = method;
    request_uri[c$uid] = unescaped_URI;

    if ( is_upgrade_uri(unescaped_URI) || is_upgrade_uri(original_URI) )
        {
        add upgrade_request[c$uid];

        NOTICE([$note=Firmware_Upgrade_Endpoint,
                $msg=fmt("检测到固件升级相关接口访问: method=%s uri=%s", method, unescaped_URI),
                $conn=c,
                $uid=c$uid]);

        if ( c$id$resp_p == 80/tcp )
            {
            NOTICE([$note=Firmware_Insecure_Upgrade,
                    $msg=fmt("固件升级接口通过HTTP明文访问: method=%s uri=%s", method, unescaped_URI),
                    $conn=c,
                    $uid=c$uid]);
            }
        }

    if ( ( method == "POST" || method == "PUT" ) && ( is_upgrade_uri(unescaped_URI) || is_firmware_uri(unescaped_URI) ) )
        {
        NOTICE([$note=Firmware_Upload_Observed,
                $msg=fmt("检测到固件上传/升级提交行为: method=%s uri=%s", method, unescaped_URI),
                $conn=c,
                $uid=c$uid]);
        }
    }

event http_header(c: connection, is_orig: bool, name: string, value: string)
    {
    local lname = to_lower(name);

    if ( is_orig && lname == "host" )
        request_host[c$uid] = to_lower(value);

    if ( ! is_orig && lname == "content-type" )
        response_mime[c$uid] = to_lower(value);
    }

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
    {
    if ( is_orig || c$uid !in upgrade_request )
        return;

    if ( |response_body[c$uid]| >= max_manifest_bytes )
        return;

    response_body[c$uid] += data;
    }

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
    {
    if ( is_orig )
        return;

    if ( response_mime[c$uid] == "" || response_mime[c$uid] in manifest_mime_types )
        inspect_manifest(c);
    }

