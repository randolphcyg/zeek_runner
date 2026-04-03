@load frameworks/files/extract-all-files
@load base/utils/files

global extractedFilePath = getenv("EXTRACTED_FILE_PATH");
global extractedFileMinSize = getenv("EXTRACTED_FILE_MIN_SIZE");
redef FileExtract::prefix = extractedFilePath;
const MIN_FILE_SIZE = 1 * 1024;

event zeek_init() {
    Kafka::headers["extractedFilePath"] = FileExtract::prefix;
}

const ALLOWED_MIME_TYPES = set(
    "application/zip",
    "application/x-zip-compressed",
    "application/x-rar-compressed",
    "application/octet-stream",
    "application/x-msdownload",
    "application/x-dosexec",
);

const mime_mappings: table[string] of string = {
    ["application/zip"] = ".zip",
    ["application/x-zip-compressed"] = ".zip",
    ["application/x-rar-compressed"] = ".rar",
    ["application/octet-stream"] = ".bin",
    ["application/x-msdownload"] = ".exe",
    ["application/x-dosexec"] = ".exe"
} &redef;

global task_file_hashes: table[string] of table[string] of count = table();
global file_hash_to_path: table[string] of string = table();
global file_hash_count: table[string] of count = table();

function url_decode(s: string): string {
    local result = gsub(s, /\%20/, " ");
    result = gsub(result, /\%2E/, ".");
    result = gsub(result, /\%2D/, "-");
    result = gsub(result, /\%5F/, "_");
    result = gsub(result, /\+/, " ");
    return result;
}

function get_extension(name: string): string {
    local parts = split_string(name, /\./);
    if (|parts| > 1) {
        return "." + parts[|parts|-1];
    }
    return "";
}

function get_mime_extension(f: fa_file): string {
    if (!f?$info || !f$info?$mime_type) {
        return "";
    }
    local mime_type = to_lower(f$info$mime_type);
    return mime_type in mime_mappings ? mime_mappings[mime_type] : "";
}

function get_http_filename(f: fa_file): string {
    local filename = "";
    local final_name = "";

    if (f$http?$uri) {
        local uri = f$http$uri;
        local uri_parts = split_string(uri, /\//);
        if (|uri_parts| > 0) {
            filename = uri_parts[|uri_parts|-1];
            local query_parts = split_string(filename, /\?/);
            filename = query_parts[0];
            filename = url_decode(filename);
        }
    }

    if (filename != "" && filename != "/" &&
        filename != "index.html" && filename != "index.htm") {
        final_name = filename;
    } else {
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

    local ext = get_extension(final_name);
    if (ext == "") {
        ext = get_mime_extension(f);
        if (ext != "") {
            final_name = fmt("%s%s", final_name, ext);
        }
    }

    return final_name;
}

function generate_filename(f: fa_file): string {
    local fname = "";

    if (f?$http) {
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

    fname = gsub(fname, /[\/\\:*?"<>|]/, "_");

    return fname;
}

function get_task_id(): string {
    return getenv("TASK_ID");
}

event file_sniff(f: fa_file, meta: fa_metadata) {
    if (f?$info && f$info?$mime_type) {
        if (f$info$mime_type == "application/x-x509-user-cert" ||
            f$info$mime_type == "application/x-x509-ca-cert" ||
            f$info$mime_type == "application/ocsp-response") {
            Files::skip(f$id);
            return;
        }

        if (f$info$mime_type !in ALLOWED_MIME_TYPES) {
            Files::skip(f$id);
            return;
        }
    }

    local min_size = MIN_FILE_SIZE;
    if (extractedFileMinSize != "") {
        min_size = to_count(extractedFileMinSize) * 1024;
    }

    if (f?$total_bytes && f$total_bytes < min_size) {
        Files::skip(f$id);
        return;
    }

    Files::add_analyzer(f$id, Files::ANALYZER_MD5);
    Files::add_analyzer(f$id, Files::ANALYZER_SHA256);
}

event file_hash(f: fa_file, kind: string, hash: string) {
    if (kind != "sha256" && kind != "md5") {
        return;
    }

    if (f?$info) {
        if (kind == "sha256") {
            f$info$sha256 = hash;
        } else if (kind == "md5") {
            f$info$md5 = hash;
        }
    }

    if (kind == "sha256") {
        local task_id = get_task_id();
        local file_hash = hash;

        if (task_id != "" && task_id in task_file_hashes) {
            if (file_hash in task_file_hashes[task_id]) {
                task_file_hashes[task_id][file_hash] = task_file_hashes[task_id][file_hash] + 1;
                file_hash_count[file_hash] = file_hash_count[file_hash] + 1;

                print fmt("DUPLICATE_IN_TASK: hash=%s task=%s count=%d existing=%s",
                    file_hash, task_id, task_file_hashes[task_id][file_hash],
                    file_hash_to_path[file_hash]);

                Files::skip(f$id);

                if (f?$info) {
                    f$info$extracted = fmt("DUPLICATE:%s", file_hash_to_path[file_hash]);
                }
            }
        }
    }
}

event file_state_remove(f: fa_file) {
    if (!f?$http) {
        return;
    }

    if (!f?$total_bytes || f$total_bytes <= MIN_FILE_SIZE * 1024) {
        return;
    }

    if (f?$info && f$info?$mime_type) {
        local mime_type = f$info$mime_type;
        if (mime_type !in ALLOWED_MIME_TYPES) {
            return;
        }
    }

    if (f?$info && f$info?$extracted && /^DUPLICATE:/ in f$info$extracted) {
        return;
    }

    local new_filename = generate_filename(f);
    if (new_filename == "") {
        return;
    }

    local ext = get_extension(new_filename);
    local mime_ext = get_mime_extension(f);
    if (ext == "" && mime_ext == "") {
        return;
    }

    local size = f$total_bytes;
    local file_hash = "";
    if (f?$info && f$info?$sha256) {
        file_hash = f$info$sha256;
    } else if (f?$info && f$info?$md5) {
        file_hash = f$info$md5;
    }

    local msg = fmt("FILE_EXTRACTED: file=%s size=%d", new_filename, size);
    if (file_hash != "") {
        msg += fmt(" hash=%s", file_hash);
    }
    if (f?$info && f$info?$mime_type) {
        msg += fmt(" mime=%s", f$info$mime_type);
    }
    if (f$http?$uri) {
        msg += fmt(" uri=%s", f$http$uri);
    }
    print msg;

    local old_path = fmt("%s/%s", FileExtract::prefix, f$info$extracted);
    local new_path = fmt("%s/%s", FileExtract::prefix, new_filename);
    if (rename(old_path, new_path)) {
        f$info$extracted = new_path;
        print fmt("FILE_RENAMED: %s -> %s", old_path, new_path);

        if (file_hash != "") {
            local task_id = get_task_id();
            if (task_id != "") {
                if (task_id !in task_file_hashes) {
                    task_file_hashes[task_id] = table();
                }
                task_file_hashes[task_id][file_hash] = 1;
                file_hash_to_path[file_hash] = new_path;
                if (file_hash !in file_hash_count) {
                    file_hash_count[file_hash] = 1;
                }
            }
        }
    } else {
        print fmt("FILE_RENAME_FAILED: %s", old_path);
    }
}

event zeek_done() {
    local task_id = get_task_id();
    if (task_id != "" && task_id in task_file_hashes) {
        local total_files = 0;
        local total_duplicates = 0;

        for (hash in task_file_hashes[task_id]) {
            total_files += 1;
            if (task_file_hashes[task_id][hash] > 1) {
                total_duplicates += task_file_hashes[task_id][hash] - 1;
            }
        }

        print fmt("TASK_SUMMARY: task=%s unique_files=%d total_duplicates=%d",
            task_id, total_files, total_duplicates);
    }
}
