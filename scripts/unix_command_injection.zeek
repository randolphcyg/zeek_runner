@load base/frameworks/notice
@load base/protocols/http

module UnixCommand;

export {
    redef enum Notice::Type += {
        UnixCommandInjection
    };

    type Sig: record {
        regex: pattern;
        name: string;
    };

    type SigVec: vector of Sig;

    global sigs = SigVec(
        [$regex = /.*\.\.\/\.\.\/.*/,
         $name = "unix_arcsight-1"],
        [$regex = /.*\/etc\/shadow.*/,
         $name = "unix_arcsight-2"],
        [$regex = /.*\/etc\/passwd.*/,
         $name = "unix_arcsight-3"]
    );
}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
    for (i in sigs) {
        local sig = sigs[i];
        if (sig$regex in original_URI) {
            NOTICE([
                $note = UnixCommandInjection,
                $msg = fmt("Possible Unix command injection detected in URI: %s, Signature: %s", original_URI, sig$name),
                $conn = c,
                $uid = c$uid
            ]);
        }
    }
}