redef enum Notice::Type += {
    Intel_FeedMatch
};

hook Notice::policy(n: Notice::Info)
    {
    ensure_notice_kafka_stream();
    add n$actions[Notice::ACTION_LOG];
    }

event Intel::match(s: Intel::Seen, items: set[Intel::Item]) &priority=10
    {
    ensure_intel_kafka_stream();

    local handled_by_do_notice = F;

    for ( item in items )
        {
        if ( item$meta$do_notice )
            {
            handled_by_do_notice = T;
            break;
            }
        }

    if ( handled_by_do_notice || |items| == 0 )
        return;

    local n = Notice::Info(
        $note=Intel_FeedMatch,
        $msg=fmt("Intel feed hit on %s at %s", s$indicator, s$where),
        $sub=s$indicator
    );

    if ( s?$conn )
        {
        n$conn = s$conn;

        if ( s$conn?$id )
            {
            if ( s$conn$id$orig_h < s$conn$id$resp_h )
                n$identifier = cat(s$indicator, s$conn$id$orig_h, s$conn$id$resp_h);
            else
                n$identifier = cat(s$indicator, s$conn$id$resp_h, s$conn$id$orig_h);
            }
        }

    NOTICE(n);
    }
