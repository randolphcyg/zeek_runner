@load base/protocols/http/utils

const replay_enabled = getenv("ENABLE_OFFLINE_INTEL_REPLAY") == "true";
redef exit_only_after_terminate = replay_enabled;

module OfflineIntelReplay;

type PendingIndicator: record {
    indicator: string;
    indicator_type: Intel::Type;
    where: Intel::Where;
};

global pending_addrs: set[addr] = set();
global pending_indicators: set[string, Intel::Type, Intel::Where] = set();
global feed_files_total: count = 0;
global feed_files_loaded: count = 0;
global feeds_ready = F;
global replay_done = F;
global terminate_scheduled = F;

function remember_indicator(indicator: string, indicator_type: Intel::Type, where: Intel::Where)
    {
    if ( indicator == "" )
        return;

    add pending_indicators[indicator, indicator_type, where];
    }

function replay_pending_observables()
    {
    if ( replay_done )
        return;

    replay_done = T;

    for ( host in pending_addrs )
        Intel::seen(Intel::Seen($where=Intel::IN_ANYWHERE, $host=host));

    for ( [indicator, indicator_type, where] in pending_indicators )
        {
        Intel::seen(Intel::Seen(
            $indicator=indicator,
            $indicator_type=indicator_type,
            $where=where
        ));
        }
    }

event zeek_init()
    {
    if ( ! replay_enabled )
        return;

    feed_files_total = |Intel::read_files|;
    print fmt("offline intel replay waiting for %d intel files", feed_files_total);
    }

event connection_established(c: connection)
    {
    if ( ! replay_enabled )
        return;

    if ( feeds_ready )
        return;

    add pending_addrs[c$id$orig_h];
    add pending_addrs[c$id$resp_h];
    }

event connection_state_remove(c: connection)
    {
    if ( ! replay_enabled )
        return;

    if ( feeds_ready )
        return;

    add pending_addrs[c$id$orig_h];
    add pending_addrs[c$id$resp_h];
    }

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    if ( ! replay_enabled )
        return;

    if ( feeds_ready )
        return;

    remember_indicator(query, Intel::DOMAIN, DNS::IN_REQUEST);
    }

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
    {
    if ( ! replay_enabled )
        return;

    if ( feeds_ready || ! is_orig || ! c?$http )
        return;

    remember_indicator(HTTP::build_url(c$http), Intel::URL, HTTP::IN_URL);
    }

event ssl_extension_server_name(c: connection, is_orig: bool, names: string_vec)
    {
    if ( ! replay_enabled )
        return;

    if ( feeds_ready || ! is_orig || ! c?$ssl || ! c$ssl?$server_name )
        return;

    remember_indicator(c$ssl$server_name, Intel::DOMAIN, SSL::IN_SERVER_NAME);
    }

event Input::end_of_data(name: string, source: string)
    {
    if ( ! replay_enabled )
        return;

    if ( source !in Intel::read_files )
        return;

    ++feed_files_loaded;

    if ( feed_files_loaded < feed_files_total )
        return;

    feeds_ready = T;
    replay_pending_observables();

    if ( ! terminate_scheduled )
        {
        terminate_scheduled = T;
        terminate();
        }
    }
