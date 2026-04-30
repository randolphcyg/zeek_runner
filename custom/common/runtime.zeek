@load base/frameworks/intel
@load base/frameworks/intel/input
@load policy/frameworks/intel/seen
@load policy/frameworks/intel/do_notice
@load Seiso/Kafka

global taskID = getenv("TASK_ID");
global uuid = getenv("UUID");
global onlyNotice = getenv("ONLY_NOTICE");
global pcapID = getenv("PCAP_ID");
global pcapPath = getenv("PCAP_PATH");
global scriptID = getenv("SCRIPT_ID");
global scriptPath = getenv("SCRIPT_PATH");
global analysisMode = getenv("ANALYSIS_MODE");
global notice_kafka_filter_added = F;
global intel_kafka_filter_added = F;

function current_analysis_mode(): string
    {
    if ( analysisMode != "" )
        return analysisMode;

    return "offline";
    }
