const SCRIPT_ID = "DETECT_INTEL_FEED_HIT_v3";

event zeek_init()
	{
	# The actual offline Intel matching is implemented in
	# custom/offline/intel_replay.zeek, which is loaded through
	# custom/config.zeek by the Go service. This script exists as a
	# dedicated entry marker so the task can request an "Intel validation"
	# run without duplicating replay logic in per-task scripts.
	print fmt("%s loaded", SCRIPT_ID);
	}
