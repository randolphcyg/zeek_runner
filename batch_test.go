package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/segmentio/kafka-go"
)

func TestPlanBatchRunGroupsBatchesOnlyUniquelyAttributedScripts(t *testing.T) {
	root := t.TempDir()
	writeTestScript(t, root, "a.zeek", `const SCRIPT_ID = "A"; redef enum Notice::Type += { NoticeA };`)
	writeTestScript(t, root, "b.zeek", `const SCRIPT_ID = "B"; redef enum Notice::Type += { NoticeB };`)
	writeTestScript(t, root, "c.zeek", `const SCRIPT_ID = "C";`)
	writeTestScript(t, root, "d.zeek", `const SCRIPT_ID = "D"; redef enum Notice::Type += { NoticeA };`)

	cm := &ConfigManager{}
	cm.config.Store(&Config{
		Batch: BatchConfig{
			Enabled:              true,
			MaxScriptsPerZeekRun: 16,
		},
		Pool: PoolConfig{Size: 8},
		Zeek: ZeekConfig{ScriptRoot: root},
	})
	service := NewService(nil, cm, nil, nil, &kafka.Dialer{})

	tasks := []*Task{
		{TaskID: "task", UUID: "u-a", PcapID: "pcap", PcapPath: "/tmp/a.pcap", ScriptID: "A", ScriptPath: filepath.Join(root, "a.zeek"), Status: TaskStatusPending},
		{TaskID: "task", UUID: "u-b", PcapID: "pcap", PcapPath: "/tmp/a.pcap", ScriptID: "B", ScriptPath: filepath.Join(root, "b.zeek"), Status: TaskStatusPending},
		{TaskID: "task", UUID: "u-c", PcapID: "pcap", PcapPath: "/tmp/a.pcap", ScriptID: "C", ScriptPath: filepath.Join(root, "c.zeek"), Status: TaskStatusPending},
		{TaskID: "task", UUID: "u-d", PcapID: "pcap", PcapPath: "/tmp/a.pcap", ScriptID: "D", ScriptPath: filepath.Join(root, "d.zeek"), Status: TaskStatusPending},
	}

	groups := service.planBatchRunGroups(tasks)
	var batched int
	var singles int
	for _, group := range groups {
		if len(group.tasks) > 1 {
			batched++
			if len(group.tasks) != 2 {
				t.Fatalf("batch group size = %d, want 2", len(group.tasks))
			}
		} else {
			singles++
		}
	}
	if batched != 1 || singles != 2 {
		t.Fatalf("groups batched=%d singles=%d, want batched=1 singles=2", batched, singles)
	}
}

func TestNoticeAttributionCarriesUIDAndMapsStatsToScript(t *testing.T) {
	dir := t.TempDir()
	noticeLog := "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tnotice\n#fields\tts\tuid\tnote\tmsg\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n#types\ttime\tstring\tstring\tstring\taddr\tport\taddr\tport\tenum\n" +
		"1.0\tC123\tHTTP_Upload::Suspicious_File_Upload\tdetected\t1.1.1.1\t12345\t2.2.2.2\t80\ttcp\n"
	if err := os.WriteFile(filepath.Join(dir, "notice.log"), []byte(noticeLog), 0o600); err != nil {
		t.Fatalf("write notice.log: %v", err)
	}

	hits, err := parseNoticeLog(filepath.Join(dir, "notice.log"))
	if err != nil {
		t.Fatalf("parseNoticeLog: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("hits = %d, want 1", len(hits))
	}
	if hits[0].UID != "C123" || hits[0].RuleType != "HTTP_Upload::Suspicious_File_Upload" {
		t.Fatalf("unexpected hit attribution: %+v", hits[0])
	}

	stats := statsByNoticeOwner(dir, map[string]string{"Suspicious_File_Upload": "uuid-webshell"})
	if stats["uuid-webshell"].NoticeCount != 1 {
		t.Fatalf("notice count = %d, want 1", stats["uuid-webshell"].NoticeCount)
	}
}

func TestNoticeTypeMatchesPrefixedAndBareNames(t *testing.T) {
	cases := []struct {
		actual   string
		declared string
		want     bool
	}{
		{actual: "HTTP_Upload::Suspicious_File_Upload", declared: "HTTP_Upload::Suspicious_File_Upload", want: true},
		{actual: "HTTP_Upload::Suspicious_File_Upload", declared: "Suspicious_File_Upload", want: true},
		{actual: "Suspicious_File_Upload", declared: "HTTP_Upload::Suspicious_File_Upload", want: true},
		{actual: "Other::Suspicious_File_Upload", declared: "HTTP_Upload::Suspicious_File_Upload", want: false},
	}
	for _, tc := range cases {
		if got := noticeTypeMatches(tc.actual, tc.declared); got != tc.want {
			t.Fatalf("noticeTypeMatches(%q, %q) = %v, want %v", tc.actual, tc.declared, got, tc.want)
		}
	}
}

func TestFilteredSubtaskHitEventsKeepScriptAttribution(t *testing.T) {
	dir := t.TempDir()
	noticeLog := "#fields\tts\tuid\tnote\tmsg\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n" +
		"1.0\tC1\tNoticeA\tmessage-a\t1.1.1.1\t1111\t2.2.2.2\t80\ttcp\n" +
		"2.0\tC2\tNoticeB\tmessage-b\t3.3.3.3\t2222\t4.4.4.4\t443\ttcp\n"
	if err := os.WriteFile(filepath.Join(dir, "notice.log"), []byte(noticeLog), 0o600); err != nil {
		t.Fatalf("write notice.log: %v", err)
	}

	var got []analysisSubtaskHitEvent
	service := &Service{
		analysisPublisher: &analysisEventPublisher{
			publishFn: func(_ context.Context, _ string, eventType string, payload any) error {
				if eventType != "subtask_hit" {
					t.Fatalf("eventType = %s", eventType)
				}
				got = append(got, payload.(analysisSubtaskHitEvent))
				return nil
			},
		},
	}
	opts := zeekRunOptions{
		taskID:     "task",
		uuid:       "uuid-a",
		taskType:   string(offlineTaskScan),
		pcapID:     "pcap",
		pcapPath:   "/tmp/a.pcap",
		scriptID:   "SCRIPT_A",
		scriptPath: "/tmp/a.zeek",
	}
	if err := service.publishFilteredSubtaskHitEvents(context.Background(), opts, dir, map[string]string{"NoticeA": "uuid-a", "NoticeB": "uuid-b"}); err != nil {
		t.Fatalf("publishFilteredSubtaskHitEvents: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("events = %d, want 1", len(got))
	}
	if got[0].ScriptID != "SCRIPT_A" || got[0].UUID != "uuid-a" || got[0].UID != "C1" || got[0].RuleType != "NoticeA" {
		t.Fatalf("unexpected event attribution: %+v", got[0])
	}
}
