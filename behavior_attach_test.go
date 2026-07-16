package main

import "testing"

func TestFindBehaviorBlockUsesHTTPTransactionDepth(t *testing.T) {
	blocks := map[string]map[int]behaviorBlock{
		"uid-1": {
			1: {BehaviorRuleID: "CHECK-1", URLType: "upgrade_check"},
			2: {BehaviorRuleID: "DOWNLOAD-2", URLType: "firmware_download"},
		},
	}
	first := findBehaviorBlock(&urlObservedEvent{UID: "uid-1", HTTPTransDepth: 1}, blocks, nil)
	second := findBehaviorBlock(&urlObservedEvent{UID: "uid-1", HTTPTransDepth: 2}, blocks, nil)
	if first == nil || first.BehaviorRuleID != "CHECK-1" {
		t.Fatalf("first transaction block = %#v", first)
	}
	if second == nil || second.BehaviorRuleID != "DOWNLOAD-2" {
		t.Fatalf("second transaction block = %#v", second)
	}
}

func TestFindBehaviorBlockRefusesAmbiguousConnectionWithoutDepth(t *testing.T) {
	blocks := map[string]map[int]behaviorBlock{
		"uid-1": {1: {BehaviorRuleID: "CHECK-1"}, 2: {BehaviorRuleID: "DOWNLOAD-2"}},
	}
	if got := findBehaviorBlock(&urlObservedEvent{UID: "uid-1"}, blocks, nil); got != nil {
		t.Fatalf("ambiguous transaction must not use first block: %#v", got)
	}
}
