package main

import (
	"fmt"
	"log/slog"
	"strings"
)

// attachBehaviorBlocks 将行为识别结果附加到 URL 事件。
//
// 流程：
// 1. 从 pcap 重组 HTTP 事务（支持 keep-alive、chunked、gzip/deflate/br）
// 2. 每个 HTTP 事务经 behaviorEngine 识别后生成 behaviorBlock
// 3. 按 UID/连接五元组将 behaviorBlock 关联到对应的 http_download 事件
// 4. TLS SNI 事件执行 metadata_only 识别
// 5. DNS 事件执行 metadata_only 识别
//
// 禁止将 requestBody、responseBody、解密正文或完整文件内容发送到 Kafka。
func (s *Service) attachBehaviorBlocks(events []urlObservedEvent, opts zeekRunOptions) {
	if s == nil || s.behaviorEngine == nil {
		return
	}
	eng := s.behaviorEngine

	// 1. 从 pcap 重组 HTTP 事务并执行行为识别
	// 返回按 UID 索引的 behaviorBlock 列表（同一连接可能有多个事务）
	txnBlocks := make(map[string]map[int]behaviorBlock)  // key = UID, then HTTP transaction depth
	connBlocks := make(map[string]map[int]behaviorBlock) // key = "srcIP:srcPort-dstIP:dstPort", then depth

	if opts.pcapPath != "" {
		transactions, err := reassembleHTTPTransactions(opts.pcapPath)
		if err != nil {
			slog.Warn("HTTP transaction reassembly failed, behavior blocks limited to metadata_only",
				"pcap_id", opts.pcapID, "err", err)
		} else {
			for _, tx := range transactions {
				// 设置 UID（如果有 Zeek UID 可关联，此处用连接派生）
				if tx.UID == "" {
					tx.UID = deriveUIDFromConn(tx.SrcIP, tx.SrcPort, tx.DstIP, tx.DstPort)
				}
				block := eng.analyzeHTTPTransaction(tx, opts.pcapID)
				// 只保存有实际识别结果的块（有 URLType 或有 payload）
				if block.URLType != "" || block.PayloadSHA256 != "" {
					if txnBlocks[tx.UID] == nil {
						txnBlocks[tx.UID] = make(map[int]behaviorBlock)
					}
					txnBlocks[tx.UID][tx.TxSeq] = block
					connKey := fmt.Sprintf("%s:%d-%s:%d", tx.SrcIP, tx.SrcPort, tx.DstIP, tx.DstPort)
					if connBlocks[connKey] == nil {
						connBlocks[connKey] = make(map[int]behaviorBlock)
					}
					connBlocks[connKey][tx.TxSeq] = block
				}
			}
		}
	}

	// 2. 将 behaviorBlock 附加到 URL 事件
	for i := range events {
		ev := &events[i]

		switch {
		case ev.Protocol == "tls" && ev.SNI != "":
			// TLS SNI 事件：metadata_only，不得伪造正文级命中
			block := eng.analyzeSNIEvent(ev.SNI, ev.Host, ev.SrcIP, ev.SrcPort, ev.DstIP, ev.DstPort)
			ev.Behavior = &block
			RecordBehaviorBlock(block)

		case ev.Protocol == "dns" && ev.DNSQuery != "":
			// DNS 事件：metadata_only，不得伪造正文级命中
			block := eng.analyzeDNSEvent(ev.DNSQuery, ev.DNSAnswers, ev.SrcIP, ev.SrcPort, ev.DstIP, ev.DstPort)
			ev.Behavior = &block
			RecordBehaviorBlock(block)

		case ev.Source == "http_download" || ev.Source == "http_request":
			// HTTP 事件：按 UID 或连接五元组匹配 behaviorBlock
			block := findBehaviorBlock(ev, txnBlocks, connBlocks)
			if block != nil {
				ev.Behavior = block
				RecordBehaviorBlock(*block)
			} else {
				RecordBehaviorUnmatchedTransaction()
			}
		}
	}
}

// findBehaviorBlock 查找与 URL 事件匹配的 behaviorBlock。
// 优先按 Zeek UID 匹配，其次按连接五元组匹配。
func findBehaviorBlock(ev *urlObservedEvent, txnBlocks map[string]map[int]behaviorBlock, connBlocks map[string]map[int]behaviorBlock) *behaviorBlock {
	// HTTP keep-alive 必须有 Zeek trans_depth 才能安全关联。未知深度且同连接
	// 存在多个事务时宁可不附加，也不能复用第一个事务的识别结果。
	depth := ev.HTTPTransDepth
	// 按 UID 匹配
	if ev.UID != "" {
		if blocks, ok := txnBlocks[ev.UID]; ok {
			if depth > 0 {
				if b, exists := blocks[depth]; exists {
					return &b
				}
				return nil
			}
			if len(blocks) == 1 {
				for _, b := range blocks {
					return &b
				}
			}
		}
	}
	// 按连接五元组匹配
	connKey := fmt.Sprintf("%s:%d-%s:%d", ev.SrcIP, ev.SrcPort, ev.DstIP, ev.DstPort)
	if b := blockAtDepth(connBlocks[connKey], depth); b != nil {
		return b
	}
	// 反向连接（响应流方向）
	connKeyRev := fmt.Sprintf("%s:%d-%s:%d", ev.DstIP, ev.DstPort, ev.SrcIP, ev.SrcPort)
	if b := blockAtDepth(connBlocks[connKeyRev], depth); b != nil {
		return b
	}
	return nil
}

func blockAtDepth(blocks map[int]behaviorBlock, depth int) *behaviorBlock {
	if len(blocks) == 0 {
		return nil
	}
	if depth > 0 {
		if b, ok := blocks[depth]; ok {
			return &b
		}
		return nil
	}
	if len(blocks) == 1 {
		for _, b := range blocks {
			return &b
		}
	}
	return nil
}

// deriveUIDFromConn 从连接五元组派生 UID（当 Zeek UID 不可用时）。
func deriveUIDFromConn(srcIP string, srcPort int, dstIP string, dstPort int) string {
	return strings.ReplaceAll(
		fmt.Sprintf("C%s%05d%s%05d", srcIP, srcPort, dstIP, dstPort),
		".", "_",
	)
}
