package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
)

func TestDecodeHTTPContent_Identity(t *testing.T) {
	body := []byte("hello world")
	result := decodeHTTPContent("", body)
	if !result.Complete {
		t.Fatalf("expected complete decode for identity, got err=%v", result.Err)
	}
	if !bytes.Equal(result.Body, body) {
		t.Fatalf("identity decode changed body: got %q", result.Body)
	}

	result = decodeHTTPContent("identity", body)
	if !result.Complete {
		t.Fatalf("expected complete decode for identity, got err=%v", result.Err)
	}
	if !bytes.Equal(result.Body, body) {
		t.Fatalf("identity decode changed body: got %q", result.Body)
	}
}

func TestDecodeHTTPContent_Gzip(t *testing.T) {
	original := []byte("firmware-body-" + strings.Repeat("A", 1024))
	var compressed bytes.Buffer
	gw := gzip.NewWriter(&compressed)
	if _, err := gw.Write(original); err != nil {
		t.Fatalf("gzip compress: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	result := decodeHTTPContent("gzip", compressed.Bytes())
	if !result.Complete {
		t.Fatalf("expected complete gzip decode, got err=%v", result.Err)
	}
	if !bytes.Equal(result.Body, original) {
		t.Fatalf("gzip decode mismatch: got %d bytes, want %d", len(result.Body), len(original))
	}
}

func TestDecodeHTTPContent_GzipTruncated_PartialPayload(t *testing.T) {
	original := []byte("firmware-body-" + strings.Repeat("B", 4096))
	var compressed bytes.Buffer
	gw := gzip.NewWriter(&compressed)
	if _, err := gw.Write(original); err != nil {
		t.Fatalf("gzip compress: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	// 截断压缩数据，模拟不完整 gzip 流
	truncated := compressed.Bytes()[:compressed.Len()/2]
	result := decodeHTTPContent("gzip", truncated)
	if result.Complete {
		t.Fatalf("expected incomplete decode for truncated gzip")
	}
	if result.Err == nil {
		t.Fatalf("expected error for truncated gzip")
	}
	// partial_payload: 解码出的部分内容应非空（gzip 前面部分可以解出一些数据）
	// 即使解不出数据，也必须返回原始输入以供后续处理
	if len(result.Body) == 0 {
		t.Fatalf("expected non-empty body (partial or original) for truncated gzip")
	}
}

func TestDecodeHTTPContent_Deflate_Zlib(t *testing.T) {
	original := []byte(`{"version":"1.2.3","update_required":true}`)
	var compressed bytes.Buffer
	zw := zlib.NewWriter(&compressed)
	if _, err := zw.Write(original); err != nil {
		t.Fatalf("zlib compress: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}

	result := decodeHTTPContent("deflate", compressed.Bytes())
	if !result.Complete {
		t.Fatalf("expected complete deflate (zlib) decode, got err=%v", result.Err)
	}
	if !bytes.Equal(result.Body, original) {
		t.Fatalf("deflate (zlib) decode mismatch: got %q", result.Body)
	}
}

func TestDecodeHTTPContent_Deflate_Raw(t *testing.T) {
	original := []byte(`{"status":"upgrading","progress":50}`)
	var compressed bytes.Buffer
	fw, _ := flate.NewWriter(&compressed, flate.DefaultCompression)
	if _, err := fw.Write(original); err != nil {
		t.Fatalf("raw deflate compress: %v", err)
	}
	if err := fw.Close(); err != nil {
		t.Fatalf("raw deflate close: %v", err)
	}

	result := decodeHTTPContent("deflate", compressed.Bytes())
	if !result.Complete {
		t.Fatalf("expected complete deflate (raw) decode, got err=%v", result.Err)
	}
	if !bytes.Equal(result.Body, original) {
		t.Fatalf("deflate (raw) decode mismatch: got %q", result.Body)
	}
}

func TestDecodeHTTPContent_Brotli(t *testing.T) {
	original := []byte("apk-content-" + strings.Repeat("C", 2048))
	var compressed bytes.Buffer
	bw := brotli.NewWriterV2(&compressed, brotli.BestCompression)
	if _, err := bw.Write(original); err != nil {
		t.Fatalf("brotli compress: %v", err)
	}
	if err := bw.Close(); err != nil {
		t.Fatalf("brotli close: %v", err)
	}

	result := decodeHTTPContent("br", compressed.Bytes())
	if !result.Complete {
		t.Fatalf("expected complete brotli decode, got err=%v", result.Err)
	}
	if !bytes.Equal(result.Body, original) {
		t.Fatalf("brotli decode mismatch: got %d bytes, want %d", len(result.Body), len(original))
	}
}

func TestDecodeHTTPContent_BrotliTruncated_PartialPayload(t *testing.T) {
	original := []byte(strings.Repeat("D", 8192))
	var compressed bytes.Buffer
	bw := brotli.NewWriterV2(&compressed, brotli.BestCompression)
	if _, err := bw.Write(original); err != nil {
		t.Fatalf("brotli compress: %v", err)
	}
	if err := bw.Close(); err != nil {
		t.Fatalf("brotli close: %v", err)
	}

	truncated := compressed.Bytes()[:compressed.Len()/2]
	result := decodeHTTPContent("br", truncated)
	if result.Complete {
		t.Fatalf("expected incomplete decode for truncated brotli")
	}
	if result.Err == nil {
		t.Fatalf("expected error for truncated brotli")
	}
}

func TestDecodeHTTPContent_UnsupportedEncoding_PartialPayload(t *testing.T) {
	body := []byte("some-data")
	result := decodeHTTPContent("lz77", body)
	if result.Complete {
		t.Fatalf("expected incomplete for unsupported encoding")
	}
	if result.Err == nil {
		t.Fatalf("expected error for unsupported encoding")
	}
	// 不支持的编码：返回原始输入，调用方标记 partial_payload
	if !bytes.Equal(result.Body, body) {
		t.Fatalf("expected original body for unsupported encoding, got %q", result.Body)
	}
}

func TestDecodeHTTPContent_CaseInsensitive(t *testing.T) {
	original := []byte("test-payload")
	var compressed bytes.Buffer
	gw := gzip.NewWriter(&compressed)
	if _, err := gw.Write(original); err != nil {
		t.Fatalf("gzip compress: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	// 大写编码名应也能解码
	for _, enc := range []string{"GZIP", "Gzip"} {
		result := decodeHTTPContent(enc, compressed.Bytes())
		if !result.Complete {
			t.Fatalf("expected complete decode for encoding %q, got err=%v", enc, result.Err)
		}
		if !bytes.Equal(result.Body, original) {
			t.Fatalf("decode mismatch for %q: got %q", enc, result.Body)
		}
	}
}
