package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
)

// contentDecodeResult 包含内容解码结果。
type contentDecodeResult struct {
	Body    []byte // 解码后的正文（若解码失败则为部分解码结果或原始输入）
	Complete bool   // 是否完整解码
	Err      error  // 解码错误（非 nil 表示无法完整解码）
}

// decodeHTTPContent 对 HTTP 实体正文按 Content-Encoding 解码。
// 支持的编码：identity（直接返回）、gzip、deflate（zlib 包装或 raw）、br（brotli）。
// 无法解压时返回 (原始输入, false, err)，调用方据此标记 payload_analysis_mode=partial_payload。
func decodeHTTPContent(encoding string, body []byte) contentDecodeResult {
	encoding = strings.ToLower(strings.TrimSpace(encoding))
	switch encoding {
	case "", "identity":
		return contentDecodeResult{Body: body, Complete: true}
	case "gzip":
		return decodeGzipBody(body)
	case "deflate":
		return decodeDeflateBody(body)
	case "br":
		return decodeBrotliBody(body)
	default:
		return contentDecodeResult{Body: body, Complete: false, Err: fmt.Errorf("unsupported content-encoding: %s", encoding)}
	}
}

func decodeGzipBody(body []byte) contentDecodeResult {
	r, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return contentDecodeResult{Body: body, Complete: false, Err: err}
	}
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		// 返回已成功解码的前缀，标记 partial。
		if len(out) > 0 {
			return contentDecodeResult{Body: out, Complete: false, Err: err}
		}
		return contentDecodeResult{Body: body, Complete: false, Err: err}
	}
	return contentDecodeResult{Body: out, Complete: true}
}

func decodeDeflateBody(body []byte) contentDecodeResult {
	// HTTP "deflate" 在实践中可能是 zlib 包装，也可能是 raw deflate。先试 zlib，再回退 raw。
	if out, err := decodeZlibBody(body); err == nil {
		return out
	}
	return decodeRawDeflateBody(body)
}

func decodeZlibBody(body []byte) (contentDecodeResult, error) {
	r, err := zlib.NewReader(bytes.NewReader(body))
	if err != nil {
		return contentDecodeResult{Body: body, Complete: false, Err: err}, err
	}
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		return contentDecodeResult{Body: body, Complete: false, Err: err}, err
	}
	return contentDecodeResult{Body: out, Complete: true}, nil
}

func decodeRawDeflateBody(body []byte) contentDecodeResult {
	r := flate.NewReader(bytes.NewReader(body))
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		if len(out) > 0 {
			return contentDecodeResult{Body: out, Complete: false, Err: err}
		}
		return contentDecodeResult{Body: body, Complete: false, Err: err}
	}
	return contentDecodeResult{Body: out, Complete: true}
}

func decodeBrotliBody(body []byte) contentDecodeResult {
	r := brotli.NewReader(bytes.NewReader(body))
	out, err := io.ReadAll(r)
	if err != nil {
		if len(out) > 0 {
			return contentDecodeResult{Body: out, Complete: false, Err: err}
		}
		return contentDecodeResult{Body: body, Complete: false, Err: err}
	}
	if len(out) == 0 && len(body) > 0 {
		return contentDecodeResult{Body: body, Complete: false, Err: fmt.Errorf("brotli decode produced empty output")}
	}
	return contentDecodeResult{Body: out, Complete: true}
}
