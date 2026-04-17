// version.go
package main

var (
	// Version 服务版本号，通过 ldflags 注入
	Version = "dev"
	// BuildTime 构建时间
	BuildTime = "unknown"
	// GitCommit Git 提交哈希
	GitCommit = "unknown"
)
