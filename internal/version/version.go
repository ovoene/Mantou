// Package version exposes the program version and compile-time build info.
//
// 设计要点（务必保持）：
//   - Version / OfficialURL / BuildTime 是带默认值的包级变量，直接编进源码，
//     因此任何构建方式（make / docker / go build / go run / IDE）都能得到
//     正确的版本号，不会出现运行时空值显示「未知」。
//   - 构建脚本（Makefile write-version / Dockerfile）会额外生成同包的
//     gen.go，通过 init() 覆盖这些变量，注入精确到秒的构建时间。
//   - 若未经构建脚本注入（直接 go build / go run），BuildTime 回退为
//     可执行文件的修改时间——二进制落盘的时刻即编译完成时刻，天然可靠。
package version

import (
	"os"
	"runtime"
)

// 默认值（发布版本号在此处维护；构建脚本生成的 gen.go 可在 init() 中覆盖）。
var (
	Version     = "Ver 0.0.0"
	OfficialURL = ""
	BuildTime   = ""
)

// Info bundles the version fields for the /meta/version API.
type Info struct {
	Version     string
	OfficialURL string
	BuildTime   string
	// OS / Arch 为编译后二进制的真实运行平台（runtime.GOOS / runtime.GOARCH），
	// 用于「关于」页展示当前架构，并供上传更新包时比对架构是否匹配。
	OS   string
	Arch string
}

// Load returns the build-time version info.
func Load() Info {
	return Info{
		Version:     Version,
		OfficialURL: OfficialURL,
		BuildTime:   resolveBuildTime(),
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
	}
}

// resolveBuildTime 优先返回构建脚本注入的编译时间；未注入时回退到
// 当前可执行文件的修改时间（即编译/链接完成、二进制落盘的时间）。
// 两者都不可用时返回空串，前端显示「未知」。
func resolveBuildTime() string {
	if BuildTime != "" {
		return BuildTime
	}
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	fi, err := os.Stat(exe)
	if err != nil {
		return ""
	}
	return fi.ModTime().Local().Format("2006-01-02 15:04:05")
}
