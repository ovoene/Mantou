package web

import (
	"embed"
	"io/fs"
)

// dist 内嵌前端构建产物。构建流程会先执行 `npm run build` 生成 web/dist，
// 再由 Go 编译时通过 embed 打包进最终二进制。
//
// 说明：dist 目录下至少需要存在一个占位文件（如 .gitkeep 或 index.html），
// 否则 embed 会因找不到文件而报错。发布构建时该目录会被真实产物覆盖。
//
//go:embed all:dist
var dist embed.FS

// FS 返回以 dist 为根的前端文件系统，供 HTTP 静态服务使用。
func FS() (fs.FS, error) {
	return fs.Sub(dist, "dist")
}
