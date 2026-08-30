package server

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"io/fs"
	"strings"

	"github.com/gin-gonic/gin"
)

// 本文件只管一件事：让浏览器有依据复用已经下载过的前端资源。
//
// 前端是 //go:embed 打进二进制的，由 http.FileServer(http.FS(...)) 提供。这条路径上
// 三个缓存校验符一个都不会出现：Cache-Control 与 ETag 没人设，Last-Modified 则是
// 嵌入 FS 的性质决定的——它的 ModTime() 返回零值，而 http.ServeContent 对零值直接跳过。
// 结果不是"304 命中率低"，是这条路径根本不存在：每次打开面板、每次刷新、每个新标签页，
// 首屏那 1.6 MiB 都要重新传一遍，而且每次都要重新 gzip 一遍。

const (
	// hashedAssetsDir Vite 把带内容哈希的产物全部放在这个目录下（build.assetsDir 的默认值）。
	hashedAssetsDir = "assets/"

	// immutableCacheControl 只给内容哈希命名的文件用。文件名里带着内容指纹，
	// 内容一变文件名就变，旧副本永远不会被误用——这正是 immutable 的适用前提。
	// 项目早就付出了内容哈希的代价（构建时算哈希、入口页重写引用），这是它唯一那份回报。
	immutableCacheControl = "public, max-age=31536000, immutable"

	// revalidateCacheControl 给不带哈希的文件用（favicon、图标、robots.txt 之类）。
	// 允许存，但每次用之前必须回来问一句；配合 ETag，问的结果通常是一个空的 304，
	// 只有响应头没有响应体。给这类文件一年强缓存会把换过的图标钉住一年。
	revalidateCacheControl = "public, max-age=0, must-revalidate"

	// assetETagBytes ETag 取哈希的前多少字节。128 位足够判定"内容是否相同"，
	// 而 ETag 是要跟着每个请求来回跑的，短一半就少一半的头部开销。
	assetETagBytes = 16
)

// buildAssetETags 为嵌入 FS 里的每个文件算一个强校验符，键是 FS 内的相对路径。
//
// 只留哈希串，不留文件内容——内容本来就在二进制里，再存一份纯属白占内存。
// 一次性成本是把全部资源过一遍 SHA-256（实测 36 个文件、约 2.3 MB），只发生在启动时。
//
// 单个文件读不出来就不给它校验符：那一个文件退回"每次重传"，不影响其余文件，也不影响可用性。
func buildAssetETags(fsys fs.FS) map[string]string {
	if fsys == nil {
		return nil
	}
	tags := make(map[string]string, 64)
	h := sha256.New()
	_ = fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		f, ferr := fsys.Open(path)
		if ferr != nil {
			return nil
		}
		defer f.Close()
		h.Reset()
		if _, cerr := io.Copy(h, f); cerr != nil {
			return nil
		}
		sum := h.Sum(nil)[:assetETagBytes]
		tags[path] = `"` + base64.RawURLEncoding.EncodeToString(sum) + `"`
		return nil
	})
	return tags
}

// setAssetCacheHeaders 给静态资源响应装上缓存头。name 是嵌入 FS 内的相对路径。
//
// 必须在把请求交给文件服务器**之前**装：http.ServeContent 会读走这里设的 ETag 去比对
// If-None-Match，命中就直接回 304，连文件都不用打开。
//
// 入口页不走这里——那份 HTML 会注入运行期基址，必须 no-store（见 serveIndex）。
func (s *Server) setAssetCacheHeaders(c *gin.Context, name string) {
	if strings.HasPrefix(name, hashedAssetsDir) {
		c.Header("Cache-Control", immutableCacheControl)
	} else {
		// 万一将来构建产物换了目录，命中的也是这一支：退化成"每次校验"，
		// 而不会退化成"拿着过期的东西当新的用"。方向是安全的那一边。
		c.Header("Cache-Control", revalidateCacheControl)
	}
	if tag := s.assetETags[name]; tag != "" {
		c.Header("ETag", tag)
	}
	// 同一个资源会按 Accept-Encoding 分成压缩与未压缩两个版本，共享缓存必须按此分键。
	// 压缩中间件自己也会加这一条，但它在 304 那条路上不会执行（非 200 不压），
	// 而 304 按规范同样要带上 Vary，所以在这里补齐。重复添加已由那边去重。
	c.Header("Vary", "Accept-Encoding")
}
