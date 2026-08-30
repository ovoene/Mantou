package server

import (
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"mantou/internal/config"
)

// 数据目录里会攒下一些没人再引用的文件：换过的背景图、删掉证书后剩下的 .crt/.key、
// 导入配置时中途断电留下的暂存目录。它们不影响运行，但会一直占着盘，而用户从界面上
// 看不到、也没有别的入口能删。这一对接口就是把它们列出来、再按列表删掉。
//
// 删除一律走「服务端重新扫一遍、只删交集」：请求里带来的路径只用于比对，绝不拿去拼路径。

const (
	// 一次最多列这么多条。真实场景通常是个位数，这个数只为挡住"目录被塞满"时把整页拖死。
	maxStorageItems = 500

	// 暂存目录与 .tmp 文件在正常写入过程中也会短暂存在，太新的一律不列：
	// 免得赶上一次正在进行的导入或配置保存，把人家的中间文件删掉。
	storageFreshWindow = 10 * time.Minute
)

// storageItem 一条可清理的条目。
type storageItem struct {
	Path    string `json:"path"` // 相对数据目录、以 / 分隔
	Kind    string `json:"kind"` // upload / cert / restore / temp，前端据此显示分类
	Size    int64  `json:"size"` // 目录是其中所有文件之和
	ModTime int64  `json:"modTime"`
	IsDir   bool   `json:"isDir,omitempty"`
	Note    string `json:"note,omitempty"` // 提示语的键名，交给前端翻译

	abs string // 删除时用这个（不出网，小写字段 encoding/json 不会导出）
}

// scanStorage 扫出数据目录里没人引用的文件。第二个返回值表示"还有更多没列出来"。
func (s *Server) scanStorage(cfg *config.Config) ([]storageItem, bool) {
	dataDir := s.deps.DataDir
	if dataDir == "" {
		return nil, false
	}
	items := make([]storageItem, 0, 8)
	truncated := false
	add := func(it storageItem) {
		if len(items) >= maxStorageItems {
			truncated = true
			return
		}
		items = append(items, it)
	}
	// 判断"太新"的分界线。测试里靠 os.Chtimes 把文件时间往前拨来跨过它，不用注入时钟。
	fresh := time.Now().Add(-storageFreshWindow)

	// 一、uploads 里没被引用的文件。目前这个目录只放背景图。
	uploadRoot := filepath.Join(dataDir, "uploads")
	refs := referencedUploadPaths(cfg)
	_ = filepath.WalkDir(uploadRoot, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil // 读不动的子目录跳过就好：这里是"能清点什么"，不是校验目录完整性
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		rel, relErr := filepath.Rel(uploadRoot, path)
		if relErr != nil {
			return nil
		}
		relSlash := filepath.ToSlash(rel)
		if refs[relSlash] {
			return nil
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			return nil
		}
		it := storageItem{
			Path:    "uploads/" + relSlash,
			Kind:    "upload",
			Size:    info.Size(),
			ModTime: info.ModTime().UnixMilli(),
			abs:     path,
		}
		// 刚上传、还没点保存外观的那张图这时也是"没人引用"。照样列出来、照样能删，
		// 只是标一句，免得用户把自己半分钟前刚选的图当成垃圾清掉。
		if info.ModTime().After(fresh) {
			it.Note = "fresh"
		}
		add(it)
		return nil
	})

	// 二、certs 里对不上号的文件：删掉证书之后剩下的 <id>.crt/.key、
	// 写入过程中断留下的 <id>-*.crt 与 *-*.bak。合法文件名只有这两个，逐个全名比对。
	certRoot := filepath.Join(dataDir, "certs")
	valid := make(map[string]bool, len(cfg.Certs)*2)
	for i := range cfg.Certs {
		id := cfg.Certs[i].ID
		if id == "" {
			continue
		}
		valid[id+".crt"] = true
		valid[id+".key"] = true
	}
	if entries, err := os.ReadDir(certRoot); err == nil {
		for _, entry := range entries {
			if entry.IsDir() || !entry.Type().IsRegular() || valid[entry.Name()] {
				continue
			}
			info, infoErr := entry.Info()
			if infoErr != nil {
				continue
			}
			add(storageItem{
				Path:    "certs/" + entry.Name(),
				Kind:    "cert",
				Size:    info.Size(),
				ModTime: info.ModTime().UnixMilli(),
				abs:     filepath.Join(certRoot, entry.Name()),
			})
		}
	}

	// 三、数据目录顶层的暂存残留。正常情况下导入结束就删掉了，只有中途断电才会留下。
	if entries, err := os.ReadDir(dataDir); err == nil {
		for _, entry := range entries {
			name := entry.Name()
			kind := storageLeftoverKind(name, entry.IsDir())
			if kind == "" {
				continue
			}
			info, infoErr := entry.Info()
			if infoErr != nil {
				continue
			}
			if info.ModTime().After(fresh) {
				continue // 可能是正在进行的导入或配置保存，别碰
			}
			abs := filepath.Join(dataDir, name)
			size := info.Size()
			if entry.IsDir() {
				size = dirSize(abs)
			}
			add(storageItem{
				Path:    name,
				Kind:    kind,
				Size:    size,
				ModTime: info.ModTime().UnixMilli(),
				IsDir:   entry.IsDir(),
				abs:     abs,
			})
		}
	}

	// 大的排前面：要腾地方的人第一眼就看到该删哪个。同大小按路径定序，免得两次刷新顺序乱跳。
	sort.Slice(items, func(i, j int) bool {
		if items[i].Size != items[j].Size {
			return items[i].Size > items[j].Size
		}
		return items[i].Path < items[j].Path
	})
	return items, truncated
}

// storageLeftoverKind 判断数据目录顶层的某个条目是不是暂存残留，返回空表示不是。
// 这里的名字必须与 restoreBackupResources（导入暂存）和 writeFileAtomic（<文件名>.tmp）对齐。
func storageLeftoverKind(name string, isDir bool) string {
	if isDir {
		switch {
		case strings.HasPrefix(name, "certs.restore-old-"),
			strings.HasPrefix(name, "uploads.restore-old-"),
			strings.HasPrefix(name, ".certs-restore-"),
			strings.HasPrefix(name, ".uploads-restore-"):
			return "restore"
		}
		return ""
	}
	if strings.HasSuffix(name, ".tmp") && len(name) > len(".tmp") {
		return "temp"
	}
	return ""
}

// dirSize 目录里所有文件的字节数之和，读不动的部分按 0 计。
func dirSize(root string) int64 {
	var total int64
	_ = filepath.WalkDir(root, func(_ string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		if info, infoErr := entry.Info(); infoErr == nil {
			total += info.Size()
		}
		return nil
	})
	return total
}

// handleGetStorage 列出数据目录里没人引用的文件。
func (s *Server) handleGetStorage(c *gin.Context) {
	if s.deps.DataDir == "" {
		respondError(c, http.StatusServiceUnavailable, "未配置数据目录")
		return
	}
	items, truncated := s.scanStorage(s.deps.Config.Snapshot())
	var total int64
	for i := range items {
		total += items[i].Size
	}
	respondOK(c, gin.H{
		"items":     items,
		"count":     len(items),
		"totalSize": total,
		"truncated": truncated,
		"limit":     maxStorageItems,
	})
}

type storageCleanupReq struct {
	Paths []string `json:"paths"`
}

// handleCleanupStorage 删除请求里列出的那些条目。
//
// 服务端会重新扫一遍，只删「这次也扫得出来」的那些：请求里的路径仅用于比对，
// 真正传给 os.Remove 的是扫描时自己拼好的路径。这样即便请求里塞进一个
// ../../ 之类的东西，也只是对不上号、被算进 skipped，不可能删到数据目录外面去。
func (s *Server) handleCleanupStorage(c *gin.Context) {
	var req storageCleanupReq
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "请求参数无效")
		return
	}
	if s.deps.DataDir == "" {
		respondError(c, http.StatusServiceUnavailable, "未配置数据目录")
		return
	}
	if len(req.Paths) == 0 {
		respondError(c, http.StatusBadRequest, "没有要清理的文件")
		return
	}
	if len(req.Paths) > maxStorageItems {
		respondError(c, http.StatusBadRequest, "一次清理的文件过多")
		return
	}

	items, _ := s.scanStorage(s.deps.Config.Snapshot())
	current := make(map[string]storageItem, len(items))
	for _, it := range items {
		current[it.Path] = it
	}

	var removed, skipped int
	var freed int64
	var failed []string
	for _, p := range req.Paths {
		it, ok := current[p]
		if !ok {
			skipped++ // 列表是旧的：这条已经被删了、或者刚被引用上了
			continue
		}
		delete(current, p) // 同一条路径重复出现只处理一次
		var err error
		if it.IsDir {
			err = os.RemoveAll(it.abs)
		} else {
			err = os.Remove(it.abs)
		}
		if err != nil && !os.IsNotExist(err) {
			failed = append(failed, it.Path)
			s.deps.Log.Warn("清理未引用文件失败", "path", it.Path, "err", err.Error())
			continue
		}
		removed++
		freed += it.Size
	}
	if removed > 0 {
		s.deps.Log.Info("已清理未引用文件", "count", removed, "bytes", freed)
	}
	respondOK(c, gin.H{
		"ok":      len(failed) == 0,
		"removed": removed,
		"skipped": skipped,
		"freed":   freed,
		"failed":  failed,
	})
}
