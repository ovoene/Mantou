package server

import (
	"strings"
	"testing"

	"mantou/internal/config"
)

// 本文件盯住子项 ID 的补发与去重（审计 L-04）。
//
// 这个 ID 是运行期一切按子项的账的键（连接数、访问日志、链接状态、探测排期、限流桶），
// 而它由客户端提供。撞了 ID 不会有任何报错，只是两个站点的账混成一份——
// 外加 app.MigrateWebBasicAuth 那里的一处：撞 ID 会让一个站点的 Basic 认证口令
// 哈希被写到另一个站点上。所以它必须在保存这一步就唯一。

// childrenWS 造一个只填了 ID 与子项 ID 的父项。
func childrenWS(id string, childIDs ...string) config.WebService {
	ws := config.WebService{ID: id, Name: "svc-" + id, Port: 8080}
	for _, cid := range childIDs {
		ws.Children = append(ws.Children, config.WebChild{ID: cid, Enabled: true, Type: "proxy"})
	}
	return ws
}

// childIDsOf 取子项 ID 列表。
func childIDsOf(ws config.WebService) []string {
	out := make([]string, 0, len(ws.Children))
	for _, ch := range ws.Children {
		out = append(out, ch.ID)
	}
	return out
}

// assertUniqueNonEmpty 全部非空且互不相同——这是本函数唯一的硬承诺。
func assertUniqueNonEmpty(t *testing.T, ids []string) {
	t.Helper()
	seen := make(map[string]bool, len(ids))
	for i, id := range ids {
		if id == "" {
			t.Fatalf("第 %d 个子项 ID 仍是空的：%q", i, ids)
		}
		if seen[id] {
			t.Fatalf("子项 ID %q 出现了两次：%q", id, ids)
		}
		seen[id] = true
	}
}

func TestNormalizeWebChildIDsFillsAndDedupes(t *testing.T) {
	// 别的父项已经占着 keep-a；本次保存的是 ws2。
	cfg := &config.Config{WebServices: []config.WebService{childrenWS("ws1", "keep-a")}}

	t.Run("空 ID 逐个补发", func(t *testing.T) {
		ws := childrenWS("ws2", "", "", "")
		normalizeWebChildIDs(cfg, &ws)
		assertUniqueNonEmpty(t, childIDsOf(ws))
	})

	t.Run("载荷内重复只留第一个", func(t *testing.T) {
		ws := childrenWS("ws2", "dup", "dup")
		normalizeWebChildIDs(cfg, &ws)
		ids := childIDsOf(ws)
		assertUniqueNonEmpty(t, ids)
		if ids[0] != "dup" {
			t.Errorf("先出现的那个应原样保留，实际 %q", ids[0])
		}
	})

	t.Run("撞上别的父项的子项 ID 要换掉", func(t *testing.T) {
		// 「把一个服务的 JSON 原样 POST 一遍当复制站点用」就是这个形状。
		ws := childrenWS("ws2", "keep-a")
		normalizeWebChildIDs(cfg, &ws)
		if got := childIDsOf(ws)[0]; got == "keep-a" {
			t.Error("这个 ID 已被 ws1 占着，应当补发一个新的")
		}
		assertUniqueNonEmpty(t, childIDsOf(ws))
	})

	t.Run("自己现有的子项 ID 原样保留", func(t *testing.T) {
		// 编辑保存是常态：ID 一变，这条子项的连接数/日志/限流桶就全部从零开始。
		ws := childrenWS("ws1", "keep-a")
		normalizeWebChildIDs(cfg, &ws)
		if got := childIDsOf(ws)[0]; got != "keep-a" {
			t.Errorf("同一父项自己的子项 ID 不该被换掉，实际 %q", got)
		}
	})

	t.Run("首尾空格裁掉", func(t *testing.T) {
		ws := childrenWS("ws2", "  spaced  ")
		normalizeWebChildIDs(cfg, &ws)
		if got := childIDsOf(ws)[0]; got != "spaced" {
			t.Errorf("ID = %q，应裁掉首尾空格", got)
		}
	})

	t.Run("拿不到快照时仍在载荷内去重", func(t *testing.T) {
		ws := childrenWS("ws2", "dup", "dup", "")
		normalizeWebChildIDs(nil, &ws)
		assertUniqueNonEmpty(t, childIDsOf(ws))
	})
}

// 补发出来的 ID 要和后端给父项发的那种一样：12 位十六进制（genID 是 6 字节）。
// 这一条不是格式洁癖——ID 会进 URL 路径（子项启停端点 /:cid）与日志字段。
func TestNormalizeWebChildIDsMintsHexIDs(t *testing.T) {
	ws := childrenWS("ws2", "")
	normalizeWebChildIDs(nil, &ws)
	got := childIDsOf(ws)[0]
	if len(got) != 12 || strings.TrimLeft(got, "0123456789abcdef") != "" {
		t.Fatalf("补发的 ID = %q，应为 12 位十六进制", got)
	}
}
