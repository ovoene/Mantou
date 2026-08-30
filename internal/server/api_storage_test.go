package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"mantou/internal/config"
	"mantou/internal/logx"
)

// 这一对接口删的是真文件，判断依据全在「有没有人引用」上。所以要盯两头：
// 该列的一个不能漏（漏了这个按钮就没用），不该动的一个不能碰——尤其是
// config.json 与 master.key，删掉其中任何一个都是不可逆的。

func newStorageTest(t *testing.T) (*Server, *gin.Engine, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	dir := t.TempDir()
	manager := config.NewManager(filepath.Join(dir, "config.json"))
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	s := &Server{deps: Deps{Config: manager, DataDir: dir, Log: logx.New(logx.Options{})}}
	router := gin.New()
	router.GET("/settings/storage", s.handleGetStorage)
	router.POST("/settings/storage/cleanup", s.handleCleanupStorage)
	return s, router, dir
}

// writeUnder 在数据目录下写一个文件，需要时建好父目录。
func writeUnder(t *testing.T, dir, rel string, size int) string {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("x", size)), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// backdate 把修改时间往前拨，用来跨过 storageFreshWindow。
// 不注入时钟：这样走的是线上那条真代码。
func backdate(t *testing.T, path string) {
	t.Helper()
	old := time.Now().Add(-2 * storageFreshWindow)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
}

// listStorage 调 GET 接口，返回「路径 → 条目」。
func listStorage(t *testing.T, router http.Handler) map[string]storageItem {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/settings/storage", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /settings/storage 返回 %d：%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			Items     []storageItem `json:"items"`
			Count     int           `json:"count"`
			TotalSize int64         `json:"totalSize"`
			Truncated bool          `json:"truncated"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Data.Count != len(resp.Data.Items) {
		t.Fatalf("count=%d 与实际 %d 条不一致", resp.Data.Count, len(resp.Data.Items))
	}
	out := make(map[string]storageItem, len(resp.Data.Items))
	for _, it := range resp.Data.Items {
		if _, dup := out[it.Path]; dup {
			t.Fatalf("同一路径列了两次：%s", it.Path)
		}
		out[it.Path] = it
	}
	return out
}

type cleanupResult struct {
	OK      bool     `json:"ok"`
	Removed int      `json:"removed"`
	Skipped int      `json:"skipped"`
	Freed   int64    `json:"freed"`
	Failed  []string `json:"failed"`
}

func cleanupStorage(t *testing.T, router http.Handler, paths ...string) cleanupResult {
	t.Helper()
	body, err := json.Marshal(map[string]any{"paths": paths})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/settings/storage/cleanup", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST cleanup 返回 %d：%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data cleanupResult `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp.Data
}

// ---------- 扫描 ----------

// 正在用的背景图不能出现在列表里：它一旦被删，界面上就是一片空白背景，
// 而用户点「清理」时以为自己删的是垃圾。
func TestScanStorageSkipsReferencedBackground(t *testing.T) {
	s, router, dir := newStorageTest(t)
	used := writeUnder(t, dir, "uploads/bg-inuse.png", 100)
	orphan := writeUnder(t, dir, "uploads/bg-old.png", 200)
	backdate(t, used)
	backdate(t, orphan)
	if err := s.deps.Config.Update(func(c *config.Config) {
		c.Settings.Appearance.Background.Type = "image"
		c.Settings.Appearance.Background.Value = "/uploads/bg-inuse.png"
	}); err != nil {
		t.Fatal(err)
	}

	items := listStorage(t, router)
	if _, listed := items["uploads/bg-inuse.png"]; listed {
		t.Fatal("正在用的背景图被列成了可清理——照这个列表删下去，界面背景会没了")
	}
	it, listed := items["uploads/bg-old.png"]
	if !listed {
		t.Fatalf("换掉的旧背景图没被列出来：%v", items)
	}
	if it.Kind != "upload" || it.Size != 200 {
		t.Fatalf("条目内容不对：%+v", it)
	}
	if it.Note != "" {
		t.Fatalf("时间拨回去之后不该再标「刚上传」，实际 %q", it.Note)
	}
}

// 背景图类型不是 image 时，那个值指的是颜色或渐变，uploads 里的图一律算孤儿。
func TestScanStorageColorBackgroundLeavesNoReference(t *testing.T) {
	s, router, dir := newStorageTest(t)
	backdate(t, writeUnder(t, dir, "uploads/bg-old.png", 50))
	if err := s.deps.Config.Update(func(c *config.Config) {
		c.Settings.Appearance.Background.Type = "color"
		c.Settings.Appearance.Background.Value = "#ffffff"
	}); err != nil {
		t.Fatal(err)
	}
	if _, listed := listStorage(t, router)["uploads/bg-old.png"]; !listed {
		t.Fatal("背景改成纯色之后，原先那张图就没人引用了，应当列出来")
	}
}

// 刚上传、还没点保存外观的那张图这时也「没人引用」。照样列、照样能删，但要标出来：
// 不标的话，用户上传完顺手来清一下，删掉的正是自己半分钟前刚选的图。
func TestScanStorageMarksFreshUpload(t *testing.T) {
	_, router, dir := newStorageTest(t)
	writeUnder(t, dir, "uploads/bg-just-now.png", 30)
	it, listed := listStorage(t, router)["uploads/bg-just-now.png"]
	if !listed {
		t.Fatal("刚上传的图也要列出来：藏起来就等于用户看不到、也删不掉")
	}
	if it.Note != "fresh" {
		t.Fatalf("刚上传的图要标出来，实际 note=%q", it.Note)
	}
}

// 证书目录里只有 <id>.crt 与 <id>.key 是有主的，别的都是残留：
// 删掉证书后剩下的那两个文件、写入中断留下的 <id>-*.crt、替换时的 *.bak。
func TestScanStorageListsOrphanCertFiles(t *testing.T) {
	s, router, dir := newStorageTest(t)
	keep := []string{"certs/live-1.crt", "certs/live-1.key"}
	orphans := []string{
		"certs/deleted-2.crt",      // 证书条目已经删了，文件还在
		"certs/deleted-2.key",      // 私钥更要清掉
		"certs/live-1-123456.crt",  // CreateTemp 留下的暂存文件
		"certs/live-1.crt-987.bak", // 替换时的备份
	}
	for _, rel := range append(append([]string{}, keep...), orphans...) {
		backdate(t, writeUnder(t, dir, rel, 10))
	}
	// ID 里带短横线：合法文件名按整个名字比对，不能靠"去掉扩展名后前缀匹配"。
	if err := s.deps.Config.Update(func(c *config.Config) {
		c.Certs = []config.Certificate{{ID: "live-1", Name: "站点证书"}}
	}); err != nil {
		t.Fatal(err)
	}

	items := listStorage(t, router)
	for _, rel := range keep {
		if _, listed := items[rel]; listed {
			t.Fatalf("%s 是在用证书的文件，不能列成可清理——删了它面板的 HTTPS 就起不来", rel)
		}
	}
	for _, rel := range orphans {
		it, listed := items[rel]
		if !listed {
			t.Fatalf("%s 没被列出来：%v", rel, items)
		}
		if it.Kind != "cert" {
			t.Fatalf("%s 的分类是 %q，期望 cert", rel, it.Kind)
		}
	}
}

// 导入中断留下的暂存目录要列出来，大小按里面所有文件之和算——
// 报 0 字节的话，用户看不出这一项才是最占地方的那个。
func TestScanStorageListsRestoreLeftovers(t *testing.T) {
	_, router, dir := newStorageTest(t)
	writeUnder(t, dir, "uploads.restore-old-17000/a.png", 400)
	writeUnder(t, dir, "uploads.restore-old-17000/sub/b.png", 600)
	backdate(t, filepath.Join(dir, "uploads.restore-old-17000"))
	for _, rel := range []string{"certs.restore-old-17000", ".certs-restore-abc", ".uploads-restore-xyz"} {
		if err := os.MkdirAll(filepath.Join(dir, rel), 0o755); err != nil {
			t.Fatal(err)
		}
		backdate(t, filepath.Join(dir, rel))
	}
	backdate(t, writeUnder(t, dir, "config.json.tmp", 70))

	items := listStorage(t, router)
	for _, rel := range []string{"certs.restore-old-17000", ".certs-restore-abc", ".uploads-restore-xyz"} {
		it, listed := items[rel]
		if !listed {
			t.Fatalf("%s 没被列出来：%v", rel, items)
		}
		if it.Kind != "restore" || !it.IsDir {
			t.Fatalf("%s 条目不对：%+v", rel, it)
		}
	}
	if it := items["uploads.restore-old-17000"]; it.Size != 1000 {
		t.Fatalf("暂存目录大小报 %d 字节，期望目录内 1000 字节之和", it.Size)
	}
	if it := items["config.json.tmp"]; it.Kind != "temp" || it.Size != 70 {
		t.Fatalf("临时文件条目不对：%+v", it)
	}
}

// 太新的暂存目录与 .tmp 一律不列：它们在一次正在进行的导入、或一次正在写的配置保存
// 中途也会存在，列出来就有可能被顺手删掉，把人家写一半的东西毁了。
func TestScanStorageSkipsFreshLeftovers(t *testing.T) {
	_, router, dir := newStorageTest(t)
	if err := os.MkdirAll(filepath.Join(dir, ".uploads-restore-inflight"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeUnder(t, dir, "config.json.tmp", 40)

	items := listStorage(t, router)
	for _, rel := range []string{".uploads-restore-inflight", "config.json.tmp"} {
		if _, listed := items[rel]; listed {
			t.Fatalf("%s 刚建出来就被列成可清理：可能是一次正在进行的导入或保存", rel)
		}
	}
}

// 数据目录里正常该有的东西一个都不许出现在列表里。
func TestScanStorageIgnoresRegularDataFiles(t *testing.T) {
	_, router, dir := newStorageTest(t)
	for _, rel := range []string{"config.json", "state.json", "master.key", "logs/mantou.log"} {
		backdate(t, writeUnder(t, dir, rel, 10))
	}
	if items := listStorage(t, router); len(items) != 0 {
		t.Fatalf("正常文件被列成了可清理：%v", items)
	}
}

// 条数上限：超出的部分不列，但要说清楚"还有"，不能静悄悄地少给几条。
func TestScanStorageTruncates(t *testing.T) {
	_, router, dir := newStorageTest(t)
	for i := 0; i < maxStorageItems+5; i++ {
		backdate(t, writeUnder(t, dir, "uploads/bg-"+strconv.Itoa(i)+".png", 1))
	}
	req := httptest.NewRequest(http.MethodGet, "/settings/storage", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	var resp struct {
		Data struct {
			Items     []storageItem `json:"items"`
			Truncated bool          `json:"truncated"`
			Limit     int           `json:"limit"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Data.Items) != maxStorageItems {
		t.Fatalf("列了 %d 条，期望封顶在 %d", len(resp.Data.Items), maxStorageItems)
	}
	if !resp.Data.Truncated || resp.Data.Limit != maxStorageItems {
		t.Fatalf("超出上限时要标出来：truncated=%v limit=%d", resp.Data.Truncated, resp.Data.Limit)
	}
}

// ---------- 清理 ----------

func TestCleanupStorageRemovesListedItems(t *testing.T) {
	_, router, dir := newStorageTest(t)
	file := writeUnder(t, dir, "uploads/bg-old.png", 200)
	backdate(t, file)
	writeUnder(t, dir, "uploads.restore-old-1/a.png", 300)
	stage := filepath.Join(dir, "uploads.restore-old-1")
	backdate(t, stage)

	r := cleanupStorage(t, router, "uploads/bg-old.png", "uploads.restore-old-1")
	if !r.OK || r.Removed != 2 || r.Skipped != 0 {
		t.Fatalf("清理结果不对：%+v", r)
	}
	if r.Freed != 500 {
		t.Fatalf("释放字节数报 %d，期望 500", r.Freed)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("文件还在：%v", err)
	}
	// 目录要整个删掉，只删空目录的话里面那 300 字节还占着。
	if _, err := os.Stat(stage); !os.IsNotExist(err) {
		t.Fatalf("暂存目录还在：%v", err)
	}
	if items := listStorage(t, router); len(items) != 0 {
		t.Fatalf("清理之后列表应当空了：%v", items)
	}
}

// 请求里带来的路径只用于比对，不拿去拼路径。所以不管塞什么进来，
// 都只能删到「服务端这次也扫得出来」的那些；其余一律算 skipped。
//
// 这是本文件里最要紧的一条：config.json 与 master.key 就在同一个目录下，
// 一旦能被这条路径删掉，用户的凭证与全部配置就没了，而且无从恢复。
func TestCleanupStorageRejectsPathsOutsideScan(t *testing.T) {
	_, router, dir := newStorageTest(t)
	writeUnder(t, dir, "config.json", 10)
	writeUnder(t, dir, "master.key", 10)
	outside := filepath.Join(filepath.Dir(dir), "outside-"+filepath.Base(dir)+".txt")
	if err := os.WriteFile(outside, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(outside)

	crafted := []string{
		"config.json",
		"master.key",
		"../" + filepath.Base(outside),
		"uploads/../../" + filepath.Base(outside),
		filepath.ToSlash(outside),
		"logs",
		"..",
		"",
	}
	r := cleanupStorage(t, router, crafted...)
	if r.Removed != 0 {
		t.Fatalf("删掉了 %d 项，一项都不该删：%+v", r.Removed, r)
	}
	if r.Skipped != len(crafted) {
		t.Fatalf("skipped=%d，期望把 %d 条全部算进去", r.Skipped, len(crafted))
	}
	for _, p := range []string{filepath.Join(dir, "config.json"), filepath.Join(dir, "master.key"), outside} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s 被删掉了：%v", p, err)
		}
	}
}

// 列表是几分钟前拉的，中间那张图可能已经被设成背景了。这时不能照着旧列表删。
func TestCleanupStorageSkipsNowReferencedFile(t *testing.T) {
	s, router, dir := newStorageTest(t)
	path := writeUnder(t, dir, "uploads/bg.png", 100)
	backdate(t, path)
	if _, listed := listStorage(t, router)["uploads/bg.png"]; !listed {
		t.Fatal("前置条件不成立：这时它还没人引用，应当在列表里")
	}
	// 用户在另一个标签页把它设成了背景。
	if err := s.deps.Config.Update(func(c *config.Config) {
		c.Settings.Appearance.Background.Type = "image"
		c.Settings.Appearance.Background.Value = "/uploads/bg.png"
	}); err != nil {
		t.Fatal(err)
	}

	r := cleanupStorage(t, router, "uploads/bg.png")
	if r.Removed != 0 || r.Skipped != 1 {
		t.Fatalf("已经被引用上的文件不该删：%+v", r)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("已在使用的背景图被删了：%v", err)
	}
}

// 同一条路径重复送上来只处理一次，否则 removed 会虚报。
func TestCleanupStorageIgnoresDuplicatePaths(t *testing.T) {
	_, router, dir := newStorageTest(t)
	backdate(t, writeUnder(t, dir, "uploads/bg.png", 100))
	r := cleanupStorage(t, router, "uploads/bg.png", "uploads/bg.png")
	if r.Removed != 1 || r.Skipped != 1 || r.Freed != 100 {
		t.Fatalf("重复路径应当只算一次：%+v", r)
	}
}

// 空列表与超量列表都按参数错误挡在门外。
func TestCleanupStorageRejectsBadRequests(t *testing.T) {
	_, router, _ := newStorageTest(t)
	for _, body := range []string{`{"paths":[]}`, `{}`, `not json`} {
		req := httptest.NewRequest(http.MethodPost, "/settings/storage/cleanup", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body %q 返回 %d，期望 400", body, rec.Code)
		}
	}
	many := make([]string, maxStorageItems+1)
	for i := range many {
		many[i] = "uploads/x" + strconv.Itoa(i)
	}
	body, err := json.Marshal(map[string]any{"paths": many})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/settings/storage/cleanup", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("超量请求返回 %d，期望 400", rec.Code)
	}
}

// 没配数据目录时两个接口都明确说不可用，而不是返回一个空列表——
// 空列表会被读成「很干净」，而实际情况是根本没查。
func TestStorageWithoutDataDir(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &Server{deps: Deps{Config: config.NewManager(filepath.Join(t.TempDir(), "config.json")), Log: logx.New(logx.Options{})}}
	router := gin.New()
	router.GET("/settings/storage", s.handleGetStorage)
	router.POST("/settings/storage/cleanup", s.handleCleanupStorage)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/settings/storage", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET 返回 %d，期望 503", rec.Code)
	}
	req := httptest.NewRequest(http.MethodPost, "/settings/storage/cleanup", strings.NewReader(`{"paths":["uploads/x.png"]}`))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("POST 返回 %d，期望 503", rec.Code)
	}
}
