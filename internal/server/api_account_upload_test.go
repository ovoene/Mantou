package server

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"mantou/internal/config"
	"mantou/internal/logx"
)

// 本文件盯的是背景图上传（3-C）：这条路由原先走 c.FormFile，
// 于是一张图要先整份收进内存、再拷一遍到磁盘，而这条路由没有任何串行化。
// 改成直接消费 multipart 流之后，要保证的是三件事：
// 内容一个字节都不能错、上限还得卡得住、不合格的输入不许在磁盘上留痕。

// newBackgroundTest 起一个带数据目录的最小服务端，只挂背景图上传这一条路由。
func newBackgroundTest(t *testing.T) (*gin.Engine, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	dir := t.TempDir()
	manager := config.NewManager(filepath.Join(dir, "config.json"))
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	// Log 必须给：httptest 的 ResponseRecorder 不支持设置读写截止时间，
	// extendRequestDeadlines 会走到 Debug 那一支。
	s := &Server{deps: Deps{Config: manager, DataDir: dir, Log: logx.New(logx.Options{})}}
	router := gin.New()
	router.POST("/settings/background", s.handleUploadBackground)
	return router, dir
}

// pngBytes 造一份长度为 n 的"PNG"：头 8 个字节是真魔数，其余填充。
// 只用来验证字节流有没有被完整搬到磁盘，不需要是一张能解码的图。
func pngBytes(n int) []byte {
	b := make([]byte, n)
	copy(b, []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A})
	for i := 8; i < n; i++ {
		b[i] = byte(i % 251)
	}
	return b
}

// uploadImage 组一份 multipart 请求体并发出去。extra 里的字段排在文件**之前**，
// 用来盯住 multipartFilePart 会跳过前面的非文件部分。
func uploadImage(t *testing.T, router http.Handler, contentType string, data []byte, extra map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range extra {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	h := make(map[string][]string)
	h["Content-Disposition"] = []string{`form-data; name="file"; filename="bg.png"`}
	h["Content-Type"] = []string{contentType}
	part, err := mw.CreatePart(h)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/settings/background", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// uploadedFiles 列出 data/uploads 里的文件名。目录不存在时返回 nil。
func uploadedFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dir, "uploads"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// assertUploadsDirAbsent 断言 data/uploads 这个目录压根没被建起来。
//
// 为什么盯目录而不是只盯"里面没有文件"：修复前那份代码是**先把内容整份写进磁盘、
// 再读回来判魔数、判完删掉**，所以"目录里没有文件"在修复前后同样成立，
// 拿它当断言等于什么都没钉住（这一条是被变异验证逼出来的）。
// 两版之间唯一留在磁盘上的差别就是这个目录存不存在，于是它成了"一个字节都没落盘"的凭据。
func assertUploadsDirAbsent(t *testing.T, dir string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(dir, "uploads")); !os.IsNotExist(err) {
		t.Fatalf("被拒的上传不该碰磁盘，但 uploads 目录已存在（里面有 %v）", uploadedFiles(t, dir))
	}
}

// 正常上传：文件要完整落盘，返回的 URL 要指向它。
//
// 这是流式改写最要紧的一条：头 16 个字节是先读出来做魔数判断的，
// 写文件时必须把它们再补回去，漏掉就是一张前 16 字节被砍掉的坏图——
// 而坏图在界面上是"背景不显示"，看不出是被截断了。
func TestUploadBackgroundStreamsWholeFile(t *testing.T) {
	router, dir := newBackgroundTest(t)
	data := pngBytes(64 << 10)

	w := uploadImage(t, router, "image/png", data, map[string]string{"note": "排在文件前面的字段"})
	if w.Code != http.StatusOK {
		t.Fatalf("正常上传应成功，实际 %d：%s", w.Code, w.Body.String())
	}
	var resp struct {
		Data struct {
			URL string `json:"url"`
		} `json:"data"`
		URL string `json:"url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	url := resp.URL
	if url == "" {
		url = resp.Data.URL
	}
	if !strings.HasPrefix(url, "/uploads/bg-") || !strings.HasSuffix(url, ".png") {
		t.Fatalf("返回的 URL 不对：%q（响应：%s）", url, w.Body.String())
	}

	names := uploadedFiles(t, dir)
	if len(names) != 1 {
		t.Fatalf("应只落一个文件，实际 %v", names)
	}
	if got := "/uploads/" + names[0]; got != url {
		t.Fatalf("返回的 URL 与落盘文件不一致：%q vs %q", url, got)
	}
	onDisk, err := os.ReadFile(filepath.Join(dir, "uploads", names[0]))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(onDisk, data) {
		t.Fatalf("落盘内容与上传内容不一致：磁盘 %d 字节、上传 %d 字节", len(onDisk), len(data))
	}
}

// 伪装成图片的上传：Content-Type 写着 image/png，内容不是。
//
// 修复前这份内容会被**完整写进 data/uploads**，然后靠 isRealImageFile 读回来判、
// 再 os.Remove 删掉。断言 uploads 目录压根没建起来正是为了钉住这个次序：
// 不合格的内容一个字节都不该落盘。
func TestUploadBackgroundRejectsFakeImageWithoutTouchingDisk(t *testing.T) {
	router, dir := newBackgroundTest(t)
	body := []byte("<html><script>alert(1)</script></html>")

	w := uploadImage(t, router, "image/png", body, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("伪装的图片应被拒，实际 %d：%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "并非有效的图片") {
		t.Fatalf("报错应说明内容不是图片：%s", w.Body.String())
	}
	assertUploadsDirAbsent(t, dir)
}

// 比头部缓冲还短的合法图片：一张 12 字节的 GIF。
//
// 魔数判断要读 16 个字节，而这份内容只有 12 个——io.ReadFull 会返回 ErrUnexpectedEOF。
// 那不是错误，是"源就这么长"，必须容忍。不容忍的后果是极小的合法图片一律传不上去，
// 而报的还是"读取上传文件失败"，跟体积一点关系都看不出来。
func TestUploadBackgroundAcceptsImageShorterThanHead(t *testing.T) {
	router, dir := newBackgroundTest(t)
	// isRealImage 要求至少 12 个字节，GIF 魔数占前 4 个。
	data := []byte("GIF89a\x01\x00\x01\x00\x00\x00")
	if len(data) >= imageHeadBytes {
		t.Fatalf("这条用例的前提是内容比头部缓冲短：%d vs %d", len(data), imageHeadBytes)
	}

	w := uploadImage(t, router, "image/gif", data, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("小图也应能上传，实际 %d：%s", w.Code, w.Body.String())
	}
	names := uploadedFiles(t, dir)
	if len(names) != 1 {
		t.Fatalf("应只落一个文件，实际 %v", names)
	}
	onDisk, err := os.ReadFile(filepath.Join(dir, "uploads", names[0]))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(onDisk, data) {
		t.Fatalf("落盘内容不对：%q vs %q", onDisk, data)
	}
}

// 类型不在白名单里：连正文都不该读，更不该落盘。
func TestUploadBackgroundRejectsUnsupportedType(t *testing.T) {
	router, dir := newBackgroundTest(t)

	w := uploadImage(t, router, "image/svg+xml", pngBytes(1024), nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("不支持的类型应被拒，实际 %d：%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "不支持的图片类型") {
		t.Fatalf("报错不对：%s", w.Body.String())
	}
	assertUploadsDirAbsent(t, dir)
}

// 表单里没有名叫 file 的部分。
func TestUploadBackgroundRejectsMissingFilePart(t *testing.T) {
	router, dir := newBackgroundTest(t)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.WriteField("note", "只有字段没有文件"); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/settings/background", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("缺少文件应被拒，实际 %d：%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "缺少上传文件") {
		t.Fatalf("报错不对：%s", w.Body.String())
	}
	assertUploadsDirAbsent(t, dir)
}

// 超过上限：走一遍真实路由，确认处理器传下去的确实是 maxBackgroundImageBytes，
// 且报的是那句"图片不能超过 10MB"、磁盘上不留半个文件。
//
// 只测超一个字节这一种情形（边界与清理由下面的 writeImagePart 用例用几十字节测准），
// 这里付一次 10 MB 的代价只为了验证"接线接对了"。
func TestUploadBackgroundEnforcesConfiguredLimit(t *testing.T) {
	router, dir := newBackgroundTest(t)

	w := uploadImage(t, router, "image/png", pngBytes(maxBackgroundImageBytes+1), nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("超限应被拒，实际 %d：%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "不能超过 10MB") {
		t.Fatalf("报错应是体积超限：%s", w.Body.String())
	}
	if names := uploadedFiles(t, dir); len(names) != 0 {
		t.Fatalf("超限的上传不该留下半个文件，实际 %v", names)
	}
}

// writeImagePart 的边界：正好等于上限要过，超一个字节要拒。
//
// 用几十字节的上限把这两个点测准。差一错在这里的后果是"9.99 MB 的图传不上去"
// 或"10.01 MB 的图能传上去"——两种都不会有人报 bug，只会悄悄跑偏。
func TestWriteImagePartLimitBoundary(t *testing.T) {
	cases := []struct {
		name    string
		total   int
		limit   int64
		wantErr bool
	}{
		{name: "远小于上限", total: 20, limit: 64, wantErr: false},
		{name: "正好等于上限", total: 64, limit: 64, wantErr: false},
		{name: "超一个字节", total: 65, limit: 64, wantErr: true},
		{name: "远超上限", total: 4096, limit: 64, wantErr: true},
		// 头部本身就比上限长：整份内容都在 head 里，CopyN 一个字节都拷不到，
		// 判断只能靠 len(head) 那一项——去掉它这一条就会漏过去。
		{name: "只有头部且超限", total: imageHeadBytes, limit: 8, wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data := pngBytes(c.total)
			head := data
			if len(head) > imageHeadBytes {
				head = head[:imageHeadBytes]
			}
			dst := filepath.Join(t.TempDir(), "out.png")
			err := writeImagePart(dst, head, bytes.NewReader(data[len(head):]), c.limit)

			if c.wantErr {
				if err == nil {
					t.Fatal("应报超限")
				}
				if !strings.Contains(err.Error(), "超过上限") {
					t.Fatalf("应是超限错误，实际 %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("不该报错：%v", err)
			}
			onDisk, readErr := os.ReadFile(dst)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if !bytes.Equal(onDisk, data) {
				t.Fatalf("落盘内容不对：%d 字节 vs %d 字节", len(onDisk), len(data))
			}
		})
	}
}

// 源在中途读坏：目标文件不能留在那里当孤儿。
// 清理由调用方（handleUploadBackground）做，这里验的是"写入函数把错误如实报上去"，
// 那是清理能被触发的前提。
func TestWriteImagePartReportsSourceError(t *testing.T) {
	head := pngBytes(imageHeadBytes)
	body := io.MultiReader(bytes.NewReader([]byte("一段正常内容")), errReader{})
	dst := filepath.Join(t.TempDir(), "out.png")

	err := writeImagePart(dst, head, body, 1<<20)
	if err == nil {
		t.Fatal("源读坏了应报错")
	}
	if strings.Contains(err.Error(), "超过上限") {
		t.Fatalf("不该被误判成超限：%v", err)
	}
	// 半个文件此刻确实还在——它由调用方删。这里只确认错误没被吞掉。
	if _, statErr := os.Stat(dst); statErr != nil {
		t.Fatalf("半个文件应当存在（由调用方清理）：%v", statErr)
	}
}

// errReader 读一次就报错，用来模拟客户端中途断开。
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
