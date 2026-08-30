package server

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 本文件盯的是备份导入那侧的流式读取（3-C 的第二半）。
//
// 导入原先走 c.FormFile + c.PostForm：整个上传体先进内存（32 MB 缓冲）、超出的落一份
// 临时文件到 TMPDIR，处理器再 io.ReadAll 从头读一遍。改成手工遍历 multipart 之后，
// 有两件事成了这里自己的责任：字段得与顺序无关地收齐，字段长度也得自己卡住。

// importPart 描述请求体里的一个部分。file 为 true 表示当成文件部分写出去。
type importPart struct {
	name string
	body string
	file bool
}

// buildImportBody 按给定顺序组一份 multipart 请求。顺序是这批用例的关键变量，
// 所以刻意用切片而不是 map——map 的遍历顺序恰恰是这里最不想要的东西。
func buildImportBody(t *testing.T, parts []importPart) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, p := range parts {
		if p.file {
			w, err := mw.CreateFormFile(p.name, "Mantou-backup.json")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write([]byte(p.body)); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := mw.WriteField(p.name, p.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/settings/import", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}

// 字段排在文件**后面**也要收得到。
//
// 这是手工遍历的全部理由：前端就是先 append('file')、再 append 那三个字段的
// （web/src/views/Settings.vue）。现成的 multipartFilePart 只找 file、把它之前的
// 部分丢掉，用在这条路上会让 account / password / modules 三个字段全部读成空——
// 表现是"每次导入都说要提供账户名与密码"，而用户明明填了。
func TestReadImportUploadCollectsFieldsAfterFile(t *testing.T) {
	req := buildImportBody(t, []importPart{
		{name: "file", body: "备份内容", file: true},
		{name: "account", body: "admin"},
		{name: "password", body: "口令-P@ss"},
		{name: "modules", body: "cert,forward"},
	})

	up, err := readImportUpload(req, 1<<20)
	if err != nil {
		t.Fatalf("不该报错：%v", err)
	}
	if string(up.raw) != "备份内容" {
		t.Fatalf("文件内容不对：%q", up.raw)
	}
	if up.account != "admin" || up.password != "口令-P@ss" || up.modules != "cert,forward" {
		t.Fatalf("字段没收齐：account=%q password=%q modules=%q", up.account, up.password, up.modules)
	}
}

// 字段排在文件前面同样要收得到：不许把"前端目前的顺序"当成协议。
func TestReadImportUploadCollectsFieldsBeforeFile(t *testing.T) {
	req := buildImportBody(t, []importPart{
		{name: "modules", body: "panel"},
		{name: "account", body: "admin"},
		{name: "password", body: "口令-P@ss"},
		{name: "file", body: "备份内容", file: true},
	})

	up, err := readImportUpload(req, 1<<20)
	if err != nil {
		t.Fatalf("不该报错：%v", err)
	}
	if string(up.raw) != "备份内容" {
		t.Fatalf("文件内容不对：%q", up.raw)
	}
	if up.account != "admin" || up.password != "口令-P@ss" || up.modules != "panel" {
		t.Fatalf("字段没收齐：account=%q password=%q modules=%q", up.account, up.password, up.modules)
	}
}

// 不认识的部分整份丢掉，不因此让导入失败——多一个无关字段不该是错误。
// 同时验证它夹在中间不会打断后面部分的读取。
func TestReadImportUploadIgnoresUnknownParts(t *testing.T) {
	req := buildImportBody(t, []importPart{
		{name: "csrf", body: "无关字段"},
		{name: "file", body: "备份内容", file: true},
		{name: "另一个附件", body: strings.Repeat("x", 4096), file: true},
		{name: "account", body: "admin"},
		{name: "password", body: "口令-P@ss"},
	})

	up, err := readImportUpload(req, 1<<20)
	if err != nil {
		t.Fatalf("多余的部分不该让导入失败：%v", err)
	}
	if string(up.raw) != "备份内容" {
		t.Fatalf("文件内容不对：%q", up.raw)
	}
	if up.account != "admin" || up.password != "口令-P@ss" {
		t.Fatalf("多余的部分打断了后面的字段：account=%q password=%q", up.account, up.password)
	}
}

// 同名的 file 部分出现两次：只认第一个，与 gin 的 FormFile 口径一致。
// 明确钉住而不是听天由命——"导入了哪一份"必须是确定的。
func TestReadImportUploadKeepsFirstFilePart(t *testing.T) {
	req := buildImportBody(t, []importPart{
		{name: "file", body: "第一份", file: true},
		{name: "file", body: "第二份", file: true},
	})

	up, err := readImportUpload(req, 1<<20)
	if err != nil {
		t.Fatalf("不该报错：%v", err)
	}
	if string(up.raw) != "第一份" {
		t.Fatalf("应只认第一个 file 部分，实际 %q", up.raw)
	}
}

// 各种拒绝情形，逐句对齐改写之前 c.FormFile 那几支的措辞。
func TestReadImportUploadRejections(t *testing.T) {
	cases := []struct {
		name  string
		parts []importPart
		limit int64
		want  string
	}{
		{
			name:  "没有文件部分",
			parts: []importPart{{name: "account", body: "admin"}},
			limit: 1 << 20,
			want:  "未找到上传的配置文件",
		},
		{
			name:  "文件是空的",
			parts: []importPart{{name: "file", body: "", file: true}},
			limit: 1 << 20,
			want:  "备份文件大小无效",
		},
		{
			// 上限从参数进来，于是这一条用 64 字节就能测准，不必造 128 MB。
			name:  "文件超一个字节",
			parts: []importPart{{name: "file", body: strings.Repeat("a", 65), file: true}},
			limit: 64,
			want:  "备份文件大小无效",
		},
		{
			name:  "字段超长",
			parts: []importPart{{name: "password", body: strings.Repeat("p", maxImportFieldBytes+1)}, {name: "file", body: "备份内容", file: true}},
			limit: 1 << 20,
			want:  "表单字段 password 过长",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := buildImportBody(t, c.parts)
			up, err := readImportUpload(req, c.limit)
			if err == nil {
				t.Fatalf("应报错，实际收下了 %d 字节", len(up.raw))
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("报错应包含 %q，实际 %q", c.want, err.Error())
			}
		})
	}
}

// 正好等于上限要放过去。少了这一条，"把上限判成 >=" 这种差一错没人拦。
func TestReadImportUploadAcceptsExactlyAtLimit(t *testing.T) {
	const limit = 64
	req := buildImportBody(t, []importPart{
		{name: "file", body: strings.Repeat("a", limit), file: true},
	})

	up, err := readImportUpload(req, limit)
	if err != nil {
		t.Fatalf("正好等于上限应放过，实际 %v", err)
	}
	if len(up.raw) != limit {
		t.Fatalf("内容应完整收下，实际 %d 字节", len(up.raw))
	}
}

// 字段正好等于长度上限也要放过：这个上限是防滥用的，不该去卡一个写得离谱但合法的密码。
func TestReadImportUploadAcceptsFieldExactlyAtLimit(t *testing.T) {
	long := strings.Repeat("p", maxImportFieldBytes)
	req := buildImportBody(t, []importPart{
		{name: "file", body: "备份内容", file: true},
		{name: "password", body: long},
	})

	up, err := readImportUpload(req, 1<<20)
	if err != nil {
		t.Fatalf("正好等于上限的字段应放过，实际 %v", err)
	}
	if up.password != long {
		t.Fatalf("字段应完整收下，实际 %d 字节", len(up.password))
	}
}

// 压根不是 multipart 的请求：与改写前一致，走"没找到文件"这句，
// 而不是把 mime 解析的内部错误抛给用户。
func TestReadImportUploadRejectsNonMultipart(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/settings/import", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")

	if _, err := readImportUpload(req, 1<<20); err == nil {
		t.Fatal("非 multipart 请求应报错")
	} else if !strings.Contains(err.Error(), "未找到上传的配置文件") {
		t.Fatalf("报错不对：%v", err)
	}
}

// 超限那句话里的数由上限算出来，免得常量改了文案没跟着改。
// 真实调用方传的是 maxBackupFileSize，用户看到的必须还是那句"需 ≤ 128MB"。
func TestReadImportUploadOversizeMessageMatchesRealLimit(t *testing.T) {
	req := buildImportBody(t, []importPart{{name: "file", body: "", file: true}})

	_, err := readImportUpload(req, maxBackupFileSize)
	if err == nil {
		t.Fatal("空文件应报错")
	}
	if err.Error() != "备份文件大小无效（需 ≤ 128MB）" {
		t.Fatalf("报错措辞与改写前不一致：%q", err.Error())
	}
}
