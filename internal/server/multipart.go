package server

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
)

// multipartFilePart 从 multipart 请求里取出名为 "file" 的文件部分，返回可流式读取的 part。
//
// 刻意不用 c.FormFile：那会先把整个上传体读进内存（gin 的 MaxMultipartMemory 默认 32 MB，
// 更新包与备份文件正好落在这个量级内，于是全量驻留），超出部分还要落一份临时文件，
// 之后处理器再从头读一遍——白白付出一次全量拷贝与一趟磁盘往返。
// 直接消费 multipart 流可让「上传 → 校验 → 落盘」全程只占用 32 KB 级拷贝缓冲，
// 在 512MB 内存的小主机上尤为关键。
//
// 调用方拿到 part 后自己负责 Close，以及自己卡住体积上限——这个函数只负责定位那一部分，
// 不替调用方决定"多大算大"（更新包、备份、背景图三条路的上限各不相同）。
//
// 只取第一个叫 file 的部分，它之前的部分被读掉丢弃。这决定了同一份表单里的其它字段
// 只有排在 file **之前**才拿得到，排在后面的读不到——需要同时收字段与文件的调用方
// 必须自己遍历 part（见 handleImportConfig）。
func multipartFilePart(r *http.Request) (*multipart.Part, error) {
	mr, err := r.MultipartReader()
	if err != nil {
		return nil, errors.New("不是有效的 multipart 上传请求")
	}
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			return nil, errors.New("缺少上传文件")
		}
		if err != nil {
			return nil, fmt.Errorf("读取上传数据失败：%w", err)
		}
		if part.FormName() == "file" {
			return part, nil
		}
		_ = part.Close()
	}
}

// maxImportFieldBytes 导入表单里单个非文件字段的长度上限。
//
// 手工遍历 multipart 之后，「字段不能无限长」这件事就成了这里的责任——走 gin 的表单解析时
// 它是被 MaxMultipartMemory 顺带管着的。modules 是一串逗号分隔的模块标识、account 与
// password 是凭证，实际都远在这个数以下；留到 64 KB 只是为了不去卡一个写得离谱但合法的密码。
const maxImportFieldBytes = 64 << 10

// importPrealloc 读取备份内容时的预分配上限。
//
// 常见的备份（配置 JSON + 证书 + 背景图）都在这个量级以下，一次分配到位可省掉
// bytes.Buffer 反复扩容的那串拷贝；更大的备份让它自己长。
//
// 用 Content-Length 当提示但**不**照着它全额预分配：那是客户端说的数，
// 照着它分配等于让一个一百字节的请求也能要走 128 MB。
const importPrealloc = 8 << 20

// importUpload 是导入请求里需要的全部东西：备份文件内容，以及几个表单字段。
//
// account / password 与 authAccount / authPassword 是**两套不同的凭据**，别混：
// 前者是解开这份备份文件的口令（由做备份的人自己定，见 config_crypt.go 的 deriveKey），
// 后者是本机当前管理员的账户与密码，用来证明"我是这台面板的管理员"。
// 前者不能替代后者——一份备份的口令由上传者自选，证明不了任何身份。
type importUpload struct {
	raw          []byte
	modules      string
	account      string
	password     string
	authAccount  string
	authPassword string
}

// readImportUpload 手工遍历 multipart 的各个部分，一趟读取里同时收下文件与表单字段。
//
// 为什么不用 c.FormFile + c.PostForm：那条路会先把整个上传体收进内存（gin 的
// MaxMultipartMemory 默认 32 MB），超出的部分落一份临时文件到 TMPDIR，
// 处理器再 io.ReadAll 从头读一遍。一份 128 MB 的备份因此要多付 32 MB 常驻内存、
// 96 MB 的磁盘写入，以及一趟完整读回。
//
// 也用不了 multipartFilePart：前端是先 append('file')、再 append 那三个字段的
// （见 web/src/views/Settings.vue），而那个函数只找 file、把它之前的部分丢掉，
// 排在 file 后面的字段读不到。所以这里自己遍历，与字段顺序无关。
//
// 返回的错误消息就是给用户看的那句话（导入的入参问题一律 400），
// 与改写之前 c.FormFile 那几支的措辞逐句对齐。
//
// maxFile 从参数进来而不是直接读那个常量：这样"正好等于上限"与"超一个字节"两个边界
// 能用几十字节的输入测准，不必为跑一次断言真的造两份 128 MB。真实调用方传的是
// maxBackupFileSize，超限那句话里的数也由它算出来，免得常量与文案各改一处对不上。
func readImportUpload(r *http.Request, maxFile int64) (*importUpload, error) {
	mr, err := r.MultipartReader()
	if err != nil {
		// 与改写前一致：非 multipart 请求走的也是"没找到文件"这句。
		return nil, errors.New("未找到上传的配置文件")
	}
	up := &importUpload{}
	fields := map[string]*string{
		"modules":      &up.modules,
		"account":      &up.account,
		"password":     &up.password,
		"authAccount":  &up.authAccount,
		"authPassword": &up.authPassword,
	}
	seenFile := false
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.New("读取上传文件失败")
		}
		name := part.FormName()
		switch {
		case name == "file" && !seenFile:
			// 同名部分出现多次时只认第一个，与 gin 的 FormFile 口径一致。
			seenFile = true
			var buf bytes.Buffer
			if n := r.ContentLength; n > 0 {
				hint := n
				if hint > importPrealloc {
					hint = importPrealloc
				}
				buf.Grow(int(hint))
			}
			// 多读一个字节：能读到就说明源比上限长。
			if _, err := io.Copy(&buf, io.LimitReader(part, maxFile+1)); err != nil {
				_ = part.Close()
				return nil, errors.New("读取上传文件失败")
			}
			up.raw = buf.Bytes()
		case fields[name] != nil:
			var sb strings.Builder
			if _, err := io.Copy(&sb, io.LimitReader(part, maxImportFieldBytes+1)); err != nil {
				_ = part.Close()
				return nil, errors.New("读取上传文件失败")
			}
			if sb.Len() > maxImportFieldBytes {
				_ = part.Close()
				return nil, fmt.Errorf("表单字段 %s 过长", name)
			}
			*fields[name] = sb.String()
		default:
			// 不认识的部分整份丢掉：不占内存，也不因此让整个导入失败
			// （多一个无关字段不该是错误）。
			_, _ = io.Copy(io.Discard, part)
		}
		_ = part.Close()
	}
	if !seenFile {
		return nil, errors.New("未找到上传的配置文件")
	}
	if len(up.raw) == 0 || int64(len(up.raw)) > maxFile {
		return nil, fmt.Errorf("备份文件大小无效（需 ≤ %dMB）", maxFile>>20)
	}
	return up, nil
}
