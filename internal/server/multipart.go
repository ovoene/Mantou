package server

import (
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
)

// multipartFilePart 从 multipart 请求里取出名为 "file" 的文件部分，返回可流式读取的 part。
// 等价于 multipartFilePartFields(r, nil)——不需要顺带收表单字段时用这个。
func multipartFilePart(r *http.Request) (*multipart.Part, error) {
	return multipartFilePartFields(r, nil)
}

// multipartFilePartFields 取出名为 "file" 的文件部分，并顺带收下排在它**之前**的表单字段：
// want 的键是字段名，值是接收字符串的指针（nil map 表示不收任何字段）。
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
// 只取第一个叫 file 的部分，在它之后的部分一概没读到（读了就得把文件流缓存下来，
// 那正是上面要避的事）。于是 want 里的字段**必须排在 file 之前**，调用方要负责
// 让前端按这个顺序 append；排在后面的字段拿不到，而这里只会当它没填。
// 两样都要且顺序不受控的调用方得自己遍历（见 readImportUpload）。
//
// 未出现的字段保持调用方给的初值不动，重复出现只认第一个：同名字段第二次出现时
// 覆盖前一次，就等于让请求方用一个附加字段改写前面那个值。
func multipartFilePartFields(r *http.Request, want map[string]*string) (*multipart.Part, error) {
	mr, err := r.MultipartReader()
	if err != nil {
		return nil, errors.New("不是有效的 multipart 上传请求")
	}
	seen := make(map[string]bool, len(want))
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			return nil, errors.New("缺少上传文件")
		}
		if err != nil {
			return nil, fmt.Errorf("读取上传数据失败：%w", err)
		}
		name := part.FormName()
		if name == "file" {
			return part, nil
		}
		if dst := want[name]; dst != nil && !seen[name] {
			seen[name] = true
			s, err := readField(part, name)
			if err != nil {
				_ = part.Close()
				return nil, err
			}
			*dst = s
		}
		_ = part.Close()
	}
}

// readField 把一个非文件部分读成字符串，超过 maxMultipartFieldBytes 即报错。
// 上限必须在这里执行：手工遍历 multipart 之后没有别的地方管这件事了
// （走 gin 的表单解析时它是被 MaxMultipartMemory 顺带管着的）。
func readField(part *multipart.Part, name string) (string, error) {
	var sb strings.Builder
	if _, err := io.Copy(&sb, io.LimitReader(part, maxMultipartFieldBytes+1)); err != nil {
		return "", fmt.Errorf("读取表单字段 %s 失败", name)
	}
	if sb.Len() > maxMultipartFieldBytes {
		return "", fmt.Errorf("表单字段 %s 过长", name)
	}
	return sb.String(), nil
}

// maxMultipartFieldBytes 手工遍历的 multipart 表单里单个非文件字段的长度上限。
//
// 手工遍历 multipart 之后，「字段不能无限长」这件事就成了这里的责任——走 gin 的表单解析时
// 它是被 MaxMultipartMemory 顺带管着的。这些字段是模块标识串（一串逗号分隔的名字）与凭证，
// 实际都远在这个数以下；留到 64 KB 只是为了不去卡一个写得离谱但合法的密码。
const maxMultipartFieldBytes = 64 << 10

// importPrealloc 读取备份内容时的预分配上限。
//
// 常见的备份（配置 JSON + 证书 + 背景图）都在这个量级以下，一次分配到位可省掉
// 反复扩容的那串拷贝；更大的备份让它自己长（见 readCapped）。
//
// 用 Content-Length 当提示但**不**照着它全额预分配：那是客户端说的数，
// 照着它分配等于让一个一百字节的请求也能要走 128 MB。
const importPrealloc = 8 << 20

// importPreallocUnknown Content-Length 缺失（分块传输）时的起始容量。
// 只是个起点，读多少长多少。
const importPreallocUnknown = 64 << 10

// readCapped 把 r 读进一片自增长的缓冲，容量**始终不超过 limit+1**，
// 多出的那一个字节留给调用方判断"源比上限长"。
//
// 不用 bytes.Buffer / io.ReadAll：它们只知道"还不够，再大一点"，扩到最后一档时
// 会为一份正好 128 MB 的文件要走一片明显更大的数组，而扩容的那一瞬新旧两片同时在手上。
// 导入这条路上紧接着还要几片同等大小的缓冲（见 config_crypt.go 的 cipherBytes），
// 峰值差的这一两百 MB 在 512MB 那类小主机上就是导入成不成的分界。
// 知道硬上限就该把它用上：翻倍到 limit+1 为止，绝不越过。
func readCapped(r io.Reader, limit, hint int64) ([]byte, error) {
	room := limit + 1
	if hint < 1 {
		hint = 1
	}
	if hint > room {
		hint = room
	}
	buf := make([]byte, 0, hint)
	for {
		if len(buf) == cap(buf) {
			if int64(cap(buf)) >= room {
				// 已经攒满 limit+1 个字节，够调用方判定超限了，不再往下读。
				return buf, nil
			}
			grow := int64(cap(buf)) * 2
			if grow > room {
				grow = room
			}
			next := make([]byte, len(buf), grow)
			copy(next, buf)
			buf = next
		}
		n, err := r.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if err == io.EOF {
			return buf, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

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
			hint := int64(importPreallocUnknown)
			if n := r.ContentLength; n > 0 && n < importPrealloc {
				hint = n
			} else if n >= importPrealloc {
				hint = importPrealloc
			}
			raw, err := readCapped(part, maxFile, hint)
			if err != nil {
				_ = part.Close()
				return nil, errors.New("读取上传文件失败")
			}
			up.raw = raw
		case fields[name] != nil:
			s, err := readField(part, name)
			if err != nil {
				_ = part.Close()
				return nil, err
			}
			*fields[name] = s
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
