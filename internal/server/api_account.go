package server

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"mantou/internal/auth"
	"mantou/internal/config"
)

// changeAccountReq 是修改账户请求：可同时/分别修改登录用户名与密码。
// 任一修改都需提供当前密码以授权。NewPassword 为空表示不改密码；
// Username 为空或与现值相同表示不改用户名。
type changeAccountReq struct {
	Username    string `json:"username"`
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword"`
}

// handleChangeAccount 校验当前密码后更新登录用户名和/或密码。
// 修改用户名会使既有会话主体失效，前端需据 usernameChanged 提示重新登录。
// 只改密码则作废所有旧会话、给当前浏览器换发一条新的，前端无需为此做任何事。
func (s *Server) handleChangeAccount(c *gin.Context) {
	var req changeAccountReq
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "请求参数无效")
		return
	}

	cfg := s.deps.Config.Snapshot()
	newName := strings.TrimSpace(req.Username)
	changeName := newName != "" && newName != cfg.Auth.Username
	changePass := req.NewPassword != ""

	if !changeName && !changePass {
		respondError(c, http.StatusBadRequest, "未提供任何修改")
		return
	}
	// 任何账户变更都要求验证当前密码。
	if !auth.VerifyPassword(cfg.Auth.PasswordHash, req.OldPassword) {
		respondError(c, http.StatusUnauthorized, "当前密码错误")
		return
	}
	if changeName && len(newName) < 3 {
		respondError(c, http.StatusBadRequest, "用户名至少 3 个字符")
		return
	}
	if changePass && len(req.NewPassword) < 6 {
		respondError(c, http.StatusBadRequest, "新密码至少 6 个字符")
		return
	}

	var newHash string
	if changePass {
		h, err := auth.HashPassword(req.NewPassword)
		if err != nil {
			respondError(c, http.StatusInternalServerError, "密码处理失败")
			return
		}
		newHash = h
	}

	if err := s.deps.Config.Update(func(cfg *config.Config) {
		if changeName {
			cfg.Auth.Username = newName
		}
		if changePass {
			cfg.Auth.PasswordHash = newHash
		}
	}); err != nil {
		respondError(c, http.StatusInternalServerError, "保存失败")
		return
	}
	// 会话失效。两种改动的处置不同：
	//
	// 改用户名 → 全部失效，包括当前这台。旧令牌的 subject 不再等于新用户名，
	// 它们在 authRequired 那里本就过不去；这里连表一起清掉，不留残条。
	//
	// 只改密码 → 所有旧会话失效，当前这台换一条新的接上。原来这一支什么都不做，于是
	// "我怀疑密码泄露了，赶紧改一个"这个动作对攻击者手上的会话毫无影响：签名密钥没换、
	// 用户名没变、会话表没清，三道关卡一道都不成立，那个会话会一直活到 SessionHours
	// 到期为止（见 5-F）。
	//
	// 为什么是"换一条"而不是"留着当前那条"：会话泄露最常见的形态是 Cookie 值被复制走，
	// 此时攻击者手上的令牌与管理员浏览器里的**是同一个**。保留当前令牌等于把攻击者一起保留。
	// 换成新令牌则旧值连同副本一起作废，而管理员这台浏览器只是收到一条新 Cookie，
	// 界面上察觉不到任何变化，操作步骤一步都不用改。
	othersRevoked := 0
	switch {
	case changeName:
		s.sessions.revokeAll("")
		s.clearSessionCookies(c)
	case changePass:
		othersRevoked = s.sessions.revokeAll(s.extractToken(c))
		s.rotateCurrentSession(c)
	}
	respondOK(c, gin.H{"ok": true, "usernameChanged": changeName, "passwordChanged": changePass, "othersRevoked": othersRevoked})
}

// verifyIdentityReq 是身份验证请求：只用来确认「操作者知道当前账户与密码」，不改任何东西。
type verifyIdentityReq struct {
	Account  string `json:"account"`
	Password string `json:"password"`
}

// handleVerifyIdentity 校验当前管理员账户与密码，供敏感操作在动手之前先验一次身份。
//
// 现在的调用方是导入配置：界面上先弹一个认证框，通过了才让人进到「选范围 + 填备份口令」
// 那一步，免得一长串东西都填完了，最后提交时才被打回来。
//
// 它**不是**那些操作的安全边界——真正的闸在各自的接口里（见 handleImportConfig 里那道
// 同款校验）。前端拿到 200 不等于后面那一步就免验了，谁也不许把它当令牌用。
//
// 已鉴权路由，不额外做失败计数。这不是因为猜密码没意义，而是这条路给不出任何
// 改账户与加密导出还没给出的东西：那两条一样是"拿一条会话反复试当前密码"，
// 一样只有 bcrypt 的百毫秒级成本兜着。真要限，得三处一起限；
// 只在这一条上加，攻击者换另外两条即可，界面上却多出一处会把人锁住的地方。
//
// 也刻意不与登录限流共用计数：那样一条被盗的会话就能把真正的管理员锁在登录页外面。
func (s *Server) handleVerifyIdentity(c *gin.Context) {
	var req verifyIdentityReq
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "请求参数无效")
		return
	}
	cfg := s.deps.Config.Snapshot()
	// 403 而不是 401：会话是好的，只是密码填错了，不该让前端把人强制登出。
	if strings.TrimSpace(req.Account) != cfg.Auth.Username ||
		!auth.VerifyPassword(cfg.Auth.PasswordHash, req.Password) {
		respondError(c, http.StatusForbidden, "当前账户或密码不正确")
		return
	}
	respondOK(c, gin.H{"ok": true})
}

// rotateCurrentSession 作废当前令牌、给同一台浏览器换发一条新的。
//
// 换不出来时（签发失败）就把 Cookie 清掉：这一步已经把旧令牌作废了，如果不换也不清，
// 浏览器会拿着一个刚被删掉的令牌继续请求，下一次操作才在别处报"会话已失效"。
// 宁可当场登出，也不留一个看起来还登着、实际已经空了的状态。
func (s *Server) rotateCurrentSession(c *gin.Context) {
	if old := s.extractToken(c); old != "" {
		s.sessions.remove(old)
	}
	cfg := s.deps.Config.Snapshot()
	ttl := time.Duration(cfg.Auth.SessionHours) * time.Hour
	if ttl <= 0 {
		ttl = time.Hour
	}
	token, err := auth.IssueToken(cfg.Auth.JWTSecret, cfg.Auth.Username, ttl)
	if err != nil {
		s.deps.Log.Warn("改密码后换发会话失败，已登出当前浏览器", "err", err)
		s.clearSessionCookies(c)
		return
	}
	s.sessions.add(token, cfg.Auth.Username, ttl)
	s.setSessionCookie(c, token)
}

// 允许的背景图类型与其扩展名。
var allowedImageTypes = map[string]string{
	"image/jpeg": ".jpg",
	"image/png":  ".png",
	"image/webp": ".webp",
	"image/gif":  ".gif",
}

// isRealImage 依据魔数判断字节流是否为受支持的图片格式。
func isRealImage(head []byte) bool {
	if len(head) < 12 {
		return false
	}
	// JPEG: FF D8 FF
	if head[0] == 0xFF && head[1] == 0xD8 && head[2] == 0xFF {
		return true
	}
	// PNG: 89 50 4E 47 0D 0A 1A 0A
	if head[0] == 0x89 && head[1] == 0x50 && head[2] == 0x4E && head[3] == 0x47 {
		return true
	}
	// GIF: 47 49 46 38 (GIF8)
	if head[0] == 0x47 && head[1] == 0x49 && head[2] == 0x46 && head[3] == 0x38 {
		return true
	}
	// WEBP: 52 49 46 46 ?? ?? ?? ?? 57 45 42 50 (RIFF....WEBP)
	if len(head) >= 12 &&
		head[0] == 0x52 && head[1] == 0x49 && head[2] == 0x46 && head[3] == 0x46 &&
		head[8] == 0x57 && head[9] == 0x45 && head[10] == 0x42 && head[11] == 0x50 {
		return true
	}
	return false
}

// maxBackgroundImageBytes 背景图上传的体积上限。
// 路由的请求体上限按它计算（见 bodylimit.go），所以这个数只能出现一次。
const maxBackgroundImageBytes = 10 << 20

// handleUploadBackground 接收背景图上传，保存到 data/uploads 并返回可访问 URL。
//
// 刻意不用 c.FormFile：那会先把整个上传体收进内存（gin 的 MaxMultipartMemory 默认 32 MB），
// 然后 SaveUploadedFile 再把这份内存拷一遍到磁盘——一张 10 MB 的图要过两趟全量拷贝，
// 而这条路由**没有任何串行化**，10 个并发上传就是 10 份常驻缓冲，
// 且请求本身还被 extendRequestDeadlines 放宽到 5 分钟。改成直接消费 multipart 流之后，
// 全程只占一个 32 KB 级的拷贝缓冲，与并发数无关。
//
// 顺带修掉一个次序问题：魔数校验原先在文件已经落盘之后才做，于是一个伪装成图片的
// 上传要先被完整写进 data/uploads 再删掉。现在头 16 个字节就足够判断，不合格的
// 一个字节都不落盘。
//
// 与自更新的更新包上传是同一套做法（共用 multipartFilePart），理由也一样。
func (s *Server) handleUploadBackground(c *gin.Context) {
	if s.deps.DataDir == "" {
		respondError(c, http.StatusServiceUnavailable, "未配置数据目录")
		return
	}
	// 最大 10 MB 的图片上传，慢链路上会超过面板的全局 ReadTimeout，逐请求放宽。
	s.extendRequestDeadlines(c, 5*time.Minute)
	part, err := multipartFilePart(c.Request)
	if err != nil {
		respondError(c, http.StatusBadRequest, "缺少上传文件")
		return
	}
	defer part.Close()

	// 类型在部分头里，读正文之前就能判。
	ct := part.Header.Get("Content-Type")
	ext, ok := allowedImageTypes[ct]
	if !ok {
		// 安全：不再回退到「按文件名扩展名放行」，避免把任意扩展名（如 .svg/.html）伪造成图片写入。
		respondError(c, http.StatusBadRequest, "不支持的图片类型，仅允许 jpg/png/webp/gif")
		return
	}

	// 魔数校验提到落盘之前：先把头部读出来，不合格就地拒绝。
	head := make([]byte, imageHeadBytes)
	n, err := io.ReadFull(part, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		respondError(c, http.StatusBadRequest, "读取上传文件失败")
		return
	}
	head = head[:n]
	if !isRealImage(head) {
		respondError(c, http.StatusBadRequest, "文件内容并非有效的图片")
		return
	}

	uploadDir := filepath.Join(s.deps.DataDir, "uploads")
	if err := os.MkdirAll(uploadDir, 0o755); err != nil {
		respondError(c, http.StatusInternalServerError, "创建上传目录失败")
		return
	}
	// 注意：上传时【不】删除旧背景图。旧文件回收推迟到用户点击「保存外观」那一刻
	// （见 handleUpdateAppearance），避免「上传后未保存就切走」误删仍被配置引用的旧图、
	// 却没落盘新图，反而制造孤儿文件。
	name := fmt.Sprintf("bg-%d%s", time.Now().UnixNano(), ext)
	dst := filepath.Join(uploadDir, name)
	if err := writeImagePart(dst, head, part, maxBackgroundImageBytes); err != nil {
		// 写坏的半个文件必须清掉，否则它谁也不引用、界面上也看不见（孤儿文件）。
		_ = os.Remove(dst)
		if errors.Is(err, errImageTooLarge) {
			respondError(c, http.StatusBadRequest, "图片不能超过 10MB")
			return
		}
		respondError(c, http.StatusInternalServerError, "保存文件失败")
		return
	}

	url := "/uploads/" + name
	respondOK(c, gin.H{"url": url})
}

// imageHeadBytes 判定图片魔数需要的字节数（isRealImage 最长要看到第 12 个字节）。
const imageHeadBytes = 16

// errImageTooLarge 图片超过上限。单开一个错误值而不是在写入函数里直接回响应：
// 那样它就同时管着"写文件"和"回 HTTP"两件事，测起来要起一整个 gin 上下文。
var errImageTooLarge = errors.New("图片超过上限")

// writeImagePart 把已读出的头部与剩余的流一起写进目标文件，并在写的过程中卡住体积上限。
//
// 上限从参数进来而不是直接读那个常量：这样边界（正好等于上限 / 超一个字节）能用几十字节的
// 输入测准，不必为了跑一次断言真的造 10 MB。调用方传的是 maxBackgroundImageBytes。
//
// 上限在这里卡而不是靠请求体上限兜着：请求体上限是给整个 multipart 报文的（含分隔串、
// 各部分头部与同表单的其它字段），它保证的是"进程不会被打爆"；而"这张图不能超过 10 MB"
// 是一条要能准确报给用户的业务约束，两者的数不是同一个。
func writeImagePart(dst string, head []byte, body io.Reader, limit int64) error {
	// O_EXCL：文件名带纳秒时间戳，撞名意味着出了别的问题，宁可失败也不覆盖既有文件。
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(head); err != nil {
		f.Close()
		return err
	}
	// 多要一个字节：能拷满就说明源比上限长。
	written, err := io.CopyN(f, body, limit-int64(len(head))+1)
	if err != nil && !errors.Is(err, io.EOF) {
		f.Close()
		return err
	}
	if int64(len(head))+written > limit {
		f.Close()
		return errImageTooLarge
	}
	return f.Close()
}

// handleDeleteBackground 删除已上传的背景图文件，并把外观中的背景重置为默认渐变，
// 使后续配置备份（仅打包被配置引用的上传文件）不再包含该图片。
func (s *Server) handleDeleteBackground(c *gin.Context) {
	if s.deps.DataDir == "" {
		respondError(c, http.StatusServiceUnavailable, "未配置数据目录")
		return
	}
	cfg := s.deps.Config.Snapshot()
	if err := removeBackgroundFile(s.deps.DataDir, cfg.Settings.Appearance.Background.Value); err != nil {
		respondError(c, http.StatusInternalServerError, "删除背景图失败: "+err.Error())
		return
	}
	// 将背景重置为默认渐变，确保配置不再引用已删除的文件。
	if err := s.deps.Config.Update(func(c *config.Config) {
		c.Settings.Appearance.Background = config.AppearanceBackground{
			Type:           "gradient",
			Value:          "linear-gradient(135deg,#e6efff 0%,#f3f0ff 100%)",
			Blur:           0,
			OverlayOpacity: 0.15,
			Fit:            "cover",
			Position:       "center",
		}
	}); err != nil {
		respondError(c, http.StatusInternalServerError, "更新外观失败")
		return
	}
	respondOK(c, gin.H{"ok": true})
}

// removeBackgroundFile 删除背景图引用的 data/uploads 物理文件（文件不存在或路径不安全时静默跳过）。
func removeBackgroundFile(dataDir, value string) error {
	if !strings.HasPrefix(value, "/uploads/") {
		return nil
	}
	rel := strings.TrimPrefix(value, "/uploads/")
	rel = strings.TrimPrefix(rel, "/")
	if !safeBackupPath(rel) {
		return nil
	}
	full := filepath.Join(dataDir, "uploads", filepath.FromSlash(rel))
	if _, err := os.Stat(full); err != nil {
		return nil // 文件不存在，无需删除
	}
	return os.Remove(full)
}

// nowUnix 返回当前 Unix 秒。
func nowUnix() int64 { return time.Now().Unix() }
