package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"

	"mantou/internal/auth"
	"mantou/internal/config"
	"mantou/internal/modules/wol"
	"mantou/internal/netguard"
	"mantou/internal/version"
)

// handleExportConfig 导出完整配置，备份文件始终以「登录账户名 + 密码」加密（AES-256-GCM）。
// 账户名须与当前登录账户一致、密码须正确，校验通过后才派生密钥加密，避免用任意凭据加密。
// 备份即密文，明文配置不会落盘；忘记密码将无法解密恢复，故导出时明确提示用户牢记。
const (
	maxBackupFileSize = 128 * 1024 * 1024
	maxBackupItemSize = 16 * 1024 * 1024
	maxBackupTotal    = 96 * 1024 * 1024
	maxBackupItems    = 1024
)

func (s *Server) handleExportConfig(c *gin.Context) {
	s.backupMu.Lock()
	defer s.backupMu.Unlock()

	var req struct {
		Account  string `json:"account"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Password == "" {
		respondError(c, http.StatusBadRequest, "请提供加密所用的账户名与密码")
		return
	}
	cfg := s.deps.Config.Snapshot()
	if strings.TrimSpace(req.Account) != cfg.Auth.Username || !auth.VerifyPassword(cfg.Auth.PasswordHash, req.Password) {
		// 注意：这里返回 403 而非 401。前端响应拦截器会在收到 401 时强制登出跳转登录页，
		// 而导出密码错误属于正常业务失败，应仅提示用户、停留在当前页面。
		respondError(c, http.StatusForbidden, "密码错误")
		return
	}
	certBackups := make([]CertBackup, 0, len(cfg.Certs))
	if len(cfg.Certs) > 0 && s.deps.Cert == nil {
		respondError(c, http.StatusServiceUnavailable, "证书模块未就绪，无法生成完整备份")
		return
	}
	certTotal := 0
	if len(cfg.Certs) > maxBackupItems {
		respondError(c, http.StatusInternalServerError, "证书数量超过限制")
		return
	}
	seenCertIDs := make(map[string]struct{}, len(cfg.Certs))
	for _, cert := range cfg.Certs {
		if cert.ID == "" || filepath.Base(cert.ID) != cert.ID {
			respondError(c, http.StatusInternalServerError, "证书 ID 不安全: "+cert.Name)
			return
		}
		if _, ok := seenCertIDs[cert.ID]; ok {
			respondError(c, http.StatusInternalServerError, "证书 ID 重复: "+cert.ID)
			return
		}
		seenCertIDs[cert.ID] = struct{}{}
		certPEM, keyPEM, eerr := s.deps.Cert.Export(cert, true)
		if eerr != nil {
			respondError(c, http.StatusInternalServerError, "读取证书失败: "+cert.Name+": "+eerr.Error())
			return
		}
		if len(certPEM) == 0 || len(keyPEM) == 0 || len(certPEM)+len(keyPEM) > maxBackupItemSize {
			respondError(c, http.StatusInternalServerError, "证书大小无效: "+cert.Name)
			return
		}
		certTotal += len(certPEM) + len(keyPEM)
		if certTotal > maxBackupTotal {
			respondError(c, http.StatusInternalServerError, "证书总大小超过限制")
			return
		}
		if _, eerr = tls.X509KeyPair(certPEM, keyPEM); eerr != nil {
			respondError(c, http.StatusInternalServerError, "证书无效: "+cert.Name)
			return
		}
		certBackups = append(certBackups, CertBackup{ID: cert.ID, Method: cert.Method, CertPEM: string(certPEM), KeyPEM: string(keyPEM)})
	}
	uploads, err := collectUploadBackups(s.deps.DataDir)
	if err != nil {
		respondError(c, http.StatusInternalServerError, "读取 uploads 失败: "+err.Error())
		return
	}
	// 仅备份配置实际引用的上传文件。data/uploads 可能残留历史孤儿文件
	//（如多次上传背景图、旧引用已删除），这些文件不应进入备份，否则会无谓撑大体积。
	uploads = filterReferencedUploads(cfg, uploads)
	if err := validateBackupResources(cfg, certBackups, uploads); err != nil {
		respondError(c, http.StatusInternalServerError, "备份资源无效: "+err.Error())
		return
	}
	data, err := EncryptBackup(cfg.Auth.Username, req.Password, cfg, certBackups, uploads)
	if err != nil {
		respondError(c, http.StatusInternalServerError, "加密配置失败")
		return
	}
	if len(data) > maxBackupFileSize {
		respondError(c, http.StatusInternalServerError, "备份内容超过 128MB 限制")
		return
	}
	filename := "Mantou-" + time.Now().Format("20060102150405") + ".json"
	c.Header("Content-Disposition", `attachment; filename="`+filename+`"`)
	c.Header("Content-Type", "application/json; charset=utf-8")
	c.Data(http.StatusOK, "application/json; charset=utf-8", data)
}

// handleImportConfig 导入加密备份。可以只导入其中的一部分模块（表单字段 modules，
// 逗号分隔的模块标识；缺省为全部），未选中的模块保持本机现状不动。
// 仅接受本程序生成的加密备份信封，拒绝旧版明文配置。
func (s *Server) handleImportConfig(c *gin.Context) {
	s.backupMu.Lock()
	defer s.backupMu.Unlock()

	// 备份文件上限 128 MB，且导入还要跑 60 万次迭代的 PBKDF2 解密，
	// 整个请求的正常耗时远超面板全局 ReadTimeout / WriteTimeout，逐请求放宽。
	s.extendRequestDeadlines(c, 30*time.Minute)
	// 一趟流式读取同时取回文件与三个表单字段，不经 gin 的表单解析、不落临时文件。
	// 上限与各句报错都收在 readImportUpload 里。
	up, err := readImportUpload(c.Request, maxBackupFileSize)
	if err != nil {
		respondError(c, http.StatusBadRequest, err.Error())
		return
	}
	raw := up.raw

	if !IsEncryptedEnvelope(raw) {
		respondError(c, http.StatusBadRequest, "不允许导入未加密的配置文件，请使用本程序导出的加密备份")
		return
	}

	before := s.deps.Config.Snapshot()
	// 身份验证。导入会改写配置，而「面板与设置」这一档里就包含管理员账户本身，
	// 所以这一步要先证明「我是这台面板当前的管理员」。口径与改账户、加密导出完全一致：
	// 光持有一条会话不够，必须知道当前密码（见 handleChangeAccount 与 handleExportConfig）。
	//
	// 表单里那对 account/password 顶不了这道验证，两者证明的不是同一件事：
	// 它们是解开这份备份文件的口令，由做备份的人自己定（见 config_crypt.go 的 deriveKey），
	// 拿一份自造的备份想填什么填什么，证明不了任何身份。
	//
	// 界面上那个认证弹窗只是引导，真正的闸必须在这里：直接调接口就把前端绕过去了。
	//
	// 放在明文校验之后、解密之前：明文文件仍旧回它原来那句 400（那与身份无关，
	// 是文件本身不对），而这道闸挡在 60 万次 PBKDF2 之前，不给未授权请求白跑的机会。
	//
	// 403 而不是 401：401 会被前端拦截器当成会话失效、把人强制登出，
	// 而这里的会话是好的，只是密码填错了（与导出那一支同款）。
	if strings.TrimSpace(up.authAccount) != before.Auth.Username ||
		!auth.VerifyPassword(before.Auth.PasswordHash, up.authPassword) {
		respondError(c, http.StatusForbidden, "当前账户或密码不正确")
		return
	}

	// 导入范围先解析：解密要跑 60 万次 PBKDF2，参数写错没必要等到那之后才报错。
	scope, err := parseImportScope(up.modules)
	if err != nil {
		respondError(c, http.StatusBadRequest, err.Error())
		return
	}

	account := up.account
	password := up.password
	if account == "" || password == "" {
		respondError(c, http.StatusBadRequest, "加密备份需提供导出时使用的账户名与密码")
		return
	}
	cfg, certs, uploads, err := DecryptBackup(raw, account, password)
	if err != nil {
		respondError(c, http.StatusBadRequest, err.Error())
		return
	}

	// 完整性校验：必须含管理员账户，防止空配置锁死实例。
	// 即便这次不导入「面板与设置」也照样校验——它验的是"这份文件确实是一份 Mantou 备份"，
	// 与导入范围无关。
	if cfg.Auth.Username == "" || cfg.Auth.PasswordHash == "" {
		respondError(c, http.StatusBadRequest, "配置缺少管理员账户信息，疑似空配置或非 Mantou 配置文件")
		return
	}

	// 先把整份备份迁到最新版本，再按模块切片合并（见 config.Migrate 的说明）。
	config.Migrate(cfg)
	// 合并基准必须是 Get() 的深拷贝：Snapshot() 是运行中模块共享的只读对象。
	base := s.deps.Config.Get()
	if base == nil {
		respondError(c, http.StatusInternalServerError, "读取当前配置失败，已中止导入")
		return
	}
	target := mergeImportedConfig(base, cfg, scope)
	// 未选中的模块不动它的磁盘资源：证书目录与 uploads 目录都是整体替换的，
	// 传 nil 即跳过（见 restoreBackupResources）。
	if !scope[modCert] {
		certs = nil
	}
	if !scope[modPanel] {
		uploads = nil
	}
	if err := checkImportCertRefs(target, scope); err != nil {
		respondError(c, http.StatusBadRequest, "导入范围会留下无效的证书引用: "+err.Error())
		return
	}

	if err := validateBackupResources(target, certs, uploads); err != nil {
		respondError(c, http.StatusBadRequest, "备份资源无效: "+err.Error())
		return
	}
	tx, err := s.restoreBackupResources(target, certs, uploads)
	if err != nil {
		if s.deps.Cert != nil {
			_ = s.deps.Cert.Reload(before)
		}
		respondError(c, http.StatusInternalServerError, "恢复资源失败: "+err.Error())
		return
	}
	rollback := true
	defer func() {
		if rollback {
			_ = tx.rollback()
			if s.deps.Cert != nil {
				_ = s.deps.Cert.Reload(before)
			}
		}
	}()

	// 面板端口：备份可能来自另一台机器，那台上空着的端口在这台上未必空着。
	// 端口绑不上会让重启后的面板起不来，而面板起不来就是整个进程退出（见 panelport.go）。
	//
	// 这一路不像保存设置那样回 400：用户手上只有一份加密备份，改不动里面的端口，
	// 报错等于让他彻底导不进来。所以保留当前端口、其余照常导入，并把这件事写进日志。
	// 判定用的是导入后的那份配置——试绑地址与同进程占用都该以落盘后的状态为准。
	if target.Panel.Port != before.Panel.Port {
		if verr := s.checkPanelPort(target, before.Panel.Port, target.Panel.Port); verr != nil {
			s.deps.Log.Warn("备份里的面板端口在本机不可用，已保留当前端口",
				"backupPort", target.Panel.Port, "keptPort", before.Panel.Port, "reason", verr.Error())
			target.Panel.Port = before.Panel.Port
		}
	}
	// 入站防护：与面板端口同一类风险，而且更隐蔽。备份里那份策略是在**另一台机器**上
	// 定下的——"只允许局域网"在做备份的那台上完全成立，在这台上就可能等于"把正在导入的人
	// 关在门外"。落盘之后的下一个请求就按新策略判（防火墙每次判定现取配置快照），
	// 于是用户看到的是"导入成功"，然后再也打不开面板。
	//
	// 处置与端口那一支同口径，理由也一样：不报错。用户手上只有一份加密备份，改不动里面的
	// 策略，报错等于让他彻底导不进来。保留本机当前的防火墙策略、其余照常导入，并记一条日志。
	//
	// 保存设置那条路径上，同样的判定是回 409 让用户确认（见 checkFirewallLockout 与
	// firewallReq.Force）——那里用户手里有输入框，能改；这里没有，所以只能替他保守处理。
	if scope[modPanel] {
		if verr := checkFirewallLockout(target.Settings.Security.Firewall, c.Request); verr != nil {
			s.deps.Log.Warn("备份里的入站防护策略会切断你当前的访问，已保留本机现有策略",
				"reason", verr.Error())
			target.Settings.Security.Firewall = before.Settings.Security.Firewall
		}
	}
	// 服务防护（GlobalFirewall）刻意**没有**同款兜底，这不是漏写。
	// 它拦的是 Web 服务与消息路由的连接（inboundfw 只 Wrap 这两个模块的监听器），
	// 面板自己的监听从不经过它——所以一份再严的备份策略也关不掉正在导入的这个人的门，
	// 导完他仍然能打开服务防护那一页把名单改回来。
	// 既然人还在门里，就不该替他把导入的策略悄悄换回本机现值：那会变成"勾了服务防护、
	// 提示导入成功、策略其实没进来"，正是上面那两支拿日志换来的代价，这里没有理由付。
	//
	// 数值与名单的合法性也不必在这里兜：整份备份在合并前已过 config.Migrate，
	// 里面的 normalizeGlobalFirewall 会把认不出的档位落到均衡、夹住越界值、整理两张名单
	// （Config.Replace 内部还会再跑一遍），与手改 config.json 走的是同一套规则。
	// 导入的配置没经过任何接口层校验：备份可能来自另一台机器、也可能被手工改过。
	// 发送参数非法的网络唤醒设备在这里就地禁用（口径与启动时的 app.SanitizeWOLDevices 同源），
	// 免得一份带病的备份导入完就开始每拍发一次注定失败、甚至打到公网的包。
	// 放在 Replace 之前：随这一次原子替换一起落盘，不额外写一次配置。
	for _, bad := range wol.DisableInvalidDevices(target.WOLDevices) {
		s.deps.Log.Warn("导入的网络唤醒设备参数非法，已自动禁用",
			"id", bad.ID, "name", bad.Name, "reason", bad.Reason)
	}
	if err := s.deps.Config.Replace(target); err != nil {
		respondError(c, http.StatusInternalServerError, "导入失败: "+err.Error())
		return
	}
	rollback = false
	if err := tx.commit(); err != nil {
		s.deps.Log.Warn("清理恢复临时资源失败", "err", err.Error())
	}
	s.afterChange()
	if !scope.all() {
		s.deps.Log.Info("已按所选范围导入配置", "modules", strings.Join(scope.names(), "、"))
	}
	s.warnDanglingRefs(s.deps.Config.Snapshot())

	after := s.deps.Config.Snapshot()
	restartRequired := before.Panel.Port != after.Panel.Port ||
		normalizeBasePath(before.Panel.BasePath) != normalizeBasePath(after.Panel.BasePath) ||
		before.Panel.HTTPS.Enabled != after.Panel.HTTPS.Enabled ||
		before.Panel.HTTPS.CertID != after.Panel.HTTPS.CertID ||
		before.Panel.HTTPS.Domain != after.Panel.HTTPS.Domain

	// 备份里的管理员账户与本机不同时，登录凭据已经被这一次导入换掉了，会话要跟着处置。
	//
	// 不处置会留下一个很难查的状态：你刚用**当前**密码通过了上面那道验证，导入完凭据
	// 已经是备份里那一套，而会话还活着、界面一切正常，于是毫无察觉；直到下次登录才
	// 发现进不去，而那份备份的密码可能是很久以前设的。
	//
	// 两种改动的处置照搬 handleChangeAccount，同一套理由不再重复。
	nameChanged := before.Auth.Username != after.Auth.Username
	credsChanged := nameChanged || before.Auth.PasswordHash != after.Auth.PasswordHash
	if credsChanged {
		if nameChanged {
			s.sessions.revokeAll("")
			s.clearSessionCookies(c)
		} else {
			s.sessions.revokeAll(s.extractToken(c))
			s.rotateCurrentSession(c)
		}
		s.deps.Log.Warn("导入的备份替换了管理员账户，已作废既有会话",
			"usernameChanged", nameChanged)
	}

	respondOK(c, gin.H{"ok": true, "restartRequired": restartRequired, "modules": scope.keys(), "credentialsChanged": credsChanged})
	if restartRequired {
		s.requestPanelRestart("导入配置已改变面板监听或 HTTPS，正在优雅重启面板")
	}
}

func collectUploadBackups(dataDir string) ([]FileBackup, error) {
	files := make([]FileBackup, 0)
	if dataDir == "" {
		return files, nil
	}
	root := filepath.Join(dataDir, "uploads")
	info, err := os.Stat(root)
	if os.IsNotExist(err) {
		return files, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("uploads 不是目录")
	}
	total := 0
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return fmt.Errorf("不支持的 uploads 文件类型: %s", entry.Name())
		}
		if len(files) >= maxBackupItems {
			return errors.New("uploads 文件数量超过限制")
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return fmt.Errorf("uploads 路径不安全: %s", entry.Name())
		}
		// 归一为「/」分隔：filepath.Rel 在 Windows 下返回反斜杠路径，
		// 直接进入 safeBackupPath 会被「包含 \」的守卫误杀，导致含子目录的
		// uploads 在 Windows 上导出失败。统一以正斜杠做安全检查与存储。
		relSlash := filepath.ToSlash(rel)
		if !safeBackupPath(relSlash) {
			return fmt.Errorf("uploads 路径不安全: %s", entry.Name())
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() > maxBackupItemSize || total+int(info.Size()) > maxBackupTotal {
			return fmt.Errorf("uploads 文件大小超过限制: %s", rel)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		total += len(data)
		files = append(files, FileBackup{Path: relSlash, Data: data})
		return nil
	})
	return files, err
}

// referencedUploadPaths 返回配置中引用到的 data/uploads 相对路径集合。
// 目前 data/uploads 仅用于背景图（Appearance.Background.Value 形如 /uploads/xxx）。
func referencedUploadPaths(cfg *config.Config) map[string]bool {
	refs := map[string]bool{}
	bg := cfg.Settings.Appearance.Background
	if bg.Type == "image" {
		v := bg.Value
		if strings.HasPrefix(v, "/uploads/") {
			rel := strings.TrimPrefix(v, "/uploads/")
			rel = strings.TrimPrefix(rel, "/")
			if rel != "" {
				refs[filepath.ToSlash(rel)] = true
			}
		}
	}
	return refs
}

// filterReferencedUploads 仅保留配置实际引用的上传文件，排除历史残留的孤儿文件。
func filterReferencedUploads(cfg *config.Config, uploads []FileBackup) []FileBackup {
	refs := referencedUploadPaths(cfg)
	if len(refs) == 0 {
		return nil
	}
	kept := make([]FileBackup, 0, len(uploads))
	for _, u := range uploads {
		if refs[u.Path] {
			kept = append(kept, u)
		}
	}
	return kept
}

func safeBackupPath(path string) bool {
	if path == "" || !utf8.ValidString(path) || filepath.IsAbs(path) || filepath.VolumeName(path) != "" || strings.ContainsAny(path, `:\`) {
		return false
	}
	clean := filepath.Clean(filepath.FromSlash(path))
	return clean != "." && clean != ".." && !strings.HasPrefix(clean, ".."+string(os.PathSeparator))
}

func validateBackupResources(cfg *config.Config, certs []CertBackup, uploads []FileBackup) error {
	if certs != nil {
		if len(certs) > maxBackupItems {
			return errors.New("证书数量超过限制")
		}
		if len(certs) != len(cfg.Certs) {
			return errors.New("证书资源数量与配置不一致")
		}
		seen := make(map[string]struct{}, len(certs))
		certTotal := 0
		for _, cert := range certs {
			if cert.ID == "" || filepath.Base(cert.ID) != cert.ID {
				return errors.New("证书 ID 不安全")
			}
			if _, ok := seen[cert.ID]; ok {
				return fmt.Errorf("证书 ID 重复: %s", cert.ID)
			}
			seen[cert.ID] = struct{}{}
			if len(cert.CertPEM) == 0 || len(cert.KeyPEM) == 0 || len(cert.CertPEM)+len(cert.KeyPEM) > maxBackupItemSize {
				return fmt.Errorf("证书大小无效: %s", cert.ID)
			}
			certTotal += len(cert.CertPEM) + len(cert.KeyPEM)
			if certTotal > maxBackupTotal {
				return errors.New("证书总大小超过限制")
			}
			if _, err := tls.X509KeyPair([]byte(cert.CertPEM), []byte(cert.KeyPEM)); err != nil {
				return fmt.Errorf("证书无效: %s", cert.ID)
			}
		}
		for _, configured := range cfg.Certs {
			if _, ok := seen[configured.ID]; !ok {
				return fmt.Errorf("缺少证书资源: %s", configured.ID)
			}
		}
	}
	if len(uploads) > maxBackupItems {
		return errors.New("uploads 文件数量超过限制")
	}
	seenPaths := make(map[string]struct{}, len(uploads))
	total := 0
	for _, file := range uploads {
		if !safeBackupPath(file.Path) {
			return fmt.Errorf("uploads 路径不安全: %s", file.Path)
		}
		clean := filepath.Clean(filepath.FromSlash(file.Path))
		if _, ok := seenPaths[clean]; ok {
			return fmt.Errorf("uploads 路径重复: %s", file.Path)
		}
		seenPaths[clean] = struct{}{}
		if len(file.Data) > maxBackupItemSize || total+len(file.Data) > maxBackupTotal {
			return fmt.Errorf("uploads 文件大小超过限制: %s", file.Path)
		}
		total += len(file.Data)
	}
	return nil
}

type restoreTransaction struct {
	certRoot   string
	certOld    string
	uploadRoot string
	uploadOld  string
}

func restoreDirectory(root, old string) error {
	if root == "" {
		return nil
	}
	if err := os.RemoveAll(root); err != nil {
		return err
	}
	if old != "" {
		return os.Rename(old, root)
	}
	return nil
}

func (tx *restoreTransaction) rollback() error {
	if tx == nil {
		return nil
	}
	uploadErr := restoreDirectory(tx.uploadRoot, tx.uploadOld)
	certErr := restoreDirectory(tx.certRoot, tx.certOld)
	return errors.Join(uploadErr, certErr)
}

func removeBackupDirectory(path string) error {
	if path == "" {
		return nil
	}
	return os.RemoveAll(path)
}

func (tx *restoreTransaction) commit() error {
	if tx == nil {
		return nil
	}
	return errors.Join(removeBackupDirectory(tx.uploadOld), removeBackupDirectory(tx.certOld))
}

func (s *Server) restoreBackupResources(cfg *config.Config, certs []CertBackup, uploads []FileBackup) (*restoreTransaction, error) {
	tx := &restoreTransaction{}
	// 这里问的是"备份里真的带了证书文件吗"，len 一个判断就够（nil 切片的 len 是 0）。
	// 下面几处的 `!= nil` 不是同一个意思、也不能照这样简化：它们区分的是
	// "备份里有这个字段但是空的"（JSON []）与"根本没有这个字段"（JSON null），
	// 前者要走清理流程，后者要整段跳过。
	if len(certs) > 0 && s.deps.Cert == nil {
		return nil, errors.New("证书模块未就绪")
	}
	if certs != nil && s.deps.DataDir == "" {
		return nil, errors.New("未配置数据目录")
	}
	if uploads != nil && s.deps.DataDir == "" {
		return nil, errors.New("未配置数据目录")
	}
	if certs != nil {
		for i := range cfg.Certs {
			if cfg.Certs[i].Method == "path" {
				cfg.Certs[i].Method = "file"
				cfg.Certs[i].CertPath = ""
				cfg.Certs[i].KeyPath = ""
			}
		}
	}
	if certs != nil {
		certRoot := filepath.Join(s.deps.DataDir, "certs")
		stage, err := os.MkdirTemp(s.deps.DataDir, ".certs-restore-")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(stage)
		for _, item := range certs {
			if err := os.WriteFile(filepath.Join(stage, item.ID+".crt"), []byte(item.CertPEM), 0o644); err != nil {
				return nil, err
			}
			if err := os.WriteFile(filepath.Join(stage, item.ID+".key"), []byte(item.KeyPEM), 0o600); err != nil {
				return nil, err
			}
		}
		old := certRoot + ".restore-old-" + fmt.Sprint(time.Now().UnixNano())
		if _, err := os.Stat(certRoot); err == nil {
			if err := os.Rename(certRoot, old); err != nil {
				return nil, err
			}
			tx.certOld = old
		} else if !os.IsNotExist(err) {
			return nil, err
		}
		if err := os.Rename(stage, certRoot); err != nil {
			if tx.certOld != "" {
				if restoreErr := os.Rename(tx.certOld, certRoot); restoreErr != nil {
					return nil, fmt.Errorf("激活证书目录失败: %v；恢复原目录失败: %w", err, restoreErr)
				}
				tx.certOld = ""
			}
			return nil, err
		}
		tx.certRoot = certRoot
		for _, item := range certs {
			if err := s.deps.Cert.Import(item.ID, []byte(item.CertPEM), []byte(item.KeyPEM)); err != nil {
				_ = tx.rollback()
				return nil, fmt.Errorf("加载证书 %s 失败: %w", item.ID, err)
			}
		}
	}
	if uploads == nil {
		return tx, nil
	}
	root := filepath.Join(s.deps.DataDir, "uploads")
	stage, err := os.MkdirTemp(s.deps.DataDir, ".uploads-restore-")
	if err != nil {
		_ = restoreDirectory(tx.certRoot, tx.certOld)
		return nil, err
	}
	defer os.RemoveAll(stage)
	for _, file := range uploads {
		dst := filepath.Join(stage, filepath.Clean(filepath.FromSlash(file.Path)))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			_ = restoreDirectory(tx.certRoot, tx.certOld)
			return nil, err
		}
		if err := os.WriteFile(dst, file.Data, 0o644); err != nil {
			_ = restoreDirectory(tx.certRoot, tx.certOld)
			return nil, err
		}
	}
	old := root + ".restore-old-" + fmt.Sprint(time.Now().UnixNano())
	if _, err := os.Stat(root); err == nil {
		if err := os.Rename(root, old); err != nil {
			_ = restoreDirectory(tx.certRoot, tx.certOld)
			return nil, err
		}
		tx.uploadOld = old
	} else if !os.IsNotExist(err) {
		_ = restoreDirectory(tx.certRoot, tx.certOld)
		return nil, err
	}
	if err := os.Rename(stage, root); err != nil {
		if tx.uploadOld != "" {
			if restoreErr := os.Rename(tx.uploadOld, root); restoreErr != nil {
				certRestoreErr := restoreDirectory(tx.certRoot, tx.certOld)
				return nil, errors.Join(fmt.Errorf("激活 uploads 失败: %w", err), fmt.Errorf("恢复原 uploads 失败: %w", restoreErr), certRestoreErr)
			}
			tx.uploadOld = ""
		}
		if certRestoreErr := restoreDirectory(tx.certRoot, tx.certOld); certRestoreErr != nil {
			return nil, errors.Join(err, certRestoreErr)
		}
		return nil, err
	}
	tx.uploadRoot = root
	return tx, nil
}

// handleUpdateCheck 版本/更新检测接口。
// 检测源优先级：
//  1. 配置了 Update.ManifestURL → 拉取自托管清单（JSON：version/url/description），用于不依赖 GitHub 的私有部署；
//  2. 否则回退到 GitHub 仓库检测（仓库由 Update.GitHubRepo 配置，默认 ovoene/Mantou）。
//
// 两种来源均经 30 分钟进程级缓存，避免重复外联（恢复此前的 GitHub 自动检测逻辑，仓库可配置、可不写死）。
// 返回信息：networkError 表示外联失败；rateLimited 表示 GitHub 接口被限流（与真断网区分）；
// hasUpdate/latestVersion/releaseUrl 供前端展示与跳转。
func (s *Server) handleUpdateCheck(c *gin.Context) {
	cfg := s.deps.Config.Snapshot()
	manifestURL := strings.TrimSpace(cfg.Update.ManifestURL)
	releaseURL := strings.TrimSpace(cfg.Update.ReleaseURL)

	// 当前版本信息来自 version 包（构建脚本 gen.go 经 init() 注入 Version / BuildTime）。
	v := version.Load()

	// 基础响应骨架（默认值：无更新、非网络错误、非限流）。
	baseResp := func() gin.H {
		return gin.H{
			"currentVersion": v.Version,
			"latestVersion":  "",
			"hasUpdate":      false,
			"configured":     true,
			"networkError":   false,
			"rateLimited":    false,
			"checked":        false,
			"releaseUrl":     releaseURL,
			"buildTime":      v.BuildTime,
			"officialUrl":    v.OfficialURL,
		}
	}

	// 命中缓存（30 分钟内有效）直接返回，避免重复外联。
	// 手动「检查更新」按钮携带 force=1 时跳过缓存强制重新检测，保证断网/限流后用户点按钮能立刻重试。
	force := c.Query("force") == "1"
	if !force {
		if cached := updateCheckStore.get(); cached != nil {
			if releaseURL != "" {
				// 用户若在缓存有效期内改了配置里的 ReleaseURL，以当前配置为准覆盖。
				cached["releaseUrl"] = releaseURL
			}
			respondOK(c, cached)
			return
		}
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	var (
		latest      string
		url         string
		desc        string
		err         error
		rateLimited bool
		resetAt     time.Time
	)
	if manifestURL != "" {
		// 自托管清单优先（满足不依赖 GitHub 的私有部署）。
		// 清单地址由用户填写，与其它「目标由用户指定」的出站一视同仁，受内网防护开关约束。
		latest, url, desc, err = fetchManifest(ctx, manifestURL, cfg.Settings.Security.BlockPrivateNetwork)
	} else {
		// 回退到 GitHub 仓库检测（仓库可配置，默认 ovoene/Mantou）。
		latest, url, rateLimited, resetAt, err = fetchGitHubLatestVersion(ctx, githubRepoOf(cfg))
	}
	if err != nil {
		// 网络无法连接：前端以暗黄加粗「当前网络不可用」展示，不报错。
		// 该状态【不缓存】：网络不可用是瞬态，用户随后点「检查更新」必须立即重连检测，
		// 不能被 30 分钟缓存挡住（否则点了也没反应，与需求「网络不可用点击按钮后立马重新立即检查」相悖）。
		resp := baseResp()
		resp["networkError"] = true
		respondOK(c, resp)
		return
	}
	// GitHub 限流：latest 为空但 rateLimited=true（403 + X-RateLimit-Remaining=0）。
	// 必须在 latest=="" 之前判断，否则限流会被误判为「无更新/当前版本最新」，且限流标记与
	// retryAfterSec 被丢弃、前端「限流请稍后再试」分支永不触发。限流结果带标记缓存：
	// 缓存能减少后续请求、避免继续撞限流（与 networkError 的「不缓存」语义不同）。
	if rateLimited {
		resp := baseResp()
		resp["rateLimited"] = true
		if !resetAt.IsZero() {
			resp["retryAfterSec"] = int(time.Until(resetAt).Seconds())
		}
		updateCheckStore.set(resp)
		respondOK(c, resp)
		return
	}
	if latest == "" {
		// 远端未声明任何版本：按「当前版本即最新」展示。
		resp := baseResp()
		updateCheckStore.set(resp)
		respondOK(c, resp)
		return
	}

	// 未单独配置 ReleaseURL 时，以清单/GitHub 返回的下载页为准。
	resp := baseResp()
	if url != "" && releaseURL == "" {
		resp["releaseUrl"] = url
	}
	if desc != "" {
		resp["description"] = desc
	}
	resp["latestVersion"] = latest
	resp["checked"] = true
	resp["hasUpdate"] = versionGreater(latest, v.Version)
	updateCheckStore.set(resp)
	respondOK(c, resp)
}

// defaultGitHubRepo 版本检测的出厂仓库。
const defaultGitHubRepo = "ovoene/Mantou"

// githubRepoPattern 仓库标识的合法形状：owner/name。
//
// 两段都要求以字母或数字开头，因此 "."、".." 这类段名被直接排除——这正是必须校验的原因：
// 这个值会被拼进 "https://api.github.com/repos/" + repo + "/releases/latest"，
// 而 URL 里的 ".." 由服务端（GitHub）解析，填 "../../users/someone" 就能把这次请求
// 挪到另一个接口上，再把它返回的 html_url 当作"新版本下载页"显示在面板里。
// 主机名换不掉（authority 早已闭合），但"面板给出的下载链接指向哪"是可以被改的。
//
// 字符集取 GitHub 实际允许的：owner 用字母数字与连字符，仓库名另允许下划线与点。
// 一律不含 "/"、"?"、"#"、"@"、"%"，所以拼出来的 URL 结构不可能被改写。
var githubRepoPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,63}/[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)

// validGitHubRepo 判断一个仓库标识能否安全地拼进 GitHub API 地址。空串表示"未配置"，不算合法值。
func validGitHubRepo(repo string) bool {
	return githubRepoPattern.MatchString(repo)
}

// validGitHubRepoField 判断「项目仓库」这一项填的内容能否接受。
//
// 两种写法都收：owner/name，或一个完整的 http(s) 地址——后者是前端已有的用法，
// 界面上那个仓库图标会直接把它当项目主页链接用（见 web/src/views/About.vue 的 repoUrl）。
// 限定 scheme 是顺手的一道：这个值会变成页面上的 href，不该允许出现别的协议。
func validGitHubRepoField(raw string) bool {
	if validGitHubRepo(raw) {
		return true
	}
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// repoFromGitHubURL 从 https://github.com/owner/name[/...] 里取出 owner/name。
//
// 只认 github.com 一个主机：换成别的站点，它的路径与 api.github.com 上的仓库路径就没有
// 对应关系了，猜一个出来只会让版本检测查到一个不相干的仓库。
func repoFromGitHubURL(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	if h := strings.ToLower(u.Hostname()); h != "github.com" && h != "www.github.com" {
		return "", false
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 {
		return "", false
	}
	repo := parts[0] + "/" + strings.TrimSuffix(parts[1], ".git")
	if !validGitHubRepo(repo) {
		return "", false
	}
	return repo, true
}

// githubRepoOf 返回用于版本检测的 GitHub 仓库（owner/name）。
// 来自配置 Update.GitHubRepo，留空默认 ovoene/Mantou（恢复自动检测，但仓库可配置、不写死）。
//
// 形状不合法时退回默认值，而不是照原样拼进 URL。写入接口已经拦了一道（见 api_overview.go
// 的 GitHubRepo 分支），这里再拦是因为配置未必经过那道闸：手改 config.json、导入一份别处的
// 备份都能把任意字符串放进这个字段。校验放在"使用点"才真正覆盖所有来源。
//
// 填成完整 github.com 地址的（前端支持的另一种写法）从里面把 owner/name 抽出来用，
// 而不是当成不合法：否则界面上的仓库链接指向用户填的那个仓库、版本检测却在查默认仓库，
// 两处对不上。
func githubRepoOf(cfg *config.Config) string {
	raw := strings.TrimSpace(cfg.Update.GitHubRepo)
	if validGitHubRepo(raw) {
		return raw
	}
	if repo, ok := repoFromGitHubURL(raw); ok {
		return repo
	}
	return defaultGitHubRepo
}

// handleVersion 直接返回 version 包的内容（版本号、官网地址、编译时间）；
// 供前端「关于」页读取展示。编译时间由构建脚本写入，未构建则为空。
func (s *Server) handleVersion(c *gin.Context) {
	v := version.Load()
	respondOK(c, gin.H{
		"version":     v.Version,
		"officialUrl": v.OfficialURL,
		"buildTime":   v.BuildTime,
		"os":          v.OS,
		"arch":        v.Arch,
	})
}

// updateCheckStore 缓存版本检测结果，避免重复外联清单地址（清单源由 Update.ManifestURL 配置）。
// 缓存有效期 30 分钟（updateCheckCacheTTL）；命中且在有效期内直接返回，不复访网络。
// 进程级单例（单一二进制运行一个服务），进程重启后失效，首查仍会联网一次。
type updateCheckCache struct {
	mu        sync.Mutex
	expiresAt time.Time
	resp      gin.H
}

var updateCheckStore = &updateCheckCache{}

// updateCheckCacheTTL 版本检测结果缓存时长。
const updateCheckCacheTTL = 30 * time.Minute

// get 返回未过期的缓存副本（命中返回浅拷贝，避免调用方修改污染缓存）；未命中返回 nil。
func (c *updateCheckCache) get() gin.H {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Now().Before(c.expiresAt) && c.resp != nil {
		out := make(gin.H, len(c.resp))
		for k, val := range c.resp {
			out[k] = val
		}
		return out
	}
	return nil
}

// set 写入缓存并刷新过期时间。
func (c *updateCheckCache) set(resp gin.H) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resp = resp
	c.expiresAt = time.Now().Add(updateCheckCacheTTL)
}

// fetchManifest 从可配置的清单地址（Update.ManifestURL）拉取版本清单。
// 清单为 JSON：{ "version": "...", "url": "...", "description": "..." }。
// 仅当配置了 ManifestURL 时才调用；返回规范化版本号、下载页地址与描述；err 表示网络/接口异常。
//
// blockPrivate 即「内网防护」开关（Settings.Security.BlockPrivateNetwork）。清单地址完全由
// 用户填写，与「动态域名从 URL 取址」「计划任务 HTTP 动作」「消息目标」同属一类出站，
// 因此必须和它们走同一个受管客户端——否则开关打开后其余三条路被堵上，
// 「检查更新」这条路照样能打内网，开关就给了用户一个不成立的承诺。
func fetchManifest(ctx context.Context, manifestURL string, blockPrivate bool) (ver, releaseURL, desc string, err error) {
	if manifestURL == "" {
		return "", "", "", fmt.Errorf("未配置清单地址")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURL, nil)
	if err != nil {
		return "", "", "", err
	}
	req.Header.Set("User-Agent", "mantou")
	client := netguard.HTTPClient(blockPrivate, 10*time.Second)
	res, err := client.Do(req)
	if err != nil {
		return "", "", "", err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return "", "", "", fmt.Errorf("清单接口响应状态 %d", res.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, 256*1024))
	if err != nil {
		return "", "", "", err
	}
	var m struct {
		Version     string `json:"version"`
		URL         string `json:"url"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return "", "", "", err
	}
	return normalizeVersion(strings.TrimSpace(m.Version)), strings.TrimSpace(m.URL), strings.TrimSpace(m.Description), nil
}

// githubRateLimited 根据 GitHub 响应头判断是否因 API 限额被拒（未认证限额 60 次/小时/IP）。
// 仅当状态码为 403 且 X-RateLimit-Remaining=0 时判定为限流；同时解析 X-RateLimit-Reset（Unix 秒）给出可重试时间。
func githubRateLimited(res *http.Response) (bool, time.Time) {
	if res.StatusCode != http.StatusForbidden {
		return false, time.Time{}
	}
	if strings.TrimSpace(res.Header.Get("X-RateLimit-Remaining")) != "0" {
		return false, time.Time{}
	}
	var resetAt time.Time
	if rs := strings.TrimSpace(res.Header.Get("X-RateLimit-Reset")); rs != "" {
		if sec, e := strconv.ParseInt(rs, 10, 64); e == nil {
			resetAt = time.Unix(sec, 0)
		}
	}
	return true, resetAt
}

// fetchGitHubLatestVersion 检查 GitHub 仓库是否有更新版本。
// 优先取「最新 Release」（releases/latest 的 tag_name）；无 Release 时回退到「标签」（tags 第一个）。
// 返回规范化后的版本号（已去掉前导 v/V）、下载页地址；err 表示网络/接口异常，空版本表示远端没有任何版本；
// rateLimited/resetAt 表示是否因 GitHub 限额被拒及可重试时间。
func fetchGitHubLatestVersion(ctx context.Context, repo string) (ver, releaseURL string, rateLimited bool, resetAt time.Time, err error) {
	if tag, url, rl, ra, e := githubLatestRelease(ctx, repo); e == nil {
		if tag != "" {
			return tag, url, false, time.Time{}, nil
		}
		if rl {
			return "", "", true, ra, nil
		}
	} else {
		return "", "", false, time.Time{}, e
	}
	// 无 Release（含 404 或无 Release）则回退到标签。
	return githubLatestTag(ctx, repo)
}

// githubLatestRelease 获取仓库「最新 Release」的版本与下载页。
func githubLatestRelease(ctx context.Context, repo string) (ver, releaseURL string, rateLimited bool, resetAt time.Time, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.github.com/repos/"+repo+"/releases/latest", nil)
	if err != nil {
		return "", "", false, time.Time{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "mantou") // GitHub API 要求 UA，否则 403
	client := &http.Client{Timeout: 10 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return "", "", false, time.Time{}, err
	}
	defer res.Body.Close()

	// 限流优先判断：403 + Remaining=0 视为 GitHub 接口限额，而非通用错误。
	if rl, ra := githubRateLimited(res); rl {
		return "", "", true, ra, nil
	}
	if res.StatusCode == http.StatusNotFound {
		return "", "", false, time.Time{}, nil // 无 Release 不算错误，交由标签兜底
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return "", "", false, time.Time{}, fmt.Errorf("GitHub releases 响应状态 %d", res.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, 256*1024))
	if err != nil {
		return "", "", false, time.Time{}, err
	}
	var m struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return "", "", false, time.Time{}, err
	}
	if strings.TrimSpace(m.TagName) == "" {
		return "", "", false, time.Time{}, nil
	}
	return normalizeVersion(m.TagName), m.HTMLURL, false, time.Time{}, nil
}

// githubLatestTag 获取仓库「标签」列表中的第一个（通常即最新）版本与下载页。
func githubLatestTag(ctx context.Context, repo string) (ver, releaseURL string, rateLimited bool, resetAt time.Time, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.github.com/repos/"+repo+"/tags", nil)
	if err != nil {
		return "", "", false, time.Time{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "mantou")
	client := &http.Client{Timeout: 10 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return "", "", false, time.Time{}, err
	}
	defer res.Body.Close()

	// 限流优先判断：复用同一套 403 + Remaining=0 判定。
	if rl, ra := githubRateLimited(res); rl {
		return "", "", true, ra, nil
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return "", "", false, time.Time{}, fmt.Errorf("GitHub tags 响应状态 %d", res.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, 256*1024))
	if err != nil {
		return "", "", false, time.Time{}, err
	}
	var tags []struct {
		Name    string `json:"name"`
		HTMLURL string `json:"html_url"`
	}
	if err := json.Unmarshal(data, &tags); err != nil {
		return "", "", false, time.Time{}, err
	}
	if len(tags) == 0 {
		return "", "", false, time.Time{}, nil
	}
	if strings.TrimSpace(tags[0].Name) == "" {
		return "", "", false, time.Time{}, nil
	}
	return normalizeVersion(tags[0].Name), tags[0].HTMLURL, false, time.Time{}, nil
}

// versionGreater 判断 latest 是否比 current 新。
// 去除前导 v/V，按点分段做数值比较；非数值段回退到字符串比较；无法解析时按不相等即认为有更新。
func versionGreater(latest, current string) bool {
	l := normalizeVersion(latest)
	c := normalizeVersion(current)
	if l == "" {
		return false
	}
	if c == "" {
		// 运行版本未知（如开发构建），有清单版本即提示更新。
		return true
	}
	if l == c {
		return false
	}
	ls := strings.Split(l, ".")
	cs := strings.Split(c, ".")
	n := len(ls)
	if len(cs) > n {
		n = len(cs)
	}
	for i := 0; i < n; i++ {
		var lv, cv string
		if i < len(ls) {
			lv = ls[i]
		}
		if i < len(cs) {
			cv = cs[i]
		}
		ln, lok := atoiSafe(lv)
		cn, cok := atoiSafe(cv)
		if lok && cok {
			if ln != cn {
				return ln > cn
			}
			continue
		}
		if lv != cv {
			return lv > cv
		}
	}
	return false
}

// normalizeVersion 去掉前导 v/V 以及「Ver 」这类前缀与首尾空白，便于数值比较。
func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	// 兼容 "Ver x.y.z" 前缀（TrimPrefix("V") 后剩 "er x.y.z"）。
	if strings.HasPrefix(strings.ToLower(v), "er ") {
		v = v[3:]
	}
	v = strings.TrimSpace(v)
	return v
}

// atoiSafe 尝试把字符串解析为非负整数（忽略前导零）。
func atoiSafe(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n, true
}
