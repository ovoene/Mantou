package server

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"mantou/internal/auth"
	"mantou/internal/config"
	"mantou/internal/strutil"

	"github.com/gin-gonic/gin"
)

// 更新包体积上限。实测（go build -trimpath -ldflags "-s -w"）单个 linux/amd64 二进制
// 约 13.6MB、gzip 后约 5.1MB，故：
//   - maxUpdatePackageBytes（压缩态，32MB）留出 6 倍余量；原值 200MB 纯属虚高，
//     却让任何已认证请求都能一次性占掉数百 MB 的内存与磁盘。
//   - maxUpdateEntryBytes（解压态，64MB）用于防压缩炸弹：gzip 对高度可压缩数据
//     可达 1000:1 以上，若不限制单条目解压体积，几 MB 的包即可写满磁盘。
//   - 签名文件仅 64 字节（Ed25519），4KB 上限足够且能挡住伪造的超大 .sig。
const (
	maxUpdatePackageBytes   = 32 << 20
	maxUpdateEntryBytes     = 64 << 20
	maxUpdateSignatureBytes = 4 << 10
	// maxUpdateEntries 允许扫描的 tar 条目数上限。压缩态上限管不住条目**数量**：
	// gzip 对高度重复的 tar 头压缩比极高，几 MB 的包可以展开成数百万条空条目，
	// 于是解析头部本身就成了 CPU 消耗攻击（不落盘，因此体积上限不会触发）。
	// 正常更新包只有 1–3 个条目，4096 已是极宽松的余量。
	maxUpdateEntries = 4096
	// updateSmokeTestTimeout 候选二进制 `-version` 冒烟测试的超时。
	updateSmokeTestTimeout = 20 * time.Second
)

// errUpdateTooLarge 表示上传或解压的数据超出允许体积。
var errUpdateTooLarge = errors.New("数据超出允许体积上限")

// unsignedUpdateBlocked 判断当前配置下该不该接收更新包，并给出拒收时对用户说的那句话。
//
// 配了公钥就一律放行到验签那一步（签名本身即授权）；没配公钥则要求「允许未验签的更新包」
// 处在有效窗口内（见 config.UpdateConfig.UnsignedUpdateAllowed）。窗口过期与从未打开
// 分开措辞：两者的下一步动作不同，一个是"去打开"，一个是"再打开一次"。
//
// 抽成函数是为了能在任何平台上测到：handleSelfUpdate 在 Windows 上第一行就返回 501，
// 判断留在里面的话本机跑不到。now 从参数进来，好让过期这一支不必真的等一天。
func unsignedUpdateBlocked(u config.UpdateConfig, now time.Time) (bool, string) {
	if strings.TrimSpace(u.SignKey) != "" {
		return false, ""
	}
	if u.UnsignedUpdateAllowed(now) {
		return false, ""
	}
	if u.AllowUnsignedUpdate && u.AllowUnsignedSince > 0 {
		return true, fmt.Sprintf("「允许未验签的更新包」已超过 %d 小时有效期，当前不接收更新包。"+
			"请在「设置 → 在线更新」重新打开它（需再次验证密码），或配置更新包签名公钥",
			int(config.AllowUnsignedUpdateTTL/time.Hour))
	}
	return true, "未配置更新包签名公钥，当前不接收更新包。可在「设置 → 在线更新」配置公钥，或打开「允许未验签的更新包」"
}

// adminCredentialsOK 报告一对账户名/密码是否对得上配置里的管理员凭据，
// 供「敏感操作要当场再验一次密码」的几处复核共用（打开未验签开关、上传未验签的更新包）。
//
// 账户名 TrimSpace 后比较、密码原样交给 bcrypt：前者是用户在输入框里打出来的名字，
// 首尾空格几乎总是误触；后者的空格是密码的一部分，碰不得。
//
// 单独一个函数而不是在两处各写一遍那个表达式：一是两处必须同口径——某天这里加一条
// 「账户名不区分大小写」而另一处没跟上，就会出现一条路放行另一条拒绝；二是能测——
// handleSelfUpdate 在 Windows 上第一行就返回 501，那条路上的复核在本机跑不到。
//
// 配置尚未初始化（用户名与哈希都是空串）时一律为假：VerifyPassword 拿空哈希验不过。
func adminCredentialsOK(a config.Auth, account, password string) bool {
	return strings.TrimSpace(account) == a.Username && auth.VerifyPassword(a.PasswordHash, password)
}

// operator 返回当前请求的操作者名，供审计记录使用。
//
// 鉴权中间件把它放进上下文（middleware.go 里的 c.Set("username", …)），所以到得了处理器
// 的请求一定有这个值。留一个占位是给直接构造 gin.Context 的测试与将来可能的内部调用：
// 审计记录宁可写"未知"，也不要因为少一个字段而整条不写。
func operator(c *gin.Context) string {
	if name := c.GetString("username"); name != "" {
		return name
	}
	return "(未知)"
}

// updateAuditRecord 组装「即将覆盖二进制」那一条审计记录：返回该用 Warn 还是 Info、
// 消息本身，以及结构化字段。
//
// 抽成函数只为一件事——能测。走到调用它的那一行需要一个真能跑起来的同架构二进制
// 和一次真的文件覆盖，单元测试里做不到；而这条记录少任何一项，都要等到某次事后
// 排查时才会发现"当初没记下来"。
//
// sigState 只有 "verified" 与 "unsigned" 两种取值，后者用 Warn：那是一次主动放宽，
// 在日志里该比常规记录显眼一点。
func updateAuditRecord(operatorName, ip, exeName, digest, sigState, arch string) (bool, string, []any) {
	args := []any{
		"exe", exeName, "operator", operatorName, "ip", ip,
		"sha256", digest, "signature", sigState, "arch", arch,
	}
	if sigState == updateSigVerified {
		return false, "自更新：更新包已通过签名校验，准备覆盖", args
	}
	return true, "自更新：按「允许未验签的更新包」放行一个未验签的更新包，准备覆盖", args
}

// 审计记录里 signature 字段的两种取值。
const (
	updateSigVerified = "verified"
	updateSigUnsigned = "unsigned"
)

// handleSelfUpdate 接收上传的 tar.gz 更新包，就地替换当前可执行文件后重启。
// 流程：流式解包 → 定位包内同名可执行文件 → 架构校验 → 签名校验 → `-version` 冒烟测试 →
// 备份现有二进制 → 原子 rename 覆盖 → 覆盖后复检（失败则自动回滚）→ 延时以新二进制重启。
// 仅在非 Windows 平台生效（Windows 无法替换正在运行的可执行文件）。
func (s *Server) handleSelfUpdate(c *gin.Context) {
	if runtime.GOOS == "windows" {
		respondError(c, http.StatusNotImplemented, "Windows 平台不支持在线覆盖更新，请手动替换后重启")
		return
	}

	cfg := s.deps.Config.Snapshot()
	signKey := strings.TrimSpace(cfg.Update.SignKey)

	// 没配签名公钥时默认不接收更新包。
	//
	// 往这里传一个 tar.gz，结果是面板拿一个新二进制把自己换掉。没有验签，
	// 就没有任何环节能分辨那个包是不是用户自己的——这条路径让一个被盗的会话
	// 不需要 shell 就能换掉机器上的程序。
	//
	// 也不能一禁了之：自己生成密钥、给 tar.gz 签名，不是这个项目对用户的要求，
	// 那样等于把一个能用的功能删掉。所以留「允许未验签的更新包」这个开关
	//（设置 → 在线更新），默认关闭、打开要验密码、且只在一段窗口内有效。
	//
	// 这一判在读请求体之前：拒收就不该先把几十 MB 收下来。
	if blocked, msg := unsignedUpdateBlocked(cfg.Update, time.Now()); blocked {
		respondError(c, http.StatusForbidden, msg)
		return
	}

	// 未验签这条路下面要再验一次当前密码，那次校验与导出/导入/改账户共用一份失败计数
	//（见 reauth.go）：都是"拿一条已有会话反复猜当前密码"，只限其中几条等于没限。
	//
	// 只在 signKey == "" 时取这道闸：配了公钥的上传根本不问密码，不该被别处的密码失败连坐。
	//
	// 位置与上面那一判同侧、都在读请求体之前：一条已经被锁住的会话不该先把 32 MB 传完再被拒。
	if signKey == "" && !s.reauthAllowed(c) {
		return
	}

	// 先按 Content-Length 早退，避免把明显超限的请求体读进来才拒绝。
	// multipart 封装本身有额外开销，故留 1MB 余量；真正的硬限制由 cappedReader 在读取时执行。
	if c.Request.ContentLength > maxUpdatePackageBytes+(1<<20) {
		respondError(c, http.StatusBadRequest,
			fmt.Sprintf("更新包大小无效（需 ≤ %dMB）", maxUpdatePackageBytes>>20))
		return
	}

	// 更新包最大 32 MB，之后还要解压、验签、跑一次冒烟测试并原子替换二进制；
	// 这条链路的正常耗时远超面板全局 ReadTimeout / WriteTimeout，逐请求放宽。
	s.extendRequestDeadlines(c, 30*time.Minute)

	exePath, err := os.Executable()
	if err != nil {
		respondError(c, http.StatusInternalServerError, "无法定位当前可执行文件")
		return
	}
	exePath, _ = filepath.EvalSymlinks(exePath)
	exeDir := filepath.Dir(exePath)
	exeName := filepath.Base(exePath)

	// 未验签这条路上顺带收下 account / password 两个表单字段，用于下面的二次认证。
	// 它们必须排在 file 之前（见 multipartFilePartFields），前端按这个顺序 append。
	var acct, pwd string
	want := map[string]*string{"account": &acct, "password": &pwd}
	part, err := multipartFilePartFields(c.Request, want)
	if err != nil {
		respondError(c, http.StatusBadRequest, err.Error())
		return
	}
	defer part.Close()

	// 未验签这条路要求当场再验一次管理员密码。
	//
	// 为什么只在这一支要：配了公钥时，签名本身就是授权——拿不到私钥的人做不出能通过的包，
	// 再问一次密码只是给用户添一道手续。而未验签时"包是谁做的"无从判断，唯一还能问的
	// 就是"传它的人是不是本人"。这道口子的后果是执行任意二进制，与导出/导入备份同级，
	// 因此用同一套做法（见 handleExportConfig）。
	//
	// 它也不与设置页那次验证重复：那一次证明的是"打开这个开关的人是本人"，
	// 这一次证明的是"此刻上传这个包的人是本人"。开关一开就有一整段窗口，
	// 窗口里的每一次上传都得自己过这一关，否则窗口期内一条被盗的会话照样能换掉二进制。
	if signKey == "" {
		if !adminCredentialsOK(cfg.Auth, acct, pwd) {
			s.reauthFail(c)
			// 403 而非 401：前端响应拦截器收到 401 会强制登出跳登录页，
			// 而这里只是本次操作的凭据没对上，应当停在当前页提示。
			s.deps.Log.Warn("自更新：未验签上传的身份复核失败，已拒绝",
				"exe", exeName, "operator", operator(c), "ip", c.ClientIP())
			respondError(c, http.StatusForbidden, "账户或密码错误，未验签的更新包已拒绝")
			return
		}
		s.reauthOK(c)
	}

	s.deps.Log.Info("收到自更新请求", "exe", exeName, "declaredSize", c.Request.ContentLength,
		"operator", operator(c), "ip", c.ClientIP())

	// 解包到与目标同目录的临时文件（保证 rename 为同一文件系统上的原子操作）。
	tmpPath := filepath.Join(exeDir, "."+exeName+".update-"+time.Now().Format("20060102150405"))
	// 仅在配置了签名公钥时才提取 .sig：未配置时不需要它，且可让解包在取到二进制后立即停止。
	sigPath := ""
	if signKey != "" {
		sigPath = tmpPath + ".sig"
		defer os.Remove(sigPath)
	}
	if err := extractExecutable(newCappedReader(part, maxUpdatePackageBytes), exeName, tmpPath, sigPath); err != nil {
		_ = os.Remove(tmpPath)
		respondError(c, http.StatusBadRequest, "更新包解析失败："+err.Error())
		return
	}

	// 架构校验：解析包内二进制的 ELF 头，确认其 GOARCH 与当前运行进程一致。
	// 不一致（如向 x86_64 宿主上传了 arm64 包）直接拒绝，避免用错架构二进制覆盖自身。
	pkgArch, err := detectBinaryArch(tmpPath)
	if err != nil {
		_ = os.Remove(tmpPath)
		respondError(c, http.StatusBadRequest, "无法识别更新包架构："+err.Error())
		return
	}
	if pkgArch != runtime.GOARCH {
		_ = os.Remove(tmpPath)
		respondError(c, http.StatusBadRequest,
			fmt.Sprintf("更新包架构（%s）与当前系统架构（%s）不匹配，请重新上传正确的更新包", pkgArch, runtime.GOARCH))
		return
	}

	// 完整性 / 真实性校验：若配置了更新签名公钥（Update.SignKey），则要求更新包内附同名
	// .sig 签名文件，验签通过才允许覆盖，避免程序二进制被未授权替换。
	// 走到 else 分支说明用户在设置里显式打开了「允许未验签的更新包」且窗口未过期
	//（否则前面已经拒了），并且刚刚过了一次密码复核。
	sigState := updateSigUnsigned
	if signKey != "" {
		if err := verifyUpdateSignature(signKey, tmpPath, sigPath); err != nil {
			_ = os.Remove(tmpPath)
			s.deps.Log.Warn("自更新：更新包签名校验失败，已拒绝",
				"exe", exeName, "operator", operator(c), "ip", c.ClientIP(), "err", err.Error())
			respondError(c, http.StatusBadRequest, "更新包签名校验失败："+err.Error())
			return
		}
		sigState = updateSigVerified
	}

	// 审计记录：这一步的结果是换掉正在跑的二进制，一条日志要能独立回答
	// 「谁、从哪、装了什么、验没验签」四个问题——事后翻日志的人手上只有这一行。
	//
	// 摘要取解包出来的二进制而不是上传的 tar.gz：包体是流式消费的，留不下来；
	// 而这个摘要对得上一份发布产物的 sha256sum，也正是真正被执行的那串字节。
	sum, sumErr := sha256File(tmpPath)
	digest := "(计算失败)"
	if sumErr == nil {
		digest = hex.EncodeToString(sum[:])
	}
	warn, auditMsg, auditArgs := updateAuditRecord(operator(c), c.ClientIP(), exeName, digest, sigState, pkgArch)
	if warn {
		s.deps.Log.Warn(auditMsg, auditArgs...)
	} else {
		s.deps.Log.Info(auditMsg, auditArgs...)
	}

	// 保留原文件权限（默认可执行）。
	mode := os.FileMode(0o755)
	if fi, statErr := os.Stat(exePath); statErr == nil {
		mode = fi.Mode().Perm() | 0o100
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		_ = os.Remove(tmpPath)
		respondError(c, http.StatusInternalServerError, "设置更新文件权限失败："+err.Error())
		return
	}

	// 覆盖前冒烟测试：包完整、架构匹配、签名正确的二进制仍可能根本跑不起来
	//（交叉编译时链接了宿主 glibc、被中间设备截断、误传了同架构的其它程序……）。
	// 一旦这种二进制覆盖上去，面板将无法再启动，而自更新接口本身也随之失效——
	// 用户失去「再上传一个正确包救回来」的唯一途径，只能登机器手动恢复。
	// 因此这里先把候选二进制跑一遍 `-version`，不通过就拒绝覆盖，当前版本毫发无伤。
	if err := smokeTestBinary(tmpPath); err != nil {
		_ = os.Remove(tmpPath)
		s.deps.Log.Warn("自更新：候选二进制冒烟测试失败，已拒绝覆盖", "exe", exeName, "err", err.Error())
		respondError(c, http.StatusBadRequest, "更新包无法正常运行，已拒绝覆盖（当前版本未受影响）："+err.Error())
		return
	}
	s.deps.Log.Info("自更新：候选二进制冒烟测试通过", "exe", exeName)

	// 备份现有二进制，供覆盖后复检失败时自动回滚，也供管理员事后手动回退。
	backupPath := exePath + ".bak"
	if err := backupExecutable(exePath, backupPath); err != nil {
		_ = os.Remove(tmpPath)
		respondError(c, http.StatusInternalServerError, "备份当前可执行文件失败，已中止更新："+err.Error())
		return
	}

	if err := os.Rename(tmpPath, exePath); err != nil {
		_ = os.Remove(tmpPath)
		respondError(c, http.StatusInternalServerError, "替换可执行文件失败，请检查文件权限或磁盘空间")
		return
	}

	// 覆盖后复检：确认落到最终路径上的二进制仍可运行（排除 rename/权限/文件系统层面的意外）。
	// 失败则用备份原子回滚，保证「更新失败也一定能重启回旧版本」。
	if err := smokeTestBinary(exePath); err != nil {
		if rollbackErr := os.Rename(backupPath, exePath); rollbackErr != nil {
			s.deps.Log.Error("自更新：覆盖后复检失败且自动回滚失败，请手动恢复",
				"verify", err.Error(), "rollback", rollbackErr.Error(), "backup", backupPath)
			respondError(c, http.StatusInternalServerError,
				"更新后复检失败且自动回滚失败，请手动用备份文件 "+backupPath+" 恢复："+err.Error())
			return
		}
		s.deps.Log.Error("自更新：覆盖后复检失败，已自动回滚到更新前版本", "err", err.Error())
		respondError(c, http.StatusInternalServerError, "更新后复检失败，已自动回滚到更新前版本："+err.Error())
		return
	}

	s.deps.Log.Info("自更新：可执行文件已替换，更新前版本已备份",
		"exe", exeName, "backup", backupPath, "operator", operator(c), "ip", c.ClientIP())
	respondOK(c, gin.H{"ok": true, "restarting": true, "backup": backupPath})

	// 延时：给响应留出回写时间，随后用新二进制替换当前进程映像，
	// 实现「无需外部守护进程也能自动重启到新版本」（本地直接运行 / Docker 无 restart 策略也能生效）。
	// 若 RestartExec 未注入或不支持，回退为 os.Exit(0) 交由外部守护拉起。
	exe := exePath
	go func() {
		time.Sleep(1500 * time.Millisecond)
		s.deps.Log.Info("已应用上传的更新包，进程即将以新二进制重启")
		if s.deps.RestartExec != nil {
			if err := s.deps.RestartExec(exe); err != nil {
				s.deps.Log.Error("替换进程映像失败，回退为进程退出", "error", err.Error())
			} else {
				return // 成功：进程映像已被新二进制接管，后续代码不再执行
			}
		}
		os.Exit(0)
	}()
}

// smokeTestBinary 以 `-version` 运行候选二进制，验证它至少能被内核加载、正常执行并退出。
// 这是「能不能跑」最廉价的判据：main 在 flag.Parse 后立即打印版本并 os.Exit(0)，
// 不读配置、不监听端口、不触碰数据目录，因此对运行中的实例零副作用。
func smokeTestBinary(path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), updateSmokeTestTimeout)
	defer cancel()
	// 继承当前进程环境：二进制为 CGO_ENABLED=0 的静态可执行文件，本不依赖环境变量，
	// 但保留继承可避免在特殊部署（自定义 loader 路径等）下误判为「无法运行」。
	out, err := exec.CommandContext(ctx, path, "-version").CombinedOutput()
	// 按字符边界截断：-version 的输出正常只有一行，但失败时 CombinedOutput 会带回
	// 运行时/加载器的报错（可能含中文），按字节直接切会产出乱码。
	detail := strutil.Truncate(strings.TrimSpace(string(out)), 200, "…")
	if ctx.Err() != nil {
		return fmt.Errorf("运行 -version 超时（%s）", updateSmokeTestTimeout)
	}
	if err != nil {
		return fmt.Errorf("无法执行（%v）：%s", err, detail)
	}
	// main 的 -version 输出形如 "Mantou Ver x.y.z"；对不上说明这不是本程序的二进制。
	if !strings.Contains(detail, "Mantou") {
		return fmt.Errorf("-version 输出不像本程序：%s", detail)
	}
	return nil
}

// backupExecutable 为当前可执行文件建立备份。优先使用硬链接：与源文件共用同一 inode，
// 零拷贝、瞬时完成，且在 rename 覆盖 exePath 后旧二进制仍通过该链接存活。
// 文件系统不支持硬链接（如部分容器 overlay 跨层、网络盘）时回退为完整复制。
func backupExecutable(exePath, backupPath string) error {
	_ = os.Remove(backupPath) // 清掉上一次更新留下的备份
	if err := os.Link(exePath, backupPath); err == nil {
		return nil
	}
	src, err := os.Open(exePath)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.OpenFile(backupPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		_ = os.Remove(backupPath)
		return err
	}
	return dst.Close()
}

// extractExecutable 从 gzip+tar 流中提取可执行文件写入 binDst；若包内含同名 .sig 签名文件，
// 则一并提取到 sigDst（sigDst 非空时）。仅接受与当前运行二进制「严格同名」的常规文件条目，
// 且同名条目只允许出现一次——出现第二个直接拒绝整个包。
// 正常构建不会产出重复条目，而「后者覆盖前者」会让实际落盘的内容与人工检查包时
// 看到的第一个条目不一致，正是可以用来藏东西的地方。找不到同名条目同样拒绝。
// 条目数受 maxUpdateEntries 限制，单条目解压体积受 maxUpdateEntryBytes /
// maxUpdateSignatureBytes 限制（均为防压缩炸弹），
// 且一旦需要的条目全部取到便立即停止读取——异常包可以在合法条目之后堆放海量填充数据，
// 继续解压只是白耗 CPU 与磁盘。
func extractExecutable(r io.Reader, wantName, binDst, sigDst string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("不是有效的 gzip 包：%w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	binFound, sigFound := false, false
	entries := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			if errors.Is(err, errUpdateTooLarge) {
				return fmt.Errorf("更新包超出体积上限（%dMB）", maxUpdatePackageBytes>>20)
			}
			return fmt.Errorf("读取 tar 失败：%w", err)
		}
		entries++
		if entries > maxUpdateEntries {
			return fmt.Errorf("更新包条目过多（上限 %d 个），拒绝处理", maxUpdateEntries)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		switch filepath.Base(hdr.Name) {
		case wantName:
			if binFound {
				return fmt.Errorf("更新包中存在多个名为 %q 的可执行条目，拒绝处理", wantName)
			}
			if err := writeFile(binDst, tr, maxUpdateEntryBytes); err != nil {
				if errors.Is(err, errUpdateTooLarge) {
					return fmt.Errorf("包内可执行文件超出体积上限（%dMB）", maxUpdateEntryBytes>>20)
				}
				return fmt.Errorf("写入可执行文件失败：%w", err)
			}
			binFound = true
		case wantName + ".sig":
			if sigDst == "" {
				continue
			}
			if sigFound {
				return fmt.Errorf("更新包中存在多个签名条目，拒绝处理")
			}
			if err := writeFile(sigDst, tr, maxUpdateSignatureBytes); err != nil {
				if errors.Is(err, errUpdateTooLarge) {
					return fmt.Errorf("包内签名文件超出体积上限（%dKB）", maxUpdateSignatureBytes>>10)
				}
				return fmt.Errorf("写入签名文件失败：%w", err)
			}
			sigFound = true
		}
		if binFound && (sigFound || sigDst == "") {
			break
		}
	}
	if !binFound {
		return fmt.Errorf("更新包中未找到名为 %q 的可执行文件", wantName)
	}
	return nil
}

// verifyUpdateSignature 校验更新包二进制的 Ed25519 签名。pubKeyB64 为 base64 编码的 32 字节公钥；
// 签名是对「二进制 SHA-256 摘要」的 Ed25519 签名，由 sigPath 指向的文件提供。
func verifyUpdateSignature(pubKeyB64, binPath, sigPath string) error {
	pub, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("签名公钥格式无效")
	}
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("缺少签名文件（.sig）")
	}
	sum, err := sha256File(binPath)
	if err != nil {
		return fmt.Errorf("计算校验和失败: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), sum[:], sig) {
		return fmt.Errorf("签名不匹配")
	}
	return nil
}

// sha256File 以流式方式计算文件 SHA-256 摘要（避免大文件整体载入内存）。
func sha256File(path string) ([32]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return [32]byte{}, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return [32]byte{}, err
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

// detectBinaryArch 读取 Linux ELF 可执行文件头，返回其对应的 Go GOARCH
// （amd64 / arm64 / arm / 386 / riscv64 / loong64 / s390x / ppc64(le) / mips(le) / mips64(le)）。
// 用于上传更新包时校验架构与当前运行的 runtime.GOARCH 是否一致。
// 非 ELF（如 Windows PE / macOS Mach-O / 文本）一律视为「不是有效的 Linux 可执行文件」。
//
// 只手工读头部前 20 字节，不用 debug/elf：elf.NewFile 会连节头表与字符串表一起解析，
// 而这里的输入是任何已认证用户都能上传的文件，让它照着文件里的数字去分配内存不值当。
// 架构判断需要的三个字节全在这 20 字节里。
func detectBinaryArch(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	// ELF 头：magic(4) + EI_CLASS(1) + EI_DATA(1) + EI_VERSION(1) + EI_OSABI(1)
	//        + EI_ABIVERSION(1) + EI_PAD(7) + e_type(2) + e_machine(2) ...
	hdr := make([]byte, 20)
	if _, err := io.ReadFull(f, hdr); err != nil {
		return "", fmt.Errorf("读取文件头失败：%w", err)
	}
	if hdr[0] != 0x7f || hdr[1] != 'E' || hdr[2] != 'L' || hdr[3] != 'F' {
		return "", fmt.Errorf("更新包不是有效的 Linux 可执行文件（期望 ELF 格式）")
	}

	// EI_CLASS(hdr[4])：1=32 位，2=64 位。EI_DATA(hdr[5])：1=小端，2=大端。
	// e_machine 之后的所有多字节字段都按 EI_DATA 声明的字节序存放，原先固定按小端读
	// 是错的：一个真正的 GOARCH=mips 包（大端）里 e_machine 存成 00 08，按小端读出
	// 0x0800，于是在 MIPS 机器上上传正确的包会被判成「无法识别的 CPU 架构」。
	const (
		elfClass64 = 2
		elfLSB     = 1
		elfMSB     = 2
	)
	var machine uint16
	switch hdr[5] {
	case elfLSB:
		machine = binary.LittleEndian.Uint16(hdr[18:20])
	case elfMSB:
		machine = binary.BigEndian.Uint16(hdr[18:20])
	default:
		return "", fmt.Errorf("ELF 头的字节序标记无效（EI_DATA=%d）", hdr[5])
	}
	be := hdr[5] == elfMSB

	// 字节序还要参与命名，不只是用来把 e_machine 读对：Go 给 MIPS 与 PPC64 的大小端
	// 各留了一个独立的 GOARCH（mips/mipsle、ppc64/ppc64le），而 e_machine 两端共用同一个
	// 值，只有 EI_DATA 分得开。若不分，一个小端 MIPS 包会在大端 MIPS 面板上通过这道闸
	// （名字都算成 "mips"），要等后面的冒烟测试以 ENOEXEC 失败才拦下——而这道闸存在的
	// 意义正是提前给出一句说得清的话。
	//
	// 其余架构 Go 只有一个端序的移植（如 arm/arm64 只有小端、s390x 只有大端），
	// 端序不对说明这个包压根没有对应的 Go 目标，宁可报「无法识别」也不猜一个名字。
	switch machine {
	case 0x03: // EM_386
		if !be {
			return "386", nil
		}
	case 0x08: // EM_MIPS：大小端 × 32/64 位共四个 GOARCH
		switch {
		case be && hdr[4] == elfClass64:
			return "mips64", nil
		case be:
			return "mips", nil
		case hdr[4] == elfClass64:
			return "mips64le", nil
		default:
			return "mipsle", nil
		}
	case 0x15: // EM_PPC64
		if be {
			return "ppc64", nil
		}
		return "ppc64le", nil
	case 0x16: // EM_S390：Go 只有大端的 s390x
		if be {
			return "s390x", nil
		}
	case 0x28: // EM_ARM：Go 只有小端 arm
		if !be {
			return "arm", nil
		}
	case 0x3e: // EM_X86_64
		if !be {
			return "amd64", nil
		}
	case 0xb7: // EM_AARCH64：Go 只有小端 arm64
		if !be {
			return "arm64", nil
		}
	case 0xf3: // EM_RISCV
		if !be {
			return "riscv64", nil
		}
	case 0x102: // EM_LOONGARCH
		if !be {
			return "loong64", nil
		}
	}
	// 报错带上字节序：同一个 e_machine 值配错端序也会走到这里，光看数字会以为是别的问题。
	endian := "小端"
	if be {
		endian = "大端"
	}
	return "", fmt.Errorf("无法识别的 CPU 架构（e_machine=0x%04x，%s）", machine, endian)
}

// writeFile 将 r 的内容写入 path（覆盖），单文件体积上限为 limit 字节。
func writeFile(path string, r io.Reader, limit int64) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, newCappedReader(r, limit)); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// cappedReader 在读取超过 limit 字节时返回 errUpdateTooLarge，而不是像 io.LimitReader
// 那样静默截断。静默截断在更新场景里格外危险：它会把「包被截断 / 超限」伪装成
// 「gzip 或 tar 格式错误」，甚至写出一个"看起来完整"的半截二进制。
type cappedReader struct {
	r    io.Reader
	left int64
}

// newCappedReader 允许读取至多 limit 字节。内部多留 1 字节额度用于区分
// 「刚好等于上限」（合法，正常 EOF）与「超出上限」（返回 errUpdateTooLarge）。
func newCappedReader(r io.Reader, limit int64) *cappedReader {
	return &cappedReader{r: r, left: limit + 1}
}

func (c *cappedReader) Read(p []byte) (int, error) {
	if c.left <= 0 {
		return 0, errUpdateTooLarge
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	return n, err
}
