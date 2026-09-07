package server

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

// 本文件是「已经登录了，再把当前密码交一遍」这件事的共享失败计数。
//
// 六条路在做同一件事，理由也一样——光持有一条会话不够，动手之前得证明知道当前密码：
//   - 加密导出（handleExportConfig）
//   - 导入备份前的本机管理员校验（handleImportConfig）
//   - 敏感操作前的预检（handleVerifyIdentity）
//   - 改账户名 / 改密码时的旧密码（handleChangeAccount）
//   - 打开「允许未验签的更新包」那一次提交（handleUpdateSettings）
//   - 未验签的更新包上传（handleSelfUpdate）
//
// 之前这几处都不计数，理由写在 handleVerifyIdentity 上：只给其中一条加限制，攻击者换另一条
// 接着试，界面上却多出一处会把人锁住的地方。那句话的另一半是「真要限，得几处一起限」，
// 本文件就是那一半。少了它，一条被盗的会话可以把 bcrypt 那百毫秒当唯一的减速带，
// 不限次数地猜当前密码——而猜中的收益不是"能进面板"（他已经在里面了），
// 是能改掉登录密码把人锁在门外，导出一份带明文凭证的备份（见 config_crypt.go 文件头），
// 以及后两条那件更彻底的事：把面板二进制换成自己的。
//
// 后两条只在「真的会验密码」那一支上取闸，不是整个处理器：
// 设置接口保存的是整页设置（绝大多数改动不问密码），更新接口配了签名公钥时也不问密码。
//
// 键是**会话**，不是账户名、也不是 IP：
//   - 按账户名或 IP 记，等于把「真正的管理员做不了敏感操作」这件事交给任何能故意失败几次的
//     人；登录那侧的同款取舍写在 handleLogin 的 userKey 上。
//   - 按会话记，被锁的是那条会话自己。攻击者手里只有偷来的 Cookie，他配不出第二条
//     （要换一条得过登录，而那正是他不知道的密码），所以锁得住；真正的管理员知道密码，
//     退出再登一次就是一条新会话、一份干净的计数，对他只是多一次登录。
//
// 也刻意不与登录限流共用计数——那样一条被盗的会话就能把管理员锁在登录页外面。
const (
	// 15 次远在打错字的范围之外（登录那侧默认 5 次），而它把爆破从「bcrypt 能跑多快」
	// 压到每 10 分钟 15 次。
	reauthMaxFails = 15
	reauthWindow   = 10 * time.Minute
	reauthLockFor  = 10 * time.Minute
)

// reauth 取这份共享计数，第一次用到时建。
//
// 参数写死、不接 Auth.LoginMaxFails：那个开关是给「登录锁定」用的，用户把它关掉是不想被
// 锁在门外，不代表要连这一层一起关掉；而 newLoginLimiter 遇到 maxFails ≤ 0 会把整个
// 限流器停掉，真接上去就是"关掉登录锁定 = 顺手关掉这道闸"。
//
// 建在这里而不是 New 里：本包有几十处测试直接用 &Server{deps: …} 拼壳子，New 填的字段
// 它们一个都没有。把创建放在唯一的读取点上，任何构造路径都不可能拿到一个 nil 计数器——
// 换成"方法里判 nil 就放行"则相反：漏填的那条路径会安静地没有限制。
func (s *Server) reauth() *loginLimiter {
	s.reauthOnce.Do(func() {
		if s.reauthLimiter == nil {
			s.reauthLimiter = newLoginLimiter(reauthMaxFails, reauthWindow, reauthLockFor)
		}
	})
	return s.reauthLimiter
}

// reauthKey 取这次请求的计数键：会话令牌的哈希，取不到令牌时退回来源 IP。
//
// 存哈希而不是令牌本身：这张表的键将来可能被谁打进一条日志或一个诊断接口，
// 而令牌是能直接冒充管理员的东西。截前 12 字节（96 位）足够不撞，
// 这里要的也只是「同一条会话映射到同一个键」。
//
// 退路那一支正常走不到（这几条都是已鉴权路由，没有令牌进不来），留着是为了万一
// 以后有谁把这几个函数用到别处，键也不会变成空串——那会让所有来源共用同一个计数。
func (s *Server) reauthKey(c *gin.Context) string {
	if token := s.extractToken(c); token != "" {
		sum := sha256.Sum256([]byte(token))
		return "sess:" + base64.RawURLEncoding.EncodeToString(sum[:12])
	}
	return "ip:" + c.ClientIP()
}

// reauthAllowed 在跑 bcrypt 之前问一次：这条会话还能不能再试。
// 不能就地回 429（带 Retry-After）并返回 false，调用方直接 return。
//
// 429 而不是 401/403：401 会被前端拦截器当成会话失效、把人强制登出，而这里的会话是好的；
// 403 会被读成"密码又错了"，于是用户一直重试，把锁定时间白白耗过去。
func (s *Server) reauthAllowed(c *gin.Context) bool {
	ok, retry := s.reauth().Allowed(s.reauthKey(c))
	if ok {
		return true
	}
	c.Header("Retry-After", strconv.Itoa(retry))
	respondError(c, http.StatusTooManyRequests, "密码验证失败次数过多，请稍后再试")
	return false
}

// reauthFail 记一次失败。各处的调用都贴在各自「密码不对」那一支里，
// 只加计数，不改任何一处原有的状态码与文案。
func (s *Server) reauthFail(c *gin.Context) {
	s.reauth().Fail(s.reauthKey(c))
}

// reauthOK 密码验对了就把这条会话的失败史清掉：一次正确的密码说明持有者是本人，
// 前面那几次多半是打错字。攻击者猜中时当然也会清，但那一刻计数已经不重要了。
func (s *Server) reauthOK(c *gin.Context) {
	s.reauth().Reset(s.reauthKey(c))
}
