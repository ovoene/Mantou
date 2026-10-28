package server

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// 上传更新包之前的密码验证，以及验证通过之后发给这条会话的一次性授权。
//
// 「关于」页的上传按钮每次都先弹密码框，验对了才让人去选文件。验对之后这里给这条会话记一份
// 授权，紧接着的那一次上传用掉它（见 handleSelfUpdate），不论那次上传成败都不能再用。
// 记在服务端、按会话记，理由有二：
//   - 未验签那条路后端本来就要当场验密码。授权只记在前端的话，前端就得把密码揣到用户选完
//     文件、点完确认为止，再随上传交一遍——把口令留在页面里，比在服务端留一个一次性标记糟。
//   - 按会话记：别的浏览器、别的会话不沾这次验证的光。改密码会换发会话令牌（见
//     rotateCurrentSession），没用掉的授权随旧令牌一起作废。
//
// 用一次就作废，而不是给一段时间窗：时间窗里一条被盗的会话（或同源页面里的一段恶意脚本）
// 不需要密码就能连着换掉二进制；一次性授权最多只够一次，而那一次正是用户自己要做的。
//
// updateAuthTTL 只是「验过却没用掉」的授权的存活上限——用户验完密码、在选文件时取消了，
// 这份授权不该一直挂在那里等人来用。它要够用户从容地选文件、看确认框，过期了前端会再问一次密码。
//
// 配了签名公钥的上传，后端照旧不要求这份授权——签名本身即授权（见 TestSelfUpdateSignedSkipsPassword
// 上那段关于自动化推包的说明）；但手上有的话同样会被那次上传用掉，不留着。
// 按钮上那道密码框对两条路一视同仁，那是界面层的确认。

// updateAuthTTL 一次性授权从验证那一刻起的存活上限。
const updateAuthTTL = 5 * time.Minute

// updateAuthGrants 各会话手上的一次性授权及其截止时刻，键与复核失败计数是同一个（见 reauthKey）。
//
// 一条会话同一时刻至多一份：再验一次就覆盖掉没用掉的那份，而不是攒起来。
//
// 零值可用：本包的测试大多用 &Server{deps: …} 手拼壳子、不经过 New，
// 与 reauth() 惰性建计数器是同一个考虑。
type updateAuthGrants struct {
	mu    sync.Mutex
	until map[string]time.Time
}

// grant 给 key 发一份从 now 起有效的授权（覆盖它手上没用掉的那份），返回截止时刻。
//
// 顺手清掉已过期的条目：验过却没上传的会话不会有人来删它们，这张表只在这里收缩。
// 只有验对了密码才会走到这里，所以表的大小以「最近几分钟里验过密码的会话数」为上界。
func (g *updateAuthGrants) grant(key string, now time.Time) time.Time {
	g.mu.Lock()
	defer g.mu.Unlock()
	for k, t := range g.until {
		if !now.Before(t) {
			delete(g.until, k)
		}
	}
	if g.until == nil {
		g.until = make(map[string]time.Time)
	}
	until := now.Add(updateAuthTTL)
	g.until[key] = until
	return until
}

// consume 取走 key 手上的授权：有且没过期返回 true。不论结果如何，这份授权从此作废。
//
// 「查一下」与「作废」在同一把锁里做完：两个并发上传拿着同一条会话，至多一个能用上它。
func (g *updateAuthGrants) consume(key string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	until, ok := g.until[key]
	if !ok {
		return false
	}
	delete(g.until, key)
	return now.Before(until)
}

// selfUpdateAuthReq 上传前的密码验证请求。账户名由前端取当前登录账户填上，与加密导出同款。
type selfUpdateAuthReq struct {
	Account  string `json:"account"`
	Password string `json:"password"`
}

// handleSelfUpdateAuth 上传更新包之前验一次当前密码，通过则给这条会话发一份一次性授权。
//
// 回给前端的 expiresIn 是这份授权还剩几秒：前端据此判断用户选文件、看确认框的工夫里
// 它是不是已经过期，过期了就先再验一次密码，而不是传上来才收一个 403。
//
// 失败计数与其余几处「已登录后再验一次密码」共用（见 reauth.go）：这同样是一条拿着会话
// 就能反复猜当前密码的路，而猜中的收益是那几处里最大的一项——换掉面板二进制。
func (s *Server) handleSelfUpdateAuth(c *gin.Context) {
	if !s.reauthAllowed(c) {
		return
	}
	defer s.reauthDone(c)
	var req selfUpdateAuthReq
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "请求参数无效")
		return
	}
	cfg := s.deps.Config.Snapshot()
	if !adminCredentialsOK(cfg.Auth, req.Account, req.Password) {
		s.reauthFail(c)
		s.deps.Log.Warn("自更新：上传前的密码验证失败", "operator", operator(c), "ip", c.ClientIP())
		// 403 而非 401：会话是好的，只是这次密码没对上，不该被前端拦截器踢回登录页。
		respondError(c, http.StatusForbidden, "密码不正确")
		return
	}
	s.reauthOK(c)
	now := time.Now()
	until := s.updateAuth.grant(s.reauthKey(c), now)
	s.deps.Log.Info("自更新：上传前的密码验证通过，已发放一次性授权", "operator", operator(c), "ip", c.ClientIP(),
		"validFor", updateAuthTTL.String())
	respondOK(c, gin.H{"expiresIn": int(until.Sub(now) / time.Second)})
}
