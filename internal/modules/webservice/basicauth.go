package webservice

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"sync"
	"time"

	"mantou/internal/auth"
	"mantou/internal/config"
	"mantou/internal/errpage"
)

// 本文件实现 Web 服务子项的 Basic 认证：在反代/静态/重定向之前先要一组账号口令，
// 通过才放行。口令在配置里以 **bcrypt 哈希** 保存（见 config.WebAccess.BasicAuthPass），
// 校验结果带短期缓存。
//
// 为什么非得有缓存：bcrypt 的设计目标就是"算得慢"（默认代价约 50~100ms CPU/次），
// 而 Basic 认证是**每个请求**都重新带凭证的——浏览器打开一个页面就是几十个请求。
// 不缓存的话，一次正常访问就能把一个 CPU 核占满好几秒，站点直接变龟速，
// 且任何人不用登录就能凭"发请求"消耗服务器算力。
//
// 缓存键里含存储的哈希本身，因此改口令会让旧条目自然失效；中间件在每次 Reload 时整体重建，
// 配置一变缓存就被丢弃。
//
// 诚实的边界：失败结果只缓存很短时间，攻击者若每次都换一个**新的**随机口令，
// 仍能迫使服务端每个请求做一次 bcrypt。真正的应对是同一子项上一并开启「请求速率限制」
// （中间件顺序上限流在 Basic 认证之前，见 applyMiddleware），面板的说明文字也这么提示。
const (
	// basicAuthOKTTL 校验通过的缓存有效期。取 5 分钟：足以覆盖一次连续浏览，
	// 又能让"改了口令但还没触发 Reload"的极端情况在可接受时间内收敛。
	basicAuthOKTTL = 5 * time.Minute
	// basicAuthFailTTL 校验失败的缓存有效期，仅用于压制"同一个错口令被反复重试"
	// （浏览器在弹框前后常会重发若干次），故取得很短。
	basicAuthFailTTL = 30 * time.Second
	// basicAuthMaxEntries 缓存条目上限，防止海量不同凭证把内存撑爆。
	basicAuthMaxEntries = 4096
)

// basicAuthEntry 是一条缓存结果。
type basicAuthEntry struct {
	ok  bool
	exp time.Time
	// done 非 nil 表示"这条凭证正在算 bcrypt"：后到的同凭证请求等它关闭后复用结果，
	// 而不是各算一遍。浏览器并发拉取页面内几十个资源时，这一条把 N 次 bcrypt 降为 1 次。
	done chan struct{}
}

// basicAuthCache 缓存 Basic 认证的校验结果，每个子项一份（随中间件创建/销毁）。
type basicAuthCache struct {
	mu      sync.Mutex
	entries map[string]*basicAuthEntry
}

func newBasicAuthCache() *basicAuthCache {
	return &basicAuthCache{entries: make(map[string]*basicAuthEntry)}
}

// verify 返回该凭证是否通过校验：命中未过期缓存则直接返回，否则调用 compute 做真正的比对。
// compute 在锁外执行（bcrypt 耗时），因此不会阻塞其它凭证的查表。
func (c *basicAuthCache) verify(key string, compute func() bool) bool {
	c.mu.Lock()
	for {
		e := c.entries[key]
		if e == nil {
			break
		}
		if e.done != nil {
			// 同一凭证已有请求在算：等结果，醒来后重新查表（正常情况下拿到的就是刚写入的结果；
			// 若那条被清理掉了则由本 goroutine 自己算一次，只是多花一点 CPU，不影响正确性）。
			done := e.done
			c.mu.Unlock()
			<-done
			c.mu.Lock()
			continue
		}
		if time.Now().Before(e.exp) {
			ok := e.ok
			c.mu.Unlock()
			return ok
		}
		break
	}
	pending := &basicAuthEntry{done: make(chan struct{})}
	c.entries[key] = pending
	c.mu.Unlock()

	ok := compute()

	ttl := basicAuthFailTTL
	if ok {
		ttl = basicAuthOKTTL
	}
	c.mu.Lock()
	c.entries[key] = &basicAuthEntry{ok: ok, exp: time.Now().Add(ttl)}
	c.sweepLocked()
	c.mu.Unlock()
	close(pending.done)
	return ok
}

// sweepLocked 在超过条目上限时清理缓存；调用方须持有 c.mu。
// 正在计算中的条目（done != nil）一律保留，否则等待者醒来会白算一遍。
func (c *basicAuthCache) sweepLocked() {
	if len(c.entries) <= basicAuthMaxEntries {
		return
	}
	now := time.Now()
	for k, e := range c.entries {
		if e.done == nil && now.After(e.exp) {
			delete(c.entries, k)
		}
	}
	if len(c.entries) <= basicAuthMaxEntries {
		return
	}
	// 清完过期项仍超限：说明短时间内涌入了海量不同凭证（多半有人在猜口令）。
	// 丢掉失败项，**保住成功项**——后者不丢是因为它几乎不占地方：缓存键由
	// 「请求携带的账号+口令」与「配置里存的哈希」算出（见 basicAuthKey），而一个子项
	// 只有一个账号一个口令，所以每个子项最多留下一条成功项（改口令后旧的那条也只活到
	// basicAuthOKTTL）。反过来把成功项一起丢掉，等于猜口令的人花一批错口令就能让
	// **正常访客的每个请求**都重算一次 bcrypt，而那正是这份缓存要省掉的开销。
	for k, e := range c.entries {
		if e.done == nil && !e.ok {
			delete(c.entries, k)
		}
	}
}

// basicAuthKey 由「请求携带的账号+口令」与「配置里存的哈希」算出缓存键。
// 用摘要而非明文拼接做键有两个实际理由：键长固定（客户端塞一个几 MB 的口令也撑不大缓存），
// 且口令明文不会以 map 键的形式长期驻留内存。
func basicAuthKey(gotUser, gotPass, stored string) string {
	sum := sha256.Sum256([]byte(gotUser + "\x00" + gotPass + "\x00" + stored))
	return hex.EncodeToString(sum[:])
}

// matchBasicCredential 做一次真正的凭证比对。
// 账号用常量时间比较；口令优先按 bcrypt 哈希校验，仅当配置里存的仍是历史明文
// （启动时的一次性迁移还没跑到，例如直接手改了配置文件）时才退回明文比较——
// 这一步存在的唯一目的是保证从旧版本升级时站点不会因为"哈希还没生成"而被整站锁死。
func matchBasicCredential(user, stored string, hashed bool, gotUser, gotPass string) bool {
	if subtle.ConstantTimeCompare([]byte(gotUser), []byte(user)) != 1 {
		return false
	}
	if hashed {
		return auth.VerifyPassword(stored, gotPass)
	}
	return subtle.ConstantTimeCompare([]byte(gotPass), []byte(stored)) == 1
}

// withBasicAuth 实现 HTTP Basic 认证。
//
// 三个前置条件缺一不可：开关已开、账号非空、口令非空。
// 口令为空时刻意**整体跳过**认证而不是"用空口令校验"：后者会弹出认证框却对任何空口令放行，
// 是比不开更糟的假保护。面板与后端校验都不允许保存这种组合，这里只是兜底。
func withBasicAuth(ch config.WebChild, next http.Handler) http.Handler {
	user := ch.Access.BasicAuthUser
	stored := ch.Access.BasicAuthPass
	if !ch.Access.BasicAuth || user == "" || stored == "" {
		return next
	}
	cache := newBasicAuthCache()
	hashed := auth.IsHash(stored)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if ok {
			ok = cache.verify(basicAuthKey(u, p, stored), func() bool {
				return matchBasicCredential(user, stored, hashed, u, p)
			})
		}
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="mantou"`)
			// 带上 WWW-Authenticate 时浏览器先弹自己的账号框，这一页是用户点「取消」
			// 或口令错到放弃之后看到的东西。刻意不说是账号错还是口令错。
			errpage.Write(w, r, errpage.Page{
				Status: http.StatusUnauthorized,
				Title:  "需要登录才能访问",
				Detail: "这个站点开启了访问口令保护。",
				Hint:   "刷新页面重新填写账号与口令；忘记了请找站点管理员。",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}
