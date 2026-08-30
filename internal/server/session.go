package server

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// sessionGrace 是"关闭/信标"软注销的宽限期：在宽限内若同一会话有新的鉴权请求到达
// （典型为刷新页面复用同一 Cookie），会话会被救活；宽限到期仍无活动则真正删除。
// 借宽限期即可区分"刷新页面"（保活）与"关闭最后一个标签"（到期失效）。
const sessionGrace = 5 * time.Second

// sessionSweepInterval 是后台清扫周期：定期移除已过绝对过期时间的会话记录，
// 避免长期运行后「登录过、到期后再没访问过」的记录在内存映射中持续堆积。
const sessionSweepInterval = 10 * time.Minute

// sessionEntry 是单条服务端会话状态。
type sessionEntry struct {
	username        string
	expiresAt       time.Time // 绝对过期时间（与 JWT 有效期一致）
	lastSeenAt      time.Time // 最后一次收到本会话鉴权请求的时刻（闲置超时的起点）
	pendingDeleteAt time.Time // 非零表示已进入"待删除"宽限
}

// sessionRegistry 维护服务端会话状态，使"关闭最后一个标签"可主动失效，
// 而"刷新页面"在宽限内复用同一会话保活。进程级内存存储：重启即全部失效
// （与"关闭即退出"的语义一致，无需持久化）。后台清扫协程随 close() 结束，
// 面板在进程内重启时会新建 registry，旧实例须显式 close 以免协程泄漏。
type sessionRegistry struct {
	mu       sync.RWMutex
	entries  map[string]*sessionEntry
	stop     chan struct{}
	stopOnce sync.Once
}

func newSessionRegistry() *sessionRegistry {
	r := &sessionRegistry{
		entries: make(map[string]*sessionEntry),
		stop:    make(chan struct{}),
	}
	go r.sweepLoop()
	return r
}

// sweepLoop 周期性清理已过期会话，直到 close() 关闭 stop 通道。
//
// 这里只按绝对过期时间清，不看闲置超时：闲置阈值来自配置、随时可改，而清扫协程
// 手里没有配置快照。已闲置超时的条目在下一次 valid() 校验时就会被删掉（那条路
// 一定先于任何使用发生），即使永远没有下一次访问，也仍被绝对过期时间兜住，
// 不会无限堆积。为此把配置访问器注入进 registry，只换来一点内存回收提前，不值当。
func (r *sessionRegistry) sweepLoop() {
	ticker := time.NewTicker(sessionSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-r.stop:
			return
		case now := <-ticker.C:
			r.mu.Lock()
			for k, e := range r.entries {
				if now.After(e.expiresAt) {
					delete(r.entries, k)
				}
			}
			r.mu.Unlock()
		}
	}
}

// close 停止后台清扫协程；可安全多次调用。
func (r *sessionRegistry) close() {
	r.stopOnce.Do(func() { close(r.stop) })
}

// sessionKey 用令牌本身的 SHA-256 作为会话键，避免明文/签名落入内存映射。
func sessionKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// add 注册一个新会话（登录成功时调用）。
func (r *sessionRegistry) add(token, username string, ttl time.Duration) {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[sessionKey(token)] = &sessionEntry{
		username:   username,
		expiresAt:  now.Add(ttl),
		lastSeenAt: now,
	}
}

// valid 校验会话是否有效，返回其中的用户名。以下情况视为失效（返回 ("", false)）：
//   - 会话不存在（从未登录 / 已退出 / 已失效）；
//   - 已超过绝对过期时间；
//   - 距最后一次请求已超过 idle（闲置超时；idle ≤ 0 表示不启用）；
//   - 已进入待删除宽限且宽限到期（被"关闭最后一个标签"信标触发）。
//
// revive 表示本次请求是否应"救活"处于待删除宽限的会话：
//   - true（如页面刷新、用户主动操作）：宽限内清除宽限标记 → 保活；
//   - false（如后台周期轮询/信标，前端带 X-Mantou-Silent:1）：仅校验、不救活，
//     使「关闭最后一个标签页」能可靠到期失效，不被后台轮询反复复活。
//
// idle 是闲置超时时长，取自配置 Auth.SessionIdleMinutes，由调用方按当次请求的配置
// 快照传入——不缓存在 registry 里，是为了让设置页改完立刻生效，无需重启面板。
// 与 expiresAt 的分工：expiresAt 从登录起算、永不延长，管的是「会话最长能活多久」；
// idle 从 lastSeenAt 起算、每次请求归零，管的是「多久联系不上就认定人已不在」。
// 后者是给「关闭最后一个窗口即注销」兜底的：信标发不出去时（崩溃/强杀/断电）由它收尾。
//
// 注意 lastSeenAt 对静默请求同样刷新（不看 revive）：面板页面开着时本就有后台轮询，
// 它证明浏览器还活着，正是闲置超时要判断的那件事。这不会削弱关窗口注销——那条路
// 靠的是信标置下的 pendingDeleteAt，静默请求不会清除它。
func (r *sessionRegistry) valid(token, username string, revive bool, idle time.Duration) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[sessionKey(token)]
	if !ok {
		return "", false
	}
	now := time.Now()
	if now.After(e.expiresAt) {
		delete(r.entries, sessionKey(token))
		return "", false
	}
	if idle > 0 && now.Sub(e.lastSeenAt) > idle {
		delete(r.entries, sessionKey(token))
		return "", false
	}
	// 宽限已过即判失效，不等 markPendingDelete 里那个定时器动手。
	//
	// 两个原因。一是判定必须落在校验路径上：定时器在到期那一刻才被调度，它真正跑起来
	// 之前若有请求进来，光看前面几项会把这个已经该死的会话放过去。
	// 二是它必须挡在下面的"救活"之前，否则一个迟到的刷新（宽限过后才发出）能把
	// 关掉的会话捞回来——那正好是「关闭最后一个窗口即注销」要防的事。
	if !e.pendingDeleteAt.IsZero() && now.After(e.pendingDeleteAt) {
		delete(r.entries, sessionKey(token))
		return "", false
	}
	e.lastSeenAt = now
	if revive && !e.pendingDeleteAt.IsZero() {
		e.pendingDeleteAt = time.Time{} // 刷新复用 → 救活
	}
	return e.username, true
}

// remove 立即删除会话（显式退出按钮或用户名变更时调用）。
func (r *sessionRegistry) remove(token string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, sessionKey(token))
}

// revokeAll 清空整张会话表，返回被清掉的条数。keep 非空时保留它对应的那一条。
//
// 这是面板唯一的主动失效手段。会话表只在内存里，重启即全部失效，但"重启一次面板"
// 不该是管理员怀疑凭据泄露时唯一能做的事——改密码就该把别处的会话踢下去（见 5-F）。
//
// keep 的作用是把"别处的会话"与"我这条"分开：返回值因此正好是别处的会话数，
// 而"我这条"由调用方换发新令牌来处置（见 rotateCurrentSession）。传空则连自己一起清掉。
func (r *sessionRegistry) revokeAll(keep string) int {
	var keepKey string
	if keep != "" {
		keepKey = sessionKey(keep)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for k := range r.entries {
		if k == keepKey {
			continue
		}
		delete(r.entries, k)
		n++
	}
	return n
}

// markPendingDelete 将会话标记为待删除（进入宽限），并预约宽限到期后物理删除；
// 宽限内若有新鉴权请求（刷新）会经 valid() 清除该标记并被救活。
func (r *sessionRegistry) markPendingDelete(token string) {
	r.mu.Lock()
	e, ok := r.entries[sessionKey(token)]
	if !ok {
		r.mu.Unlock()
		return
	}
	e.pendingDeleteAt = time.Now().Add(sessionGrace)
	r.mu.Unlock()

	time.AfterFunc(sessionGrace, func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if cur, ok := r.entries[sessionKey(token)]; ok {
			if !cur.pendingDeleteAt.IsZero() && time.Now().After(cur.pendingDeleteAt) {
				delete(r.entries, sessionKey(token))
			}
		}
	})
}
