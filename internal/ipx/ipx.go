// Package ipx 收拢「按来源 IP 做访问控制」这件事：名单匹配与每 IP 限流。
//
// 建立这个包的动因和 strutil 一样——同一件事出现了第二个使用方。
// 名单匹配与限流原本只服务反向代理（webservice），消息路由的入站接收器需要
// 完全相同的语义（IP 黑白名单 + 每秒请求数）。复制一份的代价不是多 200 行代码，
// 而是同一个匹配陷阱（IPv4-in-IPv6 表示不统一、范围展开无上限）要修两次，
// 且两处会各自演化出不同的行为——而这两处都是安全边界。
package ipx

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"mantou/internal/mapx"
)

// maxRangeIPs 一条「a-b」范围最多展开成多少个单 IP。
const maxRangeIPs = 4096

// ParseCIDRs 将输入解析为 IP 网络集合，支持三类写法：
//   - 单个 IP（自动补全为 /32 或 /128）
//   - CIDR（如 10.0.0.0/24）
//   - IP 范围（如 192.168.1.1-192.168.1.20），展开为逐个单 IP（封顶 maxRangeIPs）
//
// 无法识别的条目直接跳过，不返回错误：名单是用户在面板里手填的，
// 一条写错不该让整份名单失效（那会把「白名单里有个错字」变成「谁都进不来」）。
func ParseCIDRs(items []string) []*net.IPNet {
	var out []*net.IPNet
	for _, it := range items {
		trimmed := strings.TrimSpace(it)
		if trimmed == "" {
			continue
		}
		// IP 范围：start-end（无斜杠且含连字符），展开为单 IP。
		if !strings.Contains(trimmed, "/") && strings.Contains(trimmed, "-") {
			if nets := parseRange(trimmed); nets != nil {
				out = append(out, nets...)
			}
			continue
		}
		if !strings.Contains(trimmed, "/") {
			// 单个 IP，补全为 /32 或 /128。
			ip := net.ParseIP(trimmed)
			if ip == nil {
				continue
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			trimmed = trimmed + "/" + strconv.Itoa(bits)
		}
		if _, n, err := net.ParseCIDR(trimmed); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// parseRange 将「start-end」形式的 IP 范围展开为一组单 IP 网络。
// 协议族不一致或范围过大时返回 nil（视为无效、跳过）。
func parseRange(s string) []*net.IPNet {
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 {
		return nil
	}
	start := net.ParseIP(strings.TrimSpace(parts[0]))
	end := net.ParseIP(strings.TrimSpace(parts[1]))
	if start == nil || end == nil {
		return nil
	}
	if (start.To4() == nil) != (end.To4() == nil) {
		// 协议族不一致（一个 IPv4、一个 IPv6）。
		return nil
	}
	var out []*net.IPNet
	cur := start
	count := 0
	for {
		bits := 32
		if cur.To4() == nil {
			bits = 128
		}
		out = append(out, &net.IPNet{IP: cur, Mask: net.CIDRMask(bits, bits)})
		count++
		if count > maxRangeIPs || cur.Equal(end) {
			break
		}
		next := nextIP(cur)
		if next == nil || next.Equal(cur) {
			break // 地址溢出，停止展开
		}
		cur = next
	}
	return out
}

// nextIP 返回 ip+1（按 16 字节表示递增，兼容 IPv4 / IPv6）。
func nextIP(ip net.IP) net.IP {
	v := ip.To16()
	out := make(net.IP, len(v))
	copy(out, v)
	for i := len(out) - 1; i >= 0; i-- {
		out[i]++
		if out[i] != 0 {
			break
		}
	}
	if ip.To4() != nil {
		return out[12:]
	}
	return out
}

// Matcher 是预解析好的名单匹配器：名单在 Reload 构建处理器时解析一次，请求路径上只做匹配。
//
// 分成两半是有意的：单主机条目（/32、/128）进 map 走 O(1) 精确匹配，只有真正带前缀的
// 网段才留在切片里线性扫。名单里绝大多数条目本就是单个 IP，而「a-b」范围还会被 parseRange
// 展开成最多 maxRangeIPs 个单 IP——若一律线性扫，一份几千条的封禁名单会让每个请求都遍历整表。
type Matcher struct {
	// hosts 的键取 IP 的 16 字节归一形式，使 IPv4 的 4 字节与 IPv4-in-IPv6 两种表示落到同一键。
	hosts map[[16]byte]struct{}
	nets  []*net.IPNet
}

// NewMatcher 解析名单并按「单主机 / 带前缀」分流。
func NewMatcher(items []string) *Matcher {
	m := &Matcher{}
	for _, n := range ParseCIDRs(items) {
		if ones, bits := n.Mask.Size(); ones == bits && ones > 0 {
			if m.hosts == nil {
				m.hosts = make(map[[16]byte]struct{})
			}
			m.hosts[Key(n.IP)] = struct{}{}
			continue
		}
		m.nets = append(m.nets, n)
	}
	return m
}

// Empty 报告名单是否没有任何有效条目（全部为空白或非法写法时也为真）。
func (m *Matcher) Empty() bool { return len(m.hosts) == 0 && len(m.nets) == 0 }

// Match 报告 ip 是否落在名单内。
func (m *Matcher) Match(ip net.IP) bool {
	if len(m.hosts) > 0 {
		if _, ok := m.hosts[Key(ip)]; ok {
			return true
		}
	}
	for _, n := range m.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Key 取 IP 的 16 字节归一键。非法长度（既非 4 也非 16 字节）返回零值键，
// 与任何合法地址都不会相等，因此不会造成误匹配。
func Key(ip net.IP) [16]byte {
	var k [16]byte
	if v := ip.To16(); v != nil {
		copy(k[:], v)
	}
	return k
}

// ClientIP 取请求对端 IP。刻意**不**读 X-Forwarded-For：
// 那个头是客户端可以随手伪造的，用它做访问控制等于把名单交给对方填。
// 需要信任代理头的场景应由部署方在代理层做名单，而不是在这里。
func ClientIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(host)
}

// RemoteHost 返回请求对端 IP 字符串（去掉端口）；解析失败时回退为原始 RemoteAddr。
func RemoteHost(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

// LimitKey 取限流分桶键：优先用解析后的客户端 IP，无法解析时回退为去端口的对端地址。
func LimitKey(r *http.Request) string {
	if ip := ClientIP(r); ip != nil {
		return ip.String()
	}
	return RemoteHost(r.RemoteAddr)
}

// Bucket 是极简令牌桶限流器：容量=limit（令牌/秒），按经过时间线性补充，封顶 limit。
type Bucket struct {
	mu     sync.Mutex
	limit  float64
	tokens float64
	last   time.Time
}

// NewBucket 创建一个初始装满的令牌桶。
func NewBucket(limit float64) *Bucket {
	return &Bucket{limit: limit, tokens: limit, last: time.Now()}
}

// Allow 取一个令牌，取不到返回 false。
func (l *Bucket) Allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(l.last).Seconds()
	l.tokens += elapsed * l.limit
	if l.tokens > l.limit {
		l.tokens = l.limit
	}
	l.last = now
	if l.tokens >= 1 {
		l.tokens--
		return true
	}
	return false
}

// setLimit 改这个桶的每秒上限。
//
// 桶会跨配置保存继续用（见 IPLimiter.Allow），所以上限改了要就地跟上：
// 用户把每秒上限从 5 调到 100，下一个请求就该按 100 算，而不是等这个桶
// 空闲十分钟被回收之后才生效。
//
// 不动存量令牌：Allow 每次都会先把令牌压到 limit 以内，所以调低之后
// 那点存量自然放不出老额度来（TestIPLimiterRateChangeTakesEffect 钉着这一点）。
func (l *Bucket) setLimit(limit float64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.limit = limit
}

// idle 返回距上次取令牌的时长，供 GC 判断桶是否可回收。
func (l *Bucket) idle(now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	return now.Sub(l.last)
}

const (
	// limiterMaxEntries 每个限流器保留的最大来源 IP 桶数，防止海量来源撑爆内存。
	limiterMaxEntries = 8192
	// limiterIdle 桶空闲超过该时长即可被回收，同时作为 GC 触发的最小间隔。
	limiterIdle = 10 * time.Minute
	// limiterShrinkFloor 触发整表重建的最小峰值：一次扫描/CC 能把桶数撑到上限附近，
	// 而 delete 不归还 map 桶内存（见 mapx.ShrinkSparse），攻击退潮后那块内存会一直挂着。
	limiterShrinkFloor = 512
	// limiterEvictBatch 桶数达到上限时一次淘汰的数量上限。
	// 成批淘汰是为了摊薄开销：挑淘汰对象要扫一遍全表，一次只淘汰一个就等于
	// 每来一个新来源都付一次全表扫描。
	limiterEvictBatch = limiterMaxEntries / 8
)

// IPLimiter 为每个客户端 IP 维护独立令牌桶：不同来源互不挤占。
// 定期清理长时间空闲的桶并对映射设上限，避免长期运行后来源 IP 无限累积。
//
// 一张表被多个**作用域**共用（一个接收器、一个站点子项各算一个作用域），桶键是
// 「作用域 + 来源 IP」。原来是每个作用域各建一张表，于是 limiterMaxEntries 那句
// 「最多 8192 个桶、约 0.9 MB」的保护被作用域个数乘掉了：50 个接收器各被扫一遍
// 就是 45 MB 量级，而且要等 10 分钟空闲才开始回收。共用之后 8192 重新是全局上限。
//
// 共用的是表的容量，不是令牌：不同作用域下的同一个 IP 仍然各计各的。
// 代价是一个正在被扫的作用域会挤掉别人的桶——淘汰按空闲时长（见 evictLocked），
// 挤掉的是闲着的那些，它们下次来时重建，成本只是一次 map 插入。
// 拿"有界的相互影响"换掉"无界的内存"。
type IPLimiter struct {
	mu      sync.Mutex
	buckets map[string]*Bucket
	lastGC  time.Time
	// peak 记录 buckets 见过的最大桶数，供 GC 判断是否该重建 map 以真正释放内存。
	peak int
}

// NewIPLimiter 创建一张共享桶表。
//
// 每秒上限不在这里给：共用这张表的各个作用域各有自己的那个数，由每次调用带进来。
func NewIPLimiter() *IPLimiter {
	return &IPLimiter{
		buckets: make(map[string]*Bucket),
		lastGC:  time.Now(),
	}
}

// Allow 判断 scope 作用域下、来自 key 的这次请求是否放行；limit 是该作用域此刻的每秒上限。
//
// limit 每次带上而不是存一份：这张表挂在模块上、跨配置保存一直活着，用户把每秒上限
// 从 5 改成 100 之后那个桶必须立刻跟上，而不是等它空闲十分钟被回收才生效。
func (l *IPLimiter) Allow(scope, key string, limit float64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.gcLocked(now)
	// 用 \x00 分隔：接收器 ID 与站点子项 ID 里都不会有它，
	// 于是 ("ab","c") 与 ("a","bc") 不会撞成同一个桶。
	k := scope + "\x00" + key
	b := l.buckets[k]
	if b == nil {
		if len(l.buckets) >= limiterMaxEntries {
			// 桶数达到上限且 GC 没能腾出空间：淘汰一批最闲的桶，给新来源让位。
			//
			// 原来这里是直接放行（"保守失败开放"）。代价是限流可以被来源轮换整体关掉：
			// IPv6 下一个 /64 就能提供任意多的来源地址，把 8192 个桶撑满之后每个新来源都免检，
			// 这个限流器等于不存在。淘汰会让被淘汰来源的令牌恢复满额，确实削弱限流，
			// 但削弱是有界的——攻击者得持续制造足够多的新来源才能把自己的桶顶出去，
			// 而"一律放行"是无界的。
			l.evictLocked(now)
		}
		b = NewBucket(limit)
		b.last = now
		l.buckets[k] = b
		if n := len(l.buckets); n > l.peak {
			// 高水位只能在插入时记录：gcLocked 每 10 分钟才跑一次，且是在删除之后才看长度，
			// 单靠它永远看不到真正的峰值，收缩条件也就永不成立。
			l.peak = n
		}
	} else {
		b.setLimit(limit)
	}
	return b.Allow()
}

// Len 当前桶数。给状态展示与测试用。
func (l *IPLimiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// gcLocked 周期性回收长时间空闲的桶；调用方须持有 l.mu。
// 回收后顺带判断是否该整表重建：delete 只清条目，桶数组不缩容。
func (l *IPLimiter) gcLocked(now time.Time) {
	if now.Sub(l.lastGC) < limiterIdle {
		return
	}
	l.lastGC = now
	for k, b := range l.buckets {
		if b.idle(now) >= limiterIdle {
			delete(l.buckets, k)
		}
	}
	l.buckets = mapx.ShrinkSparse(l.buckets, &l.peak, limiterShrinkFloor)
}

// evictLocked 在桶数达到上限时淘汰一批桶，腾出空间给新来源；调用方须持有 l.mu。
//
// 淘汰谁：按空闲时长，越闲越先走。这个方向不是随手定的——正在被限流的来源恰好是"最不闲"的
// 那一批，按空闲淘汰能把它们留在表里，攻击者也就没法靠轮换来源把自己的桶顶出去。
//
// 淘汰多少：阈值取平均空闲时长，一次最多 limiterEvictBatch 个。取平均是为了保证有进展——
// 平均值必然不大于最大值，因此至少最闲的那一个会被删掉，不会出现"扫了一遍谁也没删"。
func (l *IPLimiter) evictLocked(now time.Time) {
	if len(l.buckets) == 0 {
		return
	}
	var total time.Duration
	for _, b := range l.buckets {
		total += b.idle(now)
	}
	cutoff := total / time.Duration(len(l.buckets))
	removed := 0
	for k, b := range l.buckets {
		if b.idle(now) < cutoff {
			continue
		}
		delete(l.buckets, k)
		removed++
		if removed >= limiterEvictBatch {
			return
		}
	}
}
