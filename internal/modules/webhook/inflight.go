package webhook

import "sync/atomic"

// 入站请求体有**单条**上限（MaxBytesReader 按接收器的 MaxBodyKB 卡，见 handler.go），
// 但没有任何东西限制同时有多少条这样的请求在处理。
//
// 一条请求在解析之后同时持有三份东西：读进来的原始 []byte、条件求值用的解析结果
// （map[string]any，对"深嵌套 + 短键"的载荷膨胀三到十倍是常态）、以及渲染出来的消息。
// 单条 4MiB 的峰值占用因此能到几十 MB，而 Go 的 http.Server 默认不限并发连接数，
// 每 IP 限流又是**默认不启用**的（RateLimit=0 时 rc.limiter 为 nil）。
// 也就是说默认配置下这条路上一道闸都没有：并发数是对端说了算的乘数（见 3-G）。
//
// 这道闸把那个乘数变成常量。取值与响应的取舍：
//
//   - 计条数而不是计字节。计字节看起来更精确，但一条请求要预留多少字节只能按
//     接收器的上限算（真实长度要读完才知道），于是把 MaxBodyKB 调大的用户会发现
//     几条几 KB 的小请求就把预算占满了——那是拿正常配置换一个更好看的数字。
//   - 超出即回 503，不排队等。第三方推送方普遍只等几秒（见 handler.go 顶部的说明），
//     排队等于把它们全部拖到超时，而超时在对面看来是"推送失败"，接着就是重推——
//     并发只会更高。503 是唯一能让对面稍后再来的答复。
//   - 闸装在读请求体之前、鉴权之后：装在更前面的话，一串猜错路径的请求就能占满名额，
//     把真消息挡在外面；装在读完之后就没有意义了，内存已经花掉了。
const maxInflight = 64

// inflightGate 入站并发闸。
//
// CAS 而不是"先加再判"：后者在 N 个 goroutine 同时进来时会先一起加上去，
// 超额的部分正是这道闸要防的东西。CAS 循环下 cur 永不超过 maxInflight。
//
// 不记峰值、不单独计拒收数：拒收总数已经在 m.rejected 里，
// 而每一次拒收都带着原因进执行历史，管理员看得到"是并发满了"这件事。
type inflightGate struct {
	cur atomic.Int64
}

// enter 占一个名额，占不到返回 false。
func (g *inflightGate) enter() bool {
	for {
		cur := g.cur.Load()
		if cur >= maxInflight {
			return false
		}
		if g.cur.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

// leave 归还名额。调用方用 defer，保证中途的每条 return 都还得回来。
func (g *inflightGate) leave() { g.cur.Add(-1) }
