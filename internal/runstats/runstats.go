// Package runstats 存列表页上的那几个统计数字：最近一次是什么时候、结果是什么、
// 累计多少次。三类列表用它——消息路由的接收器、通知目标、网络唤醒的设备。
//
// 只在内存里，不落盘，进程重启归零。这么定有两个原因：
//
//  1. 写入频率不由本程序决定。接收器的计数是每条入站请求一次（频率由公网决定），
//     通知目标是每条消息扇出到 N 个目标就 N 次，网络唤醒的「时间范围」模式最快 1 秒一拍。
//     这些数字原先是配置条目上的字段，于是每加一次计数都要换一份配置、涨一次 rev、
//     标一次脏等着落盘——全局只有一把配置写锁，外面推得越快，面板越卡。
//  2. 这些数字丢了不影响任何行为。全项目没有任何逻辑读它们，只有列表页显示。
//     反例是 DDNS 的 lastIP 和证书的到期时间：那些是判断依据，仍然留在 state.json 里。
//
// 换到这里之后，加一次计数是一次加锁 + 一次 map 写，与配置规模无关，也不产生磁盘写入。
package runstats

import (
	"sync"

	"mantou/internal/config"
)

const (
	// MaxBytes 是所有模块的统计加起来允许占用的内存上限。
	MaxBytes = 1 << 20 // 1 MiB

	// entryBytes 是一条统计按最坏情况估的字节数，用来把 MaxBytes 折算成条数。
	//
	// 逐项算（64 位平台）：
	//   结果文本    入库时裁到 config.MaxStatusMessageLen（300 字节）加截断后缀，
	//               约 318 字节，落到分配器的 384 字节档；
	//   stat 本体   两个计数 + 一个时刻 + 一个字符串头 = 40 字节，落 48 字节档；
	//   map 里的键  种类 1 字节（对齐后 8）+ 字符串头 16 = 24 字节，
	//               加值位 8 字节与 tophash，按 map 不超过 8 成装载算约 41 字节；
	//   条目 ID     界面新建的 ID 是 12 个字符，导入进来的可能更长，按 64 字节算。
	// 合计约 537 字节。取 768 留出余量：map 扩容是翻倍的，刚过阈值那一刻桶数组会比
	// 装载量大一截，估值必须把那一刻也盖住。
	//
	// 这个折算是否站得住由 TestBudgetHoldsAtFullTable 实测核对，不只是算术。
	entryBytes = 768

	// MaxEntries 由上面两个数算出来，不另外写死一个条数。
	//
	// 算下来是 1365 条。实际用量的天花板是各模块的条目上限之和
	// （接收器 50 + 通知目标 50 + 设备 200 = 300 条），留了四倍多的余量。
	MaxEntries = MaxBytes / entryBytes
)

// Recv 一个接收器的统计。
//
// Received 与 Rejected 分开记：混成一个数之后，「累计 72 次」里有多少是真收下的、
// 多少是被限流或令牌不对挡掉的，看不出来——而这两件事要做的处置完全不同。
type Recv struct {
	LastAt     int64  // 最近一次收下的时刻（Unix 秒）；被拒的不算
	LastStatus string // 最近一次收下的处理结果
	Received   int64  // 收下并进了流水线的条数
	Rejected   int64  // 被挡在流水线之外的条数（限流、令牌不对）
}

// Send 一个通知目标的统计。
type Send struct {
	LastAt     int64
	LastStatus string
	Sent       int64
	Fail       int64
}

// Wake 一台网络唤醒设备的统计。
type Wake struct {
	LastAt   int64
	LastText string
	Count    int64
}

// kind 区分三类列表。ID 只在各自模块内唯一，跨模块可能撞上，所以键里要带种类。
type kind uint8

const (
	kindRecv kind = iota
	kindSend
	kindWake
)

type key struct {
	k  kind
	id string
}

// stat 是三类统计在库里的统一形状：一个时刻、一段文本、两个计数。
// 两个计数的含义由写入方法给定（收下/拒收、成功/失败、唤醒/未用）。
type stat struct {
	at   int64
	text string
	n1   int64
	n2   int64
}

// Store 是统计的存放处。用一张表加一把锁，不按种类分表——上限是「所有模块加起来」，
// 分了表就得再想怎么把三个数凑到一起看，没有好处。
//
// 所有方法对 nil 接收者都是安全的：写入是空操作，读出来是零值。装配层允许不带它
// （server.Deps.Stats 可以是 nil，测试里大多如此），有了这一条，调用点就不必各自判空
// ——判空这件事漏一处就是一次崩溃，而漏了的那处往往是最少走到的分支。
type Store struct {
	mu sync.Mutex
	m  map[key]*stat
}

// New 建一个空的统计库。
func New() *Store {
	return &Store{m: make(map[key]*stat)}
}

// Received 记一条收下的消息：刷新时刻与结果文本，收下计数加一。
func (s *Store) Received(id string, at int64, status string) {
	s.touch(kindRecv, id, func(e *stat) {
		e.at = at
		e.text = truncate(status)
		e.n1++
	})
}

// Rejected 记一条被挡掉的请求：只加拒收计数。
//
// 刻意不动时刻与结果文本。列表上那一列叫「最近收到」，用户读它就是「上一次真有数据进来」；
// 被限流挡掉的请求没带来任何数据，把时刻改成它等于把这一列变成「最近被人敲过」。
//
// id 必须是配置里真实存在的接收器 ID。两个调用场景（限流、令牌不对）都是路径先匹配上了
// 某个接收器才发生的，所以这一点由调用方的位置保证；换成外部可控的字符串会让这里的
// 条数上限失去意义。
func (s *Store) Rejected(id string) {
	s.touch(kindRecv, id, func(e *stat) { e.n2++ })
}

// Sent 记一次通知投递，按成功与否加到两个计数上。
func (s *Store) Sent(id string, at int64, status string, ok bool) {
	s.touch(kindSend, id, func(e *stat) {
		e.at = at
		e.text = truncate(status)
		if ok {
			e.n1++
		} else {
			e.n2++
		}
	})
}

// Woke 记一次唤醒。
func (s *Store) Woke(id string, at int64, result string) {
	s.touch(kindWake, id, func(e *stat) {
		e.at = at
		e.text = truncate(result)
		e.n1++
	})
}

// Recv 读一个接收器的统计。没有记录时返回零值，等同于「还没收到过」。
func (s *Store) Recv(id string) Recv {
	e := s.get(kindRecv, id)
	return Recv{LastAt: e.at, LastStatus: e.text, Received: e.n1, Rejected: e.n2}
}

// Send 读一个通知目标的统计。
func (s *Store) Send(id string) Send {
	e := s.get(kindSend, id)
	return Send{LastAt: e.at, LastStatus: e.text, Sent: e.n1, Fail: e.n2}
}

// Wake 读一台设备的统计。
func (s *Store) Wake(id string) Wake {
	e := s.get(kindWake, id)
	return Wake{LastAt: e.at, LastText: e.text, Count: e.n1}
}

// Usage 报告当前占用，供「关于」页与内存预算核算使用。
type Usage struct {
	Entries    int `json:"entries"`
	MaxEntries int `json:"maxEntries"`
	Bytes      int `json:"bytes"`
	MaxBytes   int `json:"maxBytes"`
}

// Usage 返回当前条数与折算出来的字节数。字节数是按 entryBytes 折算的估值，
// 不是实测——这里要的是「离上限还有多远」，不是精确内存画像。
func (s *Store) Usage() Usage {
	n := 0
	if s != nil {
		s.mu.Lock()
		n = len(s.m)
		s.mu.Unlock()
	}
	return Usage{Entries: n, MaxEntries: MaxEntries, Bytes: n * entryBytes, MaxBytes: MaxBytes}
}

// Forget 删掉指定条目的统计。条目被删除时调用，免得表里留着再也不会有人看的键。
func (s *Store) Forget(id string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, key{kindRecv, id})
	delete(s.m, key{kindSend, id})
	delete(s.m, key{kindWake, id})
}

// Reset 清空全部统计。用于「清空统计」这类显式操作与测试。
func (s *Store) Reset() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.m = make(map[key]*stat)
	s.mu.Unlock()
}

// touch 找到（或新建）一条记录并交给 mutate 就地改。
func (s *Store) touch(k kind, id string, mutate func(*stat)) {
	if s == nil || id == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	kk := key{k, id}
	e := s.m[kk]
	if e == nil {
		s.evictIfFullLocked()
		e = &stat{}
		s.m[kk] = e
	}
	mutate(e)
}

// get 取一条记录的副本；不存在时返回零值。
func (s *Store) get(k kind, id string) stat {
	if s == nil {
		return stat{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.m[key{k, id}]; e != nil {
		return *e
	}
	return stat{}
}

// evictIfFullLocked 在表满时腾出一个位置：挑 at 最小的那条删掉。
//
// 为什么是淘汰而不是拒绝新建：正常情况下表里的条数由各模块的条目上限决定
// （接收器 50、通知目标 50、设备 200，合起来 300 条，离 MaxEntries 很远），
// 只有「反复新增又删除、且从没打开过列表页」才会把陈旧的键堆到上限。
// 那种局面下拒绝新建，受害的是当前真在收数据的那一条——它永远显示 0；
// 淘汰 at 最小的那条，丢的是最久没动静的（很可能已经被删掉的）那一条。
// 两种做法丢的都只是展示用的数字，而后者不会让活着的条目显示不出来。
func (s *Store) evictIfFullLocked() {
	if len(s.m) < MaxEntries {
		return
	}
	var oldest key
	first := true
	for k, e := range s.m {
		if first || e.at < s.m[oldest].at {
			oldest, first = k, false
		}
	}
	if !first {
		delete(s.m, oldest)
	}
}

// truncate 把结果文本裁到 config.MaxStatusMessageLen 以内。
//
// 库自己裁而不是信调用方：上限是按每条最长多少字节折算出来的，一个漏裁的调用方
// 就能让整张表的占用超出预算，而这种超出在界面上完全看不出来。
//
// 复用 config 那个函数而不是另写一份：裁剪长度与截断后缀都只该有一处定义，
// 否则同一段状态文本在列表页和历史里会显示成两个样子。
func truncate(s string) string {
	return config.TruncateStatus(s)
}
