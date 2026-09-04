package module

import (
	"sync"
	"time"

	"mantou/internal/config"
	"mantou/internal/logx"
)

// Module 是各功能模块（DDNS、端口转发、Web 服务、证书等）的统一接口。
// 服务器在启动时调用 Reload 应用初始配置，配置变更后再次调用 Reload 热重载，
// 退出时调用 Close 释放资源。实现需保证：
//   - Reload 可重复调用且幂等，且**不得修改**传入的 cfg
//     （管理器会留存最近一份成功应用的配置用于回滚，写它等于污染回滚基线）；
//   - Close 可重复调用（重复调用应为空操作），见 Manager.CloseAll 的说明。
type Module interface {
	// Name 返回模块名（用于日志与状态）。
	Name() string
	// Reload 依据最新配置应用状态；应能安全地多次调用。
	Reload(cfg *config.Config) error
	// Close 停止模块并释放资源。
	Close() error
}

// Status 描述一个模块的运行状态摘要，供总览页展示。
type Status struct {
	Name    string `json:"name"`
	Total   int    `json:"total"`
	Active  int    `json:"active"`
	Healthy bool   `json:"healthy"`
	// Code 是状态短语的**键名**，Args 是它的插值参数——不是拼好的句子。
	//
	// 与 Name 同一条理由：翻译只能在前端做。这里原先是一个 Message string，各模块往里
	// 塞拼好的中文（"HTTPS 监听 0.0.0.0:25667，已接收 3 条"），英文界面上就照原样漏出中文，
	// 而这种漏字不会有任何报错，只能靠人眼在英文页面上撞见（消息路由页的状态行就是这么发现的）。
	// 换成键名之后，忘了加译名的表现是界面上出现一个可见的英文键，而不是一行中文。
	//
	// 取值由各模块自己定义（见各自的 Status 方法），前端按模块归类查译名。
	// Code 为空表示"没有额外可说的"，调用方不渲染这一行。
	Code string `json:"code,omitempty"`
	// Args 的键与译文里的 {name} 一一对应。刻意用 map 而不是定长字段：
	// 各模块要说的事不一样（监听地址、队列深度、出错条数），定长字段会退化成
	// 一堆彼此无关的可选项，而每个模块只填其中两三个。
	Args map[string]any `json:"args,omitempty"`
}

// StatusReporter 是可选接口：模块可上报自身状态。
type StatusReporter interface {
	Status() Status
}

// slowReloadThreshold 单个模块重载耗时超过该值即记一条 WARN。
// 重载在配置保存的请求路径上同步执行，慢模块会直接体现为"保存按钮转很久"，
// 没有这条日志时用户只知道"面板卡"，无法定位到是哪个模块。
const slowReloadThreshold = 3 * time.Second

// Manager 管理一组模块的生命周期与配置热重载。
type Manager struct {
	mu      sync.RWMutex
	modules []Module
	log     *logx.Logger

	// reloadMu 让多次 ReloadAll 相互串行，但**不**占用 mu：
	// 重载可能耗时数秒（绑定端口、加载证书），若全程持 mu，则 Statuses（总览页每 2 秒轮询一次）
	// 会被一并阻塞，表现为"改配置时总览页整体卡住"。
	// 串行仍是必须的：两次并发重载交叉执行会让模块看到彼此的中间状态。
	reloadMu sync.Mutex
	// lastGood 是最近一次成功应用到该模块的配置，按模块名索引，用于单模块回滚。
	// 受 reloadMu 保护（只在重载路径读写）。
	lastGood map[string]*config.Config
	// closed 在 CloseAll 之后置位，使 CloseAll 可重复调用（幂等），
	// 并让此后的 ReloadAll 直接跳过——否则关闭流程之后到来的一次配置保存
	// 会把已经停掉的监听重新拉起来，进程退出时留下"端口仍被占用"的残留。
	closed bool
}

// NewManager 创建模块管理器。
func NewManager(log *logx.Logger) *Manager {
	return &Manager{log: log, lastGood: make(map[string]*config.Config)}
}

// Register 注册一个模块。应在 ReloadAll 之前完成注册。
func (m *Manager) Register(mod Module) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.modules = append(m.modules, mod)
}

// snapshot 返回当前模块列表的副本，供重载/关闭在**不持锁**的前提下遍历。
func (m *Manager) snapshot() []Module {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]Module(nil), m.modules...)
}

// ReloadAll 用给定配置重载全部模块。
//
// 三条约定：
//  1. **不持 mu 遍历**：先取模块列表快照再逐个重载，慢模块不会阻塞 Statuses / Register。
//     多次 ReloadAll 之间由 reloadMu 串行，最后完成的一次即最终生效的配置。
//  2. **按注册顺序串行**：顺序本身是依赖关系（证书必须先于 Web 服务加载，否则
//     HTTPS 站点取不到证书），因此这里刻意不并发。
//  3. **单模块原子性**：某模块 Reload 返回错误时，立刻用它上一次成功应用的配置重载它一次，
//     使该模块回到一个完整、已知可用的状态，而不是停在"一半新一半旧"的中间态；
//     其余模块照常应用新配置（各模块之间本就互不依赖运行态）。
func (m *Manager) ReloadAll(cfg *config.Config) {
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()

	m.mu.RLock()
	closed := m.closed
	m.mu.RUnlock()
	if closed {
		m.log.Warn("模块已全部关闭，忽略本次配置重载")
		return
	}

	for _, mod := range m.snapshot() {
		name := mod.Name()
		started := time.Now()
		err := mod.Reload(cfg)
		if cost := time.Since(started); cost >= slowReloadThreshold {
			m.log.Warn("模块重载耗时偏长", "module", name, "cost", cost.String())
		}
		if err == nil {
			m.lastGood[name] = cfg
			continue
		}
		m.log.Error("模块重载失败", "module", name, "err", err.Error())
		prev := m.lastGood[name]
		if prev == nil || prev == cfg {
			// 没有可回滚的基线（首次重载即失败），只能保持现状：模块自身会通过
			// Status 上报不健康，总览页可见。
			continue
		}
		if rbErr := mod.Reload(prev); rbErr != nil {
			m.log.Error("模块重载失败后回滚也失败，该模块状态可能不完整",
				"module", name, "err", rbErr.Error())
			continue
		}
		m.log.Warn("模块重载失败，已回滚到上一份可用配置", "module", name)
	}
}

// CloseAll 关闭全部模块；可重复调用，第二次及以后为空操作。
//
// 幂等是硬需求而非防御性编程：自更新路径（cmd/mantou 的 execCh 分支）会先显式
// CloseAll 释放监听再 exec 新二进制，一旦 exec 失败函数返回，defer 里的 CloseAll
// 会再执行一次——而 webservice.Close 里有 close(m.probeStop)，重复关闭 channel 直接 panic。
func (m *Manager) CloseAll() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	mods := append([]Module(nil), m.modules...)
	m.mu.Unlock()

	for _, mod := range mods {
		if err := mod.Close(); err != nil {
			m.log.Error("模块关闭失败", "module", mod.Name(), "err", err.Error())
		}
	}
}

// Statuses 收集所有实现了 StatusReporter 的模块状态。
func (m *Manager) Statuses() []Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []Status
	for _, mod := range m.modules {
		if sr, ok := mod.(StatusReporter); ok {
			out = append(out, sr.Status())
		}
	}
	return out
}
