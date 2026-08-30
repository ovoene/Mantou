package app

import (
	"mantou/internal/auth"
	"mantou/internal/config"
	"mantou/internal/logx"
	"mantou/internal/modules/wol"
)

// MigrateWebBasicAuth 把历史配置里以**明文**保存的 Web 服务 Basic 认证口令换成 bcrypt 哈希。
//
// 为什么放在这里而不是 config.migrate：哈希需要 internal/auth，而 config 是最底层的包，
// 让它反过来依赖认证包并不合适；app 是组装各模块的地方，跨模块的一次性迁移归它管最自然。
// 调用时机必须在模块启动之前——Web 服务模块一旦起来就要拿这个字段校验访问了。
//
// 迁移分两步：先在配置锁外把哈希都算好，再在一次 Update 里按子项 ID 写回。
// bcrypt 每条要几十毫秒，若直接在 Update 的回调里算，就会在启动时把配置写锁按条目数占住。
//
// 迁移不是校验能否工作的前提：校验侧对"存的仍是明文"有兼容分支（见 basicauth.go），
// 因此本函数失败只是让明文在磁盘上多留一会儿，不会把站点锁死。
func MigrateWebBasicAuth(cfgMgr *config.Manager, log *logx.Logger) {
	hashes := make(map[string]string) // 子项 ID → 新哈希
	for _, ws := range cfgMgr.Snapshot().WebServices {
		for _, ch := range ws.Children {
			pass := ch.Access.BasicAuthPass
			if ch.ID == "" || pass == "" || auth.IsHash(pass) {
				continue
			}
			hash, err := auth.HashPassword(pass)
			if err != nil {
				// 唯一的现实原因是口令超过 bcrypt 的 72 字节上限。保留明文并告警：
				// 校验侧的明文兼容分支仍能让站点正常工作，用户改短口令后即自动完成迁移。
				log.Warn("Web 服务 Basic 认证口令无法哈希，暂仍以明文保存", "childId", ch.ID, "err", err.Error())
				continue
			}
			hashes[ch.ID] = hash
		}
	}
	if len(hashes) == 0 {
		return
	}
	if err := cfgMgr.Update(func(c *config.Config) {
		for i := range c.WebServices {
			for j := range c.WebServices[i].Children {
				ch := &c.WebServices[i].Children[j]
				hash, ok := hashes[ch.ID]
				// 再确认一次当前值仍是明文：避免在极小概率的 ID 重复下，
				// 把某个子项已经存好的哈希覆盖成另一个子项的口令哈希。
				if ok && ch.Access.BasicAuthPass != "" && !auth.IsHash(ch.Access.BasicAuthPass) {
					ch.Access.BasicAuthPass = hash
				}
			}
		}
	}); err != nil {
		log.Error("升级 Web 服务 Basic 认证口令存储失败", "err", err.Error())
		return
	}
	log.Info("已将 Web 服务 Basic 认证口令改为哈希保存", "count", len(hashes))
}

// SanitizeWOLDevices 在配置加载之后，把发送参数非法的网络唤醒设备**禁用**并逐条告警。
//
// 为什么需要这一遍：接口层的校验（server.validateWOL）只覆盖「从界面保存」这一条路径，
// 而设备条目还能从另外两条路径进入配置——手工编辑 config.json、以及整份导入备份。
// config.migrateWOL 只夹发包次数，不做合法性校验，于是一条 MAC 写错、广播地址填成域名、
// 或端口越界的设备会被照常加载，然后：
//   - 每一拍都发一次注定失败的包，界面上只留一行「失败: …」，没人会去看；
//   - 更糟的情况是广播地址指向公网，模块变成一个每秒一发的任意 UDP 发包器
//     （原因见 wol.ValidBroadcast）。
//
// 处理方式是禁用而不是丢弃：设备还在列表里，开关是关的，用户改好字段再打开即可
// （取舍见 wol.DisableInvalidDevices）。
//
// 只在真有非法项时才写配置：否则每次启动都要整份重写一遍 config.json。
// 禁用本身让这套动作幂等——下次启动它已经是关的，不再进入告警。
//
// 调用时机与 MigrateWebBasicAuth 一致：必须早于模块启动，否则调度协程已经按旧配置起来了。
func SanitizeWOLDevices(cfgMgr *config.Manager, log *logx.Logger) {
	bad := wol.InvalidDevices(cfgMgr.Snapshot().WOLDevices)
	if len(bad) == 0 {
		return
	}
	// 先告警再写盘：写盘失败时至少让用户知道这几台设备有问题。
	for _, b := range bad {
		log.Warn("网络唤醒设备参数非法，已自动禁用",
			"id", b.ID, "name", b.Name, "reason", b.Reason)
	}
	if err := cfgMgr.Update(func(c *config.Config) {
		wol.DisableInvalidDevices(c.WOLDevices)
	}); err != nil {
		// 写盘失败不影响本次运行的正确性：模块拿的是同一份内存配置，
		// 只是下次启动还要再禁用一遍、再告警一遍。
		log.Error("禁用非法网络唤醒设备失败", "err", err.Error())
		return
	}
	log.Info("已禁用参数非法的网络唤醒设备", "count", len(bad))
}
