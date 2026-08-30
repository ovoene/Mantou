package config

import (
	"os"
	"path/filepath"
	"testing"
)

// 本文件钉住一条不变量：**有管理员账户就一定是「已初始化」**。
//
// 它不是兼容性补丁，而是 /api/init/setup 那道免鉴权入口的前提——那个接口放不放行
// 只看 Auth.Initialized 一个布尔值。这个值为假而账户仍在时，面板会同时坏在两头：
// 正确的账号密码登不进来（handleLogin 直接回「尚未初始化」），而网络上任何人都能
// 重走一遍初始化向导注册新管理员，把原账户覆盖掉。先锁死自己，再对外敞开。
//
// 这个状态没有合法来源，但外部配置能把它带进来：手改过的 config.json，或一份缺
// auth.initialized 这个键的备份（备份解密后反序列化到零值 Config，缺键即为假）。
// 所以两个方向都要测：该补的补上，而**真的还没装**的那一侧绝不能被补成"已初始化"——
// 补错了就等于把初始化向导对第一个装机的人也关掉，那是彻底装不上。

// hashLike 是一段形似 bcrypt 的占位串。这里不需要真的能验证通过：本文件验的是
// 「账户字段非空时标记怎么变」，跑一次真 bcrypt 只是让测试变慢。
const hashLike = "$2a$10$0123456789012345678901uabcdefghijklmnopqrstuvwxyz012"

func TestMigrateRepairsInitializedFlag(t *testing.T) {
	cfg := Default()
	cfg.Auth.Username = "admin"
	cfg.Auth.PasswordHash = hashLike
	cfg.Auth.Initialized = false

	Migrate(cfg)

	if !cfg.Auth.Initialized {
		t.Fatal("账户字段都在，初始化标记必须被补成真——否则 /api/init/setup 会对整个网络放行")
	}
}

// 反方向：全新安装那一侧不能被误判成已初始化，否则初始化向导直接关门，谁都装不上。
func TestMigrateKeepsFreshInstallUninitialized(t *testing.T) {
	for _, tc := range []struct {
		name         string
		username     string
		passwordHash string
	}{
		{name: "全新安装：两个字段都空"},
		{name: "只有用户名（半截状态，不能当账户存在）", username: "admin"},
		{name: "只有口令哈希（同上）", passwordHash: hashLike},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.Auth.Username = tc.username
			cfg.Auth.PasswordHash = tc.passwordHash

			Migrate(cfg)

			if cfg.Auth.Initialized {
				t.Fatal("没有完整的管理员账户，不得标记为已初始化——初始化向导会因此关门")
			}
		})
	}
}

// 从磁盘加载这一条路也要补齐：手改 config.json 把 initialized 改成 false，
// 不该换来一个「谁都能重新注册管理员」的面板。
//
// 刻意不写 version 字段（即 0），顺带覆盖「一份很旧的配置」这种真实形态。
func TestLoadRepairsInitializedFlagFromDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	raw := `{"auth":{"username":"admin","passwordHash":"` + hashLike + `","initialized":false}}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}

	m := NewManager(path)
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}

	auth := m.Snapshot().Auth
	if !auth.Initialized {
		t.Fatal("磁盘上的配置有管理员账户，加载后初始化标记必须为真")
	}
	// 补标记不等于动账户：用户名与口令哈希必须原样留着。
	if auth.Username != "admin" || auth.PasswordHash != hashLike {
		t.Fatalf("补标记时不该改动账户字段，得到 username=%q passwordHash=%q", auth.Username, auth.PasswordHash)
	}
}
