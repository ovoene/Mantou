package config

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"
)

// 「允许未验签的更新包」不是一个布尔开关，而是一段有限窗口：打开的时刻记在
// update.allowUnsignedSince 里，到期与否是一道纯计算（刻意没有后台任务去清零，
// 见 UpdateConfig.AllowUnsignedSince）。
//
// 判定既然只在读的时候算，那这几支就是这项限制的全部实现——算错一次的后果不是
// 报错，而是那扇门无声地一直开着。所以边界逐条钉住：没打开、没起点、刚好到点、
// 已过期、以及一个写到将来的起点。

// TestUnsignedUpdateWindow 逐一钉住窗口判定的各个分支。
func TestUnsignedUpdateWindow(t *testing.T) {
	now := time.Date(2026, 3, 5, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name        string
		u           UpdateConfig
		wantOK      bool      // 有没有窗口（UnsignedUpdateExpiry 的第二个返回值）
		wantExpiry  time.Time // wantOK 为真时的到期时刻
		wantAllowed bool      // 此刻放不放行
	}{
		{
			name: "开关关着",
			// 起点还留着（比如用户刚关掉、而这份配置是关闭前存的）也一样没有窗口：
			// 判定的第一道是那个布尔值。
			u:      UpdateConfig{AllowUnsignedSince: now.Add(-time.Minute).Unix()},
			wantOK: false, wantAllowed: false,
		},
		{
			name: "开着但没有起点",
			// 手改 config.json、或导入一份只有布尔值的旧备份就是这个样子。
			// 按"没有窗口"处理是这里唯一的失败安全方向：一个来源不明的布尔值
			// 不足以让面板接收任意二进制。
			u:      UpdateConfig{AllowUnsignedUpdate: true},
			wantOK: false, wantAllowed: false,
		},
		{
			name: "起点是负数",
			// time.Unix 对负数一样能算出一个 1970 年之前的时刻，于是"起点 + 24h"
			// 早已过去，放行的结论恰好也是假。但这里要的是"没有窗口"而不是
			// "有一个已过期的窗口"：前者在设置页显示为关闭，后者会显示一个 1970 年的到期时刻。
			u:      UpdateConfig{AllowUnsignedUpdate: true, AllowUnsignedSince: -1},
			wantOK: false, wantAllowed: false,
		},
		{
			name: "刚打开",
			u: UpdateConfig{
				AllowUnsignedUpdate: true,
				AllowUnsignedSince:  now.Add(-time.Minute).Unix(),
			},
			wantOK: true, wantExpiry: now.Add(-time.Minute + AllowUnsignedUpdateTTL), wantAllowed: true,
		},
		{
			name: "还差一秒到期",
			u: UpdateConfig{
				AllowUnsignedUpdate: true,
				AllowUnsignedSince:  now.Add(-AllowUnsignedUpdateTTL + time.Second).Unix(),
			},
			wantOK: true, wantExpiry: now.Add(time.Second), wantAllowed: true,
		},
		{
			name: "正好到点",
			// 边界取闭区间的哪一侧都说得通，但必须定死一个，否则改一次实现就会
			// 悄悄多放行或少放行一秒。取"到点即失效"（now.Before(exp)）：
			// 与"有效期 24 小时"这句话对得上。
			u: UpdateConfig{
				AllowUnsignedUpdate: true,
				AllowUnsignedSince:  now.Add(-AllowUnsignedUpdateTTL).Unix(),
			},
			wantOK: true, wantExpiry: now, wantAllowed: false,
		},
		{
			name: "早已过期",
			u: UpdateConfig{
				AllowUnsignedUpdate: true,
				AllowUnsignedSince:  now.Add(-30 * 24 * time.Hour).Unix(),
			},
			wantOK: true, wantExpiry: now.Add(-30*24*time.Hour + AllowUnsignedUpdateTTL), wantAllowed: false,
		},
		{
			name: "起点被写到将来",
			// 一份手改过或从别处导入的配置可以把打开时刻写到很远的将来，
			// 那样算出来的到期时刻同样远，等于永不过期——正好绕掉这道限制。
			// 起点夹到不晚于 now 之后，最坏情况也只是从"现在"起算一段正常长度的窗口。
			u: UpdateConfig{
				AllowUnsignedUpdate: true,
				AllowUnsignedSince:  now.Add(365 * 24 * time.Hour).Unix(),
			},
			wantOK: true, wantExpiry: now.Add(AllowUnsignedUpdateTTL), wantAllowed: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exp, ok := tc.u.UnsignedUpdateExpiry(now)
			if ok != tc.wantOK {
				t.Fatalf("期望 ok=%v，实际 %v（到期时刻 %v）", tc.wantOK, ok, exp)
			}
			if ok && !exp.Equal(tc.wantExpiry) {
				t.Fatalf("到期时刻应为 %v，实际 %v", tc.wantExpiry, exp)
			}
			if !ok && !exp.IsZero() {
				t.Fatalf("没有窗口时不该给出到期时刻，实际 %v", exp)
			}
			if got := tc.u.UnsignedUpdateAllowed(now); got != tc.wantAllowed {
				t.Fatalf("期望放行=%v，实际 %v", tc.wantAllowed, got)
			}
		})
	}
}

// TestUnsignedUpdateWindowIgnoresSignKey 窗口判定不看公钥。
//
// 两件事分工不同：配了公钥就一律验签（签名本身即授权），这段窗口只回答
// 「没有公钥时该不该收」。若判定里混进公钥，就会出现"配了公钥反而不放行"
// 这种谁都想不到的组合——放行与否要由 handleSelfUpdate 那一层按公钥先分流。
func TestUnsignedUpdateWindowIgnoresSignKey(t *testing.T) {
	now := time.Now()
	u := UpdateConfig{
		SignKey:             "dGhpcy1pcy1ub3QtYS1yZWFsLWtleQ==",
		AllowUnsignedUpdate: true,
		AllowUnsignedSince:  now.Add(-time.Minute).Unix(),
	}
	if !u.UnsignedUpdateAllowed(now) {
		t.Fatal("窗口判定不该受公钥影响")
	}
}

// TestMigrateBackfillsUnsignedUpdateWindow 验证 v12 升级：这一项从长期开关变成有限窗口，
// 已经打开它的用户要补一个起点。
//
// 不补的后果是静默收回一项已经打开的能力：旧配置里只有布尔值，按新口径会落到
// 「开着但没有起点」那一支，于是升级后上传更新包会撞上一句"未配置公钥"——
// 而用户什么都没改。v10 那一块已经立过这个规矩（见 store.go 的版本块）。
//
// 走**导入**这条路而不是 Load：Load 是 Default() 之后再 Unmarshal，
// 而 DecryptBackup 往一个零值 Config 里解，只有版本块能把这个字段补回来。
func TestMigrateBackfillsUnsignedUpdateWindow(t *testing.T) {
	migrated := func(t *testing.T, data string) *Config {
		t.Helper()
		var c Config
		if err := json.Unmarshal([]byte(data), &c); err != nil {
			t.Fatal(err)
		}
		Migrate(&c)
		return &c
	}
	now := time.Now()

	// 旧备份：开关开着，没有 allowUnsignedSince 这个键。
	on := migrated(t, `{"version":11,"panel":{"listen":"0.0.0.0","port":25666},`+
		`"update":{"allowUnsignedUpdate":true}}`)
	if on.Update.AllowUnsignedSince <= 0 {
		t.Fatal("升级没给已打开这一项的用户补起点，这次升级静默收回了一项已打开的能力")
	}
	// 补出来的起点是"现在"，因此升级后应当有完整一段窗口可用。
	if !on.Update.UnsignedUpdateAllowed(now) {
		t.Fatalf("补出来的窗口当场就是过期的（起点 %d）", on.Update.AllowUnsignedSince)
	}
	if on.Version != CurrentVersion {
		t.Fatalf("版本号应升到 %d，实际 %d", CurrentVersion, on.Version)
	}

	// 关着的时候不补：这个数在关闭状态下没有意义，写进去只会让 config.json
	// 多一个反直觉的键，还会让下次打开时算出一段从升级那天起算、可能早已过期的窗口。
	off := migrated(t, `{"version":11,"panel":{"listen":"0.0.0.0","port":25666},`+
		`"update":{"allowUnsignedUpdate":false}}`)
	if off.Update.AllowUnsignedSince != 0 {
		t.Fatalf("开关关着时不该补起点，实际 %d", off.Update.AllowUnsignedSince)
	}
	if off.Update.UnsignedUpdateAllowed(now) {
		t.Fatal("关着的开关升级后不该变成放行")
	}

	// 已有起点的不能被覆盖：那会把每一次迁移（含每次重启时的 Load）变成一次续期，
	// 窗口跟着无限顺延，这一项就又成了不会关的门。
	old := now.Add(-2 * AllowUnsignedUpdateTTL).Unix()
	kept := migrated(t, `{"version":11,"panel":{"listen":"0.0.0.0","port":25666},`+
		`"update":{"allowUnsignedUpdate":true,"allowUnsignedSince":`+strconv.FormatInt(old, 10)+`}}`)
	if kept.Update.AllowUnsignedSince != old {
		t.Fatalf("已有起点被迁移改写了：%d → %d", old, kept.Update.AllowUnsignedSince)
	}
	if kept.Update.UnsignedUpdateAllowed(now) {
		t.Fatal("一个早已过期的窗口在迁移后又放行了")
	}

	// 已经是当前版本的配置，迁移不能碰这两个字段（幂等）。
	cur := migrated(t, `{"version":`+strconv.Itoa(CurrentVersion)+`,"panel":{"listen":"0.0.0.0","port":25666},`+
		`"update":{"allowUnsignedUpdate":true}}`)
	if cur.Update.AllowUnsignedSince != 0 {
		t.Fatalf("当前版本的配置不该被补起点，实际 %d", cur.Update.AllowUnsignedSince)
	}
}
