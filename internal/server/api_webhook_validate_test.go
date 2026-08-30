package server

import (
	"strings"
	"testing"

	"mantou/internal/config"
	"mantou/internal/modules/webhook"
)

// 本文件盯的是保存接收器时的校验。
//
// 这里挡下的每一条都是"存得下但跑不起来"的配置：运行期只能记一条警告然后让规则失效，
// 用户在界面上看不到自己错在哪。所以每个用例断言的不只是"被拒了"，
// 还包括**拒绝理由里有没有那句能照着改的话**——没有指向性的错误等于没拦。

// vcfg 一份"什么都齐了"的配置：模块已创建，模板与通知目标各一个。
//
// Webhook.Created 必须为真：模块没创建就没有监听、没有域名，启用接收器只会得到
// 一条永远收不到消息的配置，validateReceiver 会直接拦下（见「模块未创建时不能启用」用例）。
func vcfg() *config.Config {
	return &config.Config{
		Webhook:          config.WebhookServer{Created: true, Enabled: true, Listen: "0.0.0.0", Port: config.DefaultWebhookPort},
		MessageTemplates: []config.MessageTemplate{{ID: "t1", Name: "汇总模板"}},
		NotifyTargets:    []config.NotifyTarget{{ID: "g1", Name: "运维群"}},
	}
}

// okReceiver 一个能通过全部校验的接收器。每个用例只改自己关心的那一项，
// 断言失败时才能确定是那一项引起的。
func okReceiver() config.WebhookReceiver {
	return config.WebhookReceiver{
		ID: "r1", Name: "第三方系统", Enabled: true, Path: "hook",
		// 保存路径上 NormalizeReceiver 先跑一遍，落到这里的 SourceType 一定已经是
		// json 或 txt；直接调 validateReceiver 的测试得自己补上。
		SourceType:     "json",
		DefaultTargets: []string{"g1"},
		Rules: []config.WebhookRule{{
			ID: "ru1", Name: "每日汇总", Enabled: true, TemplateRef: "t1",
			Conditions: []config.Condition{{Path: "body.消息类型", Op: "eq", Value: "每日汇总"}},
		}},
	}
}

func TestValidateReceiverAccepts(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*config.Config, *config.WebhookReceiver)
	}{
		{"最小可用配置", nil},
		// 没有条件的规则是合法的"兜底规则"：一个接收器只发一种消息时最常见。
		{"规则无条件", func(_ *config.Config, r *config.WebhookReceiver) {
			r.Rules[0].Conditions = nil
		}},
		// 规则自己配了目标，接收器就不必再有默认目标。
		{"规则自带目标", func(_ *config.Config, r *config.WebhookReceiver) {
			r.DefaultTargets = nil
			r.Rules[0].Targets = []string{"g1"}
		}},
		{"没有任何规则", func(_ *config.Config, r *config.WebhookReceiver) { r.Rules = nil }},
		// 输出分支：规则级的模板与目标此时不参与运行，因此清空也该放行——
		// 拿一个不生效的格子卡人，用户只会在那里反复填。
		{"规则用输出分支", func(c *config.Config, r *config.WebhookReceiver) {
			c.MessageTemplates = append(c.MessageTemplates, config.MessageTemplate{ID: "t2", Name: "大额模板"})
			c.NotifyTargets = append(c.NotifyTargets, config.NotifyTarget{ID: "g2", Name: "财务群"})
			r.Rules[0].TemplateRef = ""
			r.Rules[0].Targets = nil
			r.Rules[0].Branches = []config.RuleBranch{
				{Name: "大额", Match: "all", TemplateRef: "t2", Targets: []string{"g2"},
					Conditions: []config.Condition{{Path: "body.数值", Op: "gt", Value: "10000"}}},
				{Name: "其余", TemplateRef: "t1", Targets: []string{"g1"}},
			}
		}},
		// 分支不带目标时回落到接收器的默认目标，与规则级同口径。
		{"分支不带目标", func(_ *config.Config, r *config.WebhookReceiver) {
			r.Rules[0].TemplateRef = ""
			r.Rules[0].Branches = []config.RuleBranch{{Name: "唯一", TemplateRef: "t1"}}
		}},
		// 改自己不该被自己的路径挡住。
		{"路径与自己相同", func(c *config.Config, r *config.WebhookReceiver) {
			c.WebhookReceivers = []config.WebhookReceiver{{ID: "r1", Name: "旧的自己", Path: "hook"}}
		}},
		// 关掉开关后名单不再参与校验：用户可能留着名单先临时放行。
		{"IP过滤关闭时名单不校验", func(_ *config.Config, r *config.WebhookReceiver) {
			r.AllowIPs = []string{"这不是一个IP"}
		}},
		{"IP白名单有效", func(_ *config.Config, r *config.WebhookReceiver) {
			r.IPFilter, r.IPFilterMode = true, "allow"
			r.AllowIPs = []string{"192.168.1.10", "10.0.0.0/8", "192.168.1.1-192.168.1.99"}
		}},
		{"关键词准入有效", func(_ *config.Config, r *config.WebhookReceiver) {
			r.KeywordFilter, r.Keywords = true, []string{"每日汇总", "已审核"}
		}},
		{"关键词准入全部模式", func(_ *config.Config, r *config.WebhookReceiver) {
			r.KeywordFilter, r.KeywordMode, r.Keywords = true, "all", []string{"每日", "已审核"}
		}},
		// 与 IP 名单同口径：开关关着时词表整体不校验（这里连数量都超了），
		// 用户可能先填好词、再决定要不要开。
		{"关键词关闭时词表不校验", func(_ *config.Config, r *config.WebhookReceiver) {
			r.Keywords = make([]string, config.MaxWebhookKeywords+1)
		}},
		{"来源类型选txt", func(_ *config.Config, r *config.WebhookReceiver) {
			r.SourceType = "txt"
		}},
		// 数量比较（"创建人大于 1"）的比较值是个数，填数字就该放行。
		{"数量比较值是数字", func(_ *config.Config, r *config.WebhookReceiver) {
			r.Rules[0].Conditions[0].Op = "countGt"
			r.Rules[0].Conditions[0].Value = "1"
		}},
		{"汉字映射名", func(_ *config.Config, r *config.WebhookReceiver) {
			r.Mappings = []config.FieldMapping{{Name: "消息编号", Path: "body.消息编号"}}
		}},
		// 模块还没创建时**停用中**的接收器照样能存：用户的顺序常常是先把接收器配好，
		// 再去建模块。只有"启用"那一侧才拦（见下面的拒绝用例）。
		{"模块未创建但接收器是停用的", func(c *config.Config, r *config.WebhookReceiver) {
			c.Webhook = config.WebhookServer{}
			r.Enabled = false
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, rc := vcfg(), okReceiver()
			if c.mut != nil {
				c.mut(cfg, &rc)
			}
			if err := validateReceiver(cfg, rc); err != nil {
				t.Fatalf("应通过校验，实际被拒：%v", err)
			}
		})
	}
}

func TestValidateReceiverRejects(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*config.Config, *config.WebhookReceiver)
		want string // 拒绝理由里必须出现的片段
	}{
		{"名称为空", func(_ *config.Config, r *config.WebhookReceiver) { r.Name = "" }, "名称不能为空"},
		// 模块没创建就没有监听、没有域名、没有可访问的地址：此刻"启用中"是纯粹的假象，
		// 而列表上那个绿开关会让人以为它在工作。错误里必须写清下一步该干什么。
		{"模块未创建时不能启用", func(c *config.Config, _ *config.WebhookReceiver) {
			c.Webhook = config.WebhookServer{}
		}, "模块设置"},
		{"路径过长", func(_ *config.Config, r *config.WebhookReceiver) {
			r.Path = strings.Repeat("a", config.MaxWebhookPathLen+1)
		}, "入站路径过长"},
		// 两个接收器共用同一个地址时，后一个永远收不到消息（运行期只有一条警告）。
		// 错误里要带上占用者的名字，否则用户不知道去改哪一个。
		{"路径与他人重复", func(c *config.Config, r *config.WebhookReceiver) {
			c.WebhookReceivers = []config.WebhookReceiver{{ID: "r9", Name: "Grafana", Path: "hook"}}
		}, "Grafana"},
		// 没起名字的接收器要退回 ID，不能显示成「」。
		{"重复时占用者无名则显示ID", func(c *config.Config, r *config.WebhookReceiver) {
			c.WebhookReceivers = []config.WebhookReceiver{{ID: "r9", Path: "hook"}}
		}, "r9"},

		{"选了令牌鉴权但没填令牌", func(_ *config.Config, r *config.WebhookReceiver) {
			r.AuthType = "token"
		}, "必须设置令牌"},
		{"选了请求头鉴权但没填令牌", func(_ *config.Config, r *config.WebhookReceiver) {
			r.AuthType = "header"
		}, "必须设置令牌"},
		{"请求头鉴权没填头名", func(_ *config.Config, r *config.WebhookReceiver) {
			r.AuthType, r.Token = "header", "秘密"
		}, "请求头名称"},

		// 空白名单会把所有来源都拒掉，空黑名单则等于没开——两种都不是用户的本意。
		{"白名单为空", func(_ *config.Config, r *config.WebhookReceiver) {
			r.IPFilter, r.IPFilterMode = true, "allow"
		}, "白名单不能为空"},
		{"黑名单为空", func(_ *config.Config, r *config.WebhookReceiver) {
			r.IPFilter, r.IPFilterMode = true, "deny"
		}, "黑名单不能为空"},
		// 逐条校验才能指出是哪一条：整批解析对认不出的条目是静默跳过的。
		{"名单条目无法识别", func(_ *config.Config, r *config.WebhookReceiver) {
			r.IPFilter, r.IPFilterMode = true, "allow"
			r.AllowIPs = []string{"192.168.1.1", "192.168.1.999"}
		}, "192.168.1.999"},

		// 开着关键词准入却没填词：运行期是失败开放（等于没开），但用户以为自己开了内容准入。
		// 这里必须拦住，错误里还要说清"留空的后果"，否则他只会再填一次空的。
		{"关键词为空", func(_ *config.Config, r *config.WebhookReceiver) {
			r.KeywordFilter = true
		}, "关键词不能为空"},
		{"关键词数量超上限", func(_ *config.Config, r *config.WebhookReceiver) {
			r.KeywordFilter = true
			r.Keywords = make([]string, config.MaxWebhookKeywords+1)
			for i := range r.Keywords {
				r.Keywords[i] = "词" + strings.Repeat("x", i)
			}
		}, "关键词数量超过上限"},
		// 长词多半是把整段正文粘进来了：那种词永远匹配不上，而界面上只表现为"一条都收不到"。
		{"单个关键词过长", func(_ *config.Config, r *config.WebhookReceiver) {
			r.KeywordFilter = true
			r.Keywords = []string{strings.Repeat("采", config.MaxWebhookKeywordLen+1)}
		}, "过长"},

		{"字段映射超上限", func(_ *config.Config, r *config.WebhookReceiver) {
			r.Mappings = make([]config.FieldMapping, config.MaxWebhookMappings+1)
		}, "字段映射数量超过上限"},
		{"规则超上限", func(_ *config.Config, r *config.WebhookReceiver) {
			r.Rules = make([]config.WebhookRule, config.MaxWebhookRules+1)
		}, "消息规则数量超过上限"},
		{"条件超上限", func(_ *config.Config, r *config.WebhookReceiver) {
			r.Rules[0].Conditions = make([]config.Condition, config.MaxWebhookConditions+1)
		}, "条件数量超过上限"},

		// 映射名会直接进模板（{{.名字}}），带空格或以数字开头的名字模板里写不出来。
		{"映射名带空格", func(_ *config.Config, r *config.WebhookReceiver) {
			r.Mappings = []config.FieldMapping{{Name: "消息 编号", Path: "body.x"}}
		}, "不能用在模板里"},
		{"映射名以数字开头", func(_ *config.Config, r *config.WebhookReceiver) {
			r.Mappings = []config.FieldMapping{{Name: "1号", Path: "body.x"}}
		}, "不能用在模板里"},
		{"映射名重复", func(_ *config.Config, r *config.WebhookReceiver) {
			r.Mappings = []config.FieldMapping{
				{Name: "编号", Path: "body.a"}, {Name: "编号", Path: "body.b"},
			}
		}, "重复"},
		// 与信封键同名会让 {{.source}} 时而是来源名、时而是业务字段。
		{"映射名与内置字段冲突", func(_ *config.Config, r *config.WebhookReceiver) {
			r.Mappings = []config.FieldMapping{{Name: webhook.ReservedFieldNames[0], Path: "body.x"}}
		}, "与内置字段冲突"},
		{"映射路径为空", func(_ *config.Config, r *config.WebhookReceiver) {
			r.Mappings = []config.FieldMapping{{Name: "编号"}}
		}, "取值路径不能为空"},

		{"规则没有名称", func(_ *config.Config, r *config.WebhookReceiver) { r.Rules[0].Name = "" }, "都要有名称"},
		{"规则没选模板", func(_ *config.Config, r *config.WebhookReceiver) { r.Rules[0].TemplateRef = "" }, "未选择消息模板"},
		// 模板被删掉之后引用它的规则会在运行期静默失效。
		{"规则引用的模板不存在", func(_ *config.Config, r *config.WebhookReceiver) {
			r.Rules[0].TemplateRef = "已删除的模板"
		}, "消息模板不存在"},
		{"规则目标已被删除", func(_ *config.Config, r *config.WebhookReceiver) {
			r.Rules[0].Targets = []string{"已删除的群"}
		}, "已被删除的目标"},
		{"默认目标已被删除", func(_ *config.Config, r *config.WebhookReceiver) {
			r.DefaultTargets = []string{"已删除的群"}
		}, "已被删除的目标"},
		// 两处都空就是一条永远发不出去的规则。
		{"规则与接收器都没有目标", func(_ *config.Config, r *config.WebhookReceiver) {
			r.DefaultTargets = nil
		}, "没有通知目标"},

		// ---- 输出分支 ----
		// 分支只在保存时校验得出来：运行期一个配坏的分支只会记一条编译告警，
		// 而它的兄弟分支照样在发消息，用户看到的是"有的群收到了、有的群没收到"。
		{"分支没有名称", func(_ *config.Config, r *config.WebhookReceiver) {
			r.Rules[0].Branches = []config.RuleBranch{{TemplateRef: "t1", Targets: []string{"g1"}}}
		}, "每个输出分支都要有名称"},
		// 同名分支在执行历史里长得一模一样，那一列恰恰是排查"谁没收到"的唯一依据。
		{"分支名重复", func(_ *config.Config, r *config.WebhookReceiver) {
			r.Rules[0].Branches = []config.RuleBranch{
				{Name: "大额", TemplateRef: "t1", Targets: []string{"g1"}},
				{Name: "大额", TemplateRef: "t1", Targets: []string{"g1"}},
			}
		}, "「大额」重复"},
		{"分支没选模板", func(_ *config.Config, r *config.WebhookReceiver) {
			r.Rules[0].Branches = []config.RuleBranch{{Name: "大额", Targets: []string{"g1"}}}
		}, "未选择消息模板"},
		{"分支引用的模板不存在", func(_ *config.Config, r *config.WebhookReceiver) {
			r.Rules[0].Branches = []config.RuleBranch{
				{Name: "大额", TemplateRef: "已删除的模板", Targets: []string{"g1"}},
			}
		}, "消息模板不存在"},
		{"分支目标已被删除", func(_ *config.Config, r *config.WebhookReceiver) {
			r.Rules[0].Branches = []config.RuleBranch{
				{Name: "大额", TemplateRef: "t1", Targets: []string{"已删除的群"}},
			}
		}, "已被删除的目标"},
		{"分支与接收器都没有目标", func(_ *config.Config, r *config.WebhookReceiver) {
			r.DefaultTargets = nil
			r.Rules[0].Branches = []config.RuleBranch{{Name: "大额", TemplateRef: "t1"}}
		}, "没有通知目标"},
		{"分支条件没填取值路径", func(_ *config.Config, r *config.WebhookReceiver) {
			r.Rules[0].Branches = []config.RuleBranch{{
				Name: "大额", TemplateRef: "t1", Targets: []string{"g1"},
				Conditions: []config.Condition{{Op: "gt", Value: "1000"}},
			}}
		}, "没填取值路径"},
		{"分支数量超上限", func(_ *config.Config, r *config.WebhookReceiver) {
			r.Rules[0].Branches = make([]config.RuleBranch, config.MaxWebhookBranches+1)
		}, "输出分支数量超过上限"},
		// 一条规则可以有十个分支，只说"未选择消息模板"没法让人找到那一格：
		// 错误里要同时点出规则名与分支名。
		{"错误同时指向规则与分支", func(_ *config.Config, r *config.WebhookReceiver) {
			r.Rules[0].Branches = []config.RuleBranch{
				{Name: "正常的", TemplateRef: "t1", Targets: []string{"g1"}},
				{Name: "配坏的", Targets: []string{"g1"}},
			}
		}, "规则「每日汇总」的分支「配坏的」"},

		{"条件判断方式不支持", func(_ *config.Config, r *config.WebhookReceiver) {
			r.Rules[0].Conditions[0].Op = "差不多等于"
		}, "不支持的判断方式"},
		// 空路径在运行期取不到任何值，于是条件永远不成立（exists 永假、empty 永真），
		// 表现为"规则配了却不生效"——错误里要连怎么填都给出来。
		{"条件没填取值路径", func(_ *config.Config, r *config.WebhookReceiver) {
			r.Rules[0].Conditions[0].Path = ""
		}, "没填取值路径，请填写要判断的字段"},
		// 坏正则在运行期只能让这条规则永不命中，保存时编译一次才能把错误还给用户。
		{"正则无法编译", func(_ *config.Config, r *config.WebhookReceiver) {
			r.Rules[0].Conditions[0].Op = "regex"
			r.Rules[0].Conditions[0].Value = "([0-9"
		}, "正则表达式无法编译"},
		// 错误里要指出是哪一条规则，接收器上可能有十几条。
		{"错误指向具体规则", func(_ *config.Config, r *config.WebhookReceiver) {
			r.Rules[0].TemplateRef = "没有这个"
		}, "每日汇总"},

		// 数量比较的比较值必须是数字：填了别的，这条条件在运行期永远不成立
		// （见 webhook.matchCount），界面上只表现为"规则配了却不生效"。
		{"数量比较值不是数字", func(_ *config.Config, r *config.WebhookReceiver) {
			r.Rules[0].Conditions[0].Op = "countGt"
			r.Rules[0].Conditions[0].Value = "一个"
		}, "数量比较值必须是数字"},
		{"数量比较值为空", func(_ *config.Config, r *config.WebhookReceiver) {
			r.Rules[0].Conditions[0].Op = "countGte"
			r.Rules[0].Conditions[0].Value = ""
		}, "数量比较值必须是数字"},
		// 只支持 auto、json、kv 与 txt 四种来源；第五种值会让 decodeBody 落到自动识别，
		// 而用户以为自己选的是别的东西。
		{"来源类型不支持", func(_ *config.Config, r *config.WebhookReceiver) {
			r.SourceType = "xml"
		}, "只支持 auto、json、kv 或 txt"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, rc := vcfg(), okReceiver()
			c.mut(cfg, &rc)
			err := validateReceiver(cfg, rc)
			if err == nil {
				t.Fatal("应被拒绝，实际通过了校验")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("拒绝理由应包含 %q，实际 %q", c.want, err.Error())
			}
		})
	}
}

// 上限校验必须排在逐条校验之前：一份被批量导入的坏配置里，
// "有 300 条规则"比"第 7 条规则没名字"更接近真正的原因。
func TestValidateReceiverLimitBeforeDetail(t *testing.T) {
	rc := okReceiver()
	rc.Rules = make([]config.WebhookRule, config.MaxWebhookRules+1) // 全是空规则，逐条校验也会失败
	err := validateReceiver(vcfg(), rc)
	if err == nil || !strings.Contains(err.Error(), "超过上限") {
		t.Fatalf("应先报数量超限，实际 %v", err)
	}
}

func TestNameOrID(t *testing.T) {
	cases := []struct{ name, id, want string }{
		{"运维群", "g1", "运维群"},
		{"", "g1", "g1"},
		{"   ", "g1", "g1"}, // 只有空白等于没起名
		{"  运维群  ", "g1", "运维群"},
		{"", "", ""},
	}
	for _, c := range cases {
		if got := nameOrID(c.name, c.id); got != c.want {
			t.Errorf("nameOrID(%q, %q) = %q，应为 %q", c.name, c.id, got, c.want)
		}
	}
}

func TestCheckLimit(t *testing.T) {
	if err := checkLimit("规则", 3, 3); err != nil {
		t.Fatalf("刚好等于上限应放行：%v", err)
	}
	err := checkLimit("规则", 4, 3)
	if err == nil {
		t.Fatal("超过上限应拒绝")
	}
	// 上限与当前数量都要写进错误：用户要据此决定删几条。
	if !strings.Contains(err.Error(), "3") || !strings.Contains(err.Error(), "4") {
		t.Fatalf("错误里应同时有上限与当前数量：%q", err.Error())
	}
}

func TestCheckTargets(t *testing.T) {
	valid := map[string]bool{"g1": true}
	if err := checkTargets("默认目标", nil, valid); err != nil {
		t.Fatalf("空列表应放行：%v", err)
	}
	if err := checkTargets("默认目标", []string{"g1"}, valid); err != nil {
		t.Fatalf("有效目标应放行：%v", err)
	}
	if err := checkTargets("默认目标", []string{"g1", "gone"}, valid); err == nil {
		t.Fatal("含已删除目标应拒绝")
	}
}
