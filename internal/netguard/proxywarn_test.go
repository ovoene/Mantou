package netguard

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"mantou/internal/logx"
)

// 「内网防护开启」与「环境里配了代理」两个设置各自都合理，撞在一起的后果是所有
// 由用户配置驱动的出站请求一起失败：防护路径刻意直连（理由见 newTransport 里那段），
// 于是在只有代理才能出网的环境里，DDNS 取不到公网地址、计划任务的 HTTP 动作打不通、
// Webhook 推不出去。而用户看到的只是一条条普通的超时与连接被拒，上面没有任何地方
// 写着是那个开关干的。这条告警是唯一的线索。
//
// 所以两个方向都要钉住：该出现时必须出现，不该出现时必须闭嘴——后者不是洁癖，
// plainTransport 那条路是**真的**会用代理的，在那里说「代理被忽略」是假话，
// 会把排查的人推向完全错误的方向。

// captureWarn 清空所有代理环境变量，换上一个可读的全局 Logger，跑 fn，返回期间的日志。
//
// 先清空是必须的：开发机与 CI 上本来就可能配着 HTTPS_PROXY，不清的话
// 「没配代理就不该告警」那条用例会随环境时红时绿。env 里的键值在清空之后设置。
func captureWarn(t *testing.T, env map[string]string, fn func()) []logx.Entry {
	t.Helper()
	for _, k := range proxyEnvVars {
		t.Setenv(k, "")
	}
	for k, v := range env {
		t.Setenv(k, v)
	}
	log := logx.New(logx.Options{MaxEntries: 16})
	logx.SetGlobal(log)
	// 归还「未设置」状态：下次 L() 会惰性造一个仅控制台的兜底 Logger，与测试二进制
	// 启动时一致，不会把这个环形缓冲留给同包里别的测试。
	defer logx.SetGlobal(nil)
	fn()
	return log.Recent(16)
}

// warnEntry 找出那条「代理被忽略」的告警。按文案片段匹配而不是按整条消息比对：
// 措辞往后会改，这条测试要盯的是"有没有告警、说没说清"，不是逐字复述文案。
func warnEntry(entries []logx.Entry) (logx.Entry, bool) {
	for _, e := range entries {
		if strings.Contains(e.Message, "环境里的代理设置不会被使用") {
			return e, true
		}
	}
	return logx.Entry{}, false
}

// fieldVal 取出日志字段的值。字段表是切片（logx.Fields），没有按键查的方法。
func fieldVal(e logx.Entry, key string) (string, bool) {
	for _, f := range e.Fields {
		if f.Key == key {
			return fmt.Sprint(f.Val), true
		}
	}
	return "", false
}

func TestGuardedTransportWarnsProxyIgnored(t *testing.T) {
	entries := captureWarn(t, map[string]string{"HTTPS_PROXY": "http://127.0.0.1:8080"}, func() {
		newTransport(true)
	})
	e, ok := warnEntry(entries)
	if !ok {
		t.Fatalf("防护开启且环境里配了代理，必须留一条告警，实际日志 %+v", entries)
	}
	if e.Level != "WARN" {
		t.Errorf("这条应当是 WARN，实际 %s", e.Level)
	}
	// 得点出是哪个变量被忽略了：只说「代理不会被使用」的话，
	// 用户还要自己翻遍 profile、compose 文件和 systemd unit 去猜是哪一处。
	if v, ok := fieldVal(e, "ignoredEnv"); !ok || !strings.Contains(v, "HTTPS_PROXY") {
		t.Errorf("告警里应点出被忽略的环境变量名，实际字段 %+v", e.Fields)
	}
	// 后果也要写出来，否则读日志的人不会把这条与他遇到的超时联系起来。
	for _, want := range []string{"直连", "DDNS"} {
		if !strings.Contains(e.Message, want) {
			t.Errorf("告警里应包含 %q，实际 %q", want, e.Message)
		}
	}
}

// TestGuardedTransportQuietWithoutProxyEnv 没配代理就不该有这条告警。
//
// 内网防护是个正常功能，绝大多数用户开着它、且从不用代理。这条告警若变成
// 「开了防护就报一条」，它就成了背景噪音——而它要提醒的那个坑是真会让所有出站
// 请求全部失败的，被当成噪音忽略掉的代价太大。
func TestGuardedTransportQuietWithoutProxyEnv(t *testing.T) {
	entries := captureWarn(t, nil, func() { newTransport(true) })
	if e, ok := warnEntry(entries); ok {
		t.Fatalf("环境里没有代理设置，不该告警，实际 %q %+v", e.Message, e.Fields)
	}
}

// TestPlainTransportNeverWarns 防护关闭时不告警——那条路是真的会用代理的。
func TestPlainTransportNeverWarns(t *testing.T) {
	env := map[string]string{"HTTP_PROXY": "http://127.0.0.1:8080"}
	entries := captureWarn(t, env, func() { newTransport(false) })
	if e, ok := warnEntry(entries); ok {
		t.Fatalf("防护关闭时代理是生效的，报「被忽略」是假话：%q", e.Message)
	}
}

// TestWarnProxyIgnoredRecognizesEveryVar proxyEnvVars 里每个名字都真的会被认出来。
//
// 逐个走一遍而不是只测一个：这张表里大小写两种写法都常见（shell profile 里多是小写，
// 容器与 CI 里多是大写），漏掉任何一个都会让那半边环境静默踩坑。
func TestWarnProxyIgnoredRecognizesEveryVar(t *testing.T) {
	for _, k := range proxyEnvVars {
		t.Run(k, func(t *testing.T) {
			entries := captureWarn(t, map[string]string{k: "http://127.0.0.1:8080"}, func() {
				newTransport(true)
			})
			e, ok := warnEntry(entries)
			if !ok {
				t.Fatalf("配了 %s 却没告警", k)
			}
			if v, _ := fieldVal(e, "ignoredEnv"); !strings.Contains(v, k) {
				t.Errorf("告警里应列出 %s，实际 %q", k, v)
			}
		})
	}
}

// TestWhitespaceProxyValueIsNotConfigured 值是空白的变量按「没配」算。
//
// `HTTP_PROXY=` 与 `HTTP_PROXY=" "` 在 compose 文件与 CI 配置里很常见（占位、
// 或被某个模板渲染成了空），Go 自己也把空值当成没设代理。跟着它一致，
// 免得这条告警在一个根本没有代理的环境里天天出现。
func TestWhitespaceProxyValueIsNotConfigured(t *testing.T) {
	entries := captureWarn(t, map[string]string{"HTTP_PROXY": "   "}, func() { newTransport(true) })
	if e, ok := warnEntry(entries); ok {
		t.Fatalf("空白值应按未配置算，不该告警：%+v", e.Fields)
	}
}

// TestTransportProxyPolicyMatchesWarning 钉住告警所依据的那个事实本身：
// 防护开启的 Transport 不带 Proxy，关闭的带。
//
// 告警文案说的是「代理不会被使用」。哪天有人给防护路径补上 tr.Proxy，
// 这条告警就从提醒变成误报，而它自己测不出这件事——所以在这里直接验字段。
func TestTransportProxyPolicyMatchesWarning(t *testing.T) {
	var guarded, plain *http.Transport
	captureWarn(t, nil, func() {
		guarded, plain = newTransport(true), newTransport(false)
	})
	if guarded.Proxy != nil {
		t.Error("防护开启的 Transport 不该带 Proxy（钩子只会校验代理地址，防护会形同虚设）")
	}
	if plain.Proxy == nil {
		t.Error("防护关闭的 Transport 应尊重 HTTP_PROXY / HTTPS_PROXY / NO_PROXY")
	}
}
