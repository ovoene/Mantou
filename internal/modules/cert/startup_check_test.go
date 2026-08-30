package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"mantou/internal/config"
	"mantou/internal/logx"
)

// ---------- 启动时的证书检查 ----------
//
// 这一组钉的是那条「证书启动检查完成」日志：它是用户不点进证书页也能知道
// 「还剩几天」的唯一途径，所以措辞、张数、点名的是哪几张都算契约。

// 一张证书、一切正常时，这条日志必须正好是这句话。
func TestStartupSummaryReadsAsSpecified(t *testing.T) {
	got := startupSummary([]startupOutcome{{label: "example.com", state: startupStateOK, remaining: 45}})
	want := "证书启动检查完成，共 1 张证书；example.com 剩余有效期 45 天。"
	if got != want {
		t.Fatalf("日志文案不符：\n实际 %s\n应为 %s", got, want)
	}
}

// 三种结果各有各的说法。「已过期」与「加载不出来」尤其不能长得一样：
// 前者要去续期，后者是还没签发过或文件被人挪走了，处置完全不同。
func TestStartupOutcomeClausePerState(t *testing.T) {
	cases := []struct {
		name string
		out  startupOutcome
		want string
	}{
		{"有效", startupOutcome{label: "a.com", state: startupStateOK, remaining: 60}, "a.com 剩余有效期 60 天"},
		{"已过期", startupOutcome{label: "a.com", state: startupStateExpired}, "a.com 已过期"},
		{"未加载", startupOutcome{label: "a.com", state: startupStateUnloaded}, "a.com 尚未加载到证书，暂无法判断有效期"},
	}
	for _, tc := range cases {
		if got := tc.out.clause(); got != tc.want {
			t.Errorf("%s：实际 %q，应为 %q", tc.name, got, tc.want)
		}
	}
}

// 排序按紧迫程度，不按配置里的先后。这一条是收口那件事能成立的前提：
// 只点名前 maxSummaryCerts 张，被折叠掉的必须是最不着急的那几张。
func TestStartupCheckOrdersByUrgency(t *testing.T) {
	outs := []startupOutcome{
		{label: "ok-90", state: startupStateOK, remaining: 90},
		{label: "unloaded", state: startupStateUnloaded},
		{label: "ok-3", state: startupStateOK, remaining: 3},
		{label: "expired", state: startupStateExpired},
		{label: "ok-31", state: startupStateOK, remaining: 31},
	}
	sortStartupOutcomes(outs)
	want := []string{"expired", "ok-3", "ok-31", "ok-90", "unloaded"}
	for i, label := range want {
		if outs[i].label != label {
			t.Fatalf("第 %d 位是 %q，应为 %q（完整顺序：%v）", i+1, outs[i].label, label, labelsOf(outs))
		}
	}
}

// 证书多的时候收口，别在日志面板上留一行要横向拖动的字；
// 余下那些给出「至少还有多少天」的下界——排过序才说得出这句话。
func TestStartupSummaryCapsAndGivesLowerBound(t *testing.T) {
	outs := make([]startupOutcome, 0, 10)
	for i := 0; i < 10; i++ {
		// 故意倒着给：剩余天数从多到少，排序不生效的话点名的就是最不着急的那几张。
		outs = append(outs, startupOutcome{
			label:     fmt.Sprintf("c%d.com", i),
			state:     startupStateOK,
			remaining: (10 - i) * 10,
		})
	}
	sortStartupOutcomes(outs)
	got := startupSummary(outs)

	if !strings.Contains(got, "共 10 张证书") {
		t.Fatalf("总张数未报出：%q", got)
	}
	// 最急的是 c9.com（10 天），最不急的是 c0.com（100 天）与 c1.com（90 天）。
	if !strings.Contains(got, "c9.com 剩余有效期 10 天") {
		t.Fatalf("最紧迫的那张应被点名：%q", got)
	}
	if strings.Contains(got, "c0.com") || strings.Contains(got, "c1.com") {
		t.Fatalf("最不紧迫的两张不该逐张点名：%q", got)
	}
	if n := strings.Count(got, "剩余有效期"); n != maxSummaryCerts+1 {
		// +1 是末尾那句「另有 N 张证书剩余有效期不少于 …」。
		t.Fatalf("点名了 %d 处剩余有效期，应为 %d 处", n, maxSummaryCerts+1)
	}
	// 下界取被折叠的第一张（c1.com，90 天）：同档内升序，它就是余下那些里最少的那个。
	if !strings.Contains(got, "另有 2 张证书剩余有效期不少于 90 天") {
		t.Fatalf("收口那句的下界不对：%q", got)
	}
}

// 被折叠掉的那些里有已过期的时候，同样不能给天数下界——过期的没有「剩余多少天」可言，
// 而「不少于 0 天」这种话既没用又会让人以为那几张还有效。
// 过期的排在最前，只有它们多到挤过 maxSummaryCerts 才会落进被折叠的部分。
func TestStartupSummaryOmitsLowerBoundWhenTailExpired(t *testing.T) {
	outs := make([]startupOutcome, 0, maxSummaryCerts+3)
	for i := 0; i < maxSummaryCerts+2; i++ {
		outs = append(outs, startupOutcome{label: fmt.Sprintf("dead%d.com", i), state: startupStateExpired})
	}
	outs = append(outs, startupOutcome{label: "alive.com", state: startupStateOK, remaining: 50})
	sortStartupOutcomes(outs)
	got := startupSummary(outs)

	if !strings.Contains(got, "另有 3 张证书已检查") {
		t.Fatalf("收口那句应只报张数：%q", got)
	}
	if strings.Contains(got, "不少于") {
		t.Fatalf("被折叠的那些里有已过期的，不能给出天数下界：%q", got)
	}
}

// 被折叠掉的那些里有「加载不出来」的时候，不能给「至少还有多少天」的下界——
// 那几张的剩余天数根本不知道，给了就是编的。
func TestStartupSummaryOmitsLowerBoundWhenTailUnknown(t *testing.T) {
	outs := make([]startupOutcome, 0, maxSummaryCerts+2)
	for i := 0; i < maxSummaryCerts+1; i++ {
		outs = append(outs, startupOutcome{label: fmt.Sprintf("c%d.com", i), state: startupStateOK, remaining: 40 + i})
	}
	outs = append(outs, startupOutcome{label: "never-issued", state: startupStateUnloaded})
	sortStartupOutcomes(outs)
	got := startupSummary(outs)

	if !strings.Contains(got, "另有 2 张证书已检查") {
		t.Fatalf("收口那句应只报张数：%q", got)
	}
	if strings.Contains(got, "不少于") {
		t.Fatalf("被折叠的那些里有未加载的，不能给出天数下界：%q", got)
	}
}

// 启动检查覆盖全部证书，不只是「自动签发 + 自动续期」那一部分：
// 导入的证书一样会过期，而它恰恰没有自动续期兜着。停用的要标出来，
// 否则读日志的人会为一张根本没在用的证书白紧张一场。
func TestStartupCheckCoversImportedAndDisabledCerts(t *testing.T) {
	log := logx.New(logx.Options{})
	cfg := &testConfigWriter{}
	dir := t.TempDir()
	m := New(log, dir, cfg)
	defer m.Close()

	certPEM, keyPEM := newDatedTestCertificate(t, "kept.example.com", 40)
	if err := m.Import("cert1", certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	offPEM, offKeyPEM := newDatedTestCertificate(t, "off.example.com", 5)
	if err := m.Import("cert2", offPEM, offKeyPEM); err != nil {
		t.Fatal(err)
	}

	conf := &config.Config{Certs: []config.Certificate{
		{ID: "cert1", Name: "手工导入的", Method: "file", Enabled: true},
		{ID: "cert2", Name: "停着的", Method: "file", Enabled: false},
		{ID: "cert3", Name: "还没签发的", Method: "acme", Enabled: true},
	}}
	if err := m.Reload(conf); err != nil {
		t.Fatal(err)
	}

	line := startupCheckLine(t, log)
	for _, want := range []string{
		"共 3 张证书",
		"停着的（已停用） 剩余有效期 5 天",
		"手工导入的 剩余有效期 40 天",
		"还没签发的 尚未加载到证书，暂无法判断有效期",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("日志里缺 %q：\n%s", want, line)
		}
	}
}

// 已过期的排在最前，并且如实说「已过期」而不是「剩余有效期 0 天」。
func TestStartupCheckNamesExpiredFirst(t *testing.T) {
	log := logx.New(logx.Options{})
	m := New(log, t.TempDir(), &testConfigWriter{})
	defer m.Close()

	freshPEM, freshKey := newDatedTestCertificate(t, "fresh.example.com", 60)
	if err := m.Import("cert1", freshPEM, freshKey); err != nil {
		t.Fatal(err)
	}
	deadPEM, deadKey := newDatedTestCertificate(t, "dead.example.com", 0)
	if err := m.Import("cert2", deadPEM, deadKey); err != nil {
		t.Fatal(err)
	}

	if err := m.Reload(&config.Config{Certs: []config.Certificate{
		{ID: "cert1", Name: "还早", Method: "file", Enabled: true},
		{ID: "cert2", Name: "已经过了", Method: "file", Enabled: true},
	}}); err != nil {
		t.Fatal(err)
	}

	line := startupCheckLine(t, log)
	if !strings.Contains(line, "共 2 张证书；已经过了 已过期；还早 剩余有效期 60 天") {
		t.Fatalf("过期的那张应排在最前并如实说已过期：\n%s", line)
	}
	if strings.Contains(line, "剩余有效期 0 天") {
		t.Fatalf("过期不该报成剩余 0 天：\n%s", line)
	}
}

// 每次启动只记一条。Reload 在每次改配置后都会被调用（见 app 里的 OnConfigChanged），
// 若不区分「第一次加载」，改一次设置就多一条，日志面板很快就被这条挤满。
func TestStartupCheckLogsOncePerProcess(t *testing.T) {
	log := logx.New(logx.Options{})
	m := New(log, t.TempDir(), &testConfigWriter{})
	defer m.Close()

	certPEM, keyPEM := newDatedTestCertificate(t, "a.example.com", 20)
	if err := m.Import("cert1", certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	conf := &config.Config{Certs: []config.Certificate{{ID: "cert1", Name: "甲", Method: "file", Enabled: true}}}
	for i := 0; i < 3; i++ {
		if err := m.Reload(conf); err != nil {
			t.Fatal(err)
		}
	}
	if n := countStartupCheckLines(log); n != 1 {
		t.Fatalf("重载 3 次记了 %d 条启动检查日志，应为 1 条", n)
	}
}

// 一张证书都没有时不记：那时没有可报的内容，而一条「共 0 张」会在此后
// 每次启动都占掉首页日志里本就不多的一行。
func TestStartupCheckStaysSilentWithoutCerts(t *testing.T) {
	log := logx.New(logx.Options{})
	m := New(log, t.TempDir(), &testConfigWriter{})
	defer m.Close()

	if err := m.Reload(&config.Config{}); err != nil {
		t.Fatal(err)
	}
	if n := countStartupCheckLines(log); n != 0 {
		t.Fatalf("没有证书时记了 %d 条启动检查日志，应为 0 条", n)
	}
}

// startupCheckLine 取出那条启动检查日志，找不到或不止一条都算失败。
func startupCheckLine(t *testing.T, log *logx.Logger) string {
	t.Helper()
	var found []string
	for _, e := range log.Recent(200) {
		if strings.HasPrefix(e.Message, "证书启动检查完成") {
			found = append(found, e.Message)
		}
	}
	if len(found) != 1 {
		t.Fatalf("启动检查日志有 %d 条，应为 1 条", len(found))
	}
	return found[0]
}

func countStartupCheckLines(log *logx.Logger) int {
	n := 0
	for _, e := range log.Recent(200) {
		if strings.HasPrefix(e.Message, "证书启动检查完成") {
			n++
		}
	}
	return n
}

func labelsOf(outs []startupOutcome) []string {
	labels := make([]string, 0, len(outs))
	for _, o := range outs {
		labels = append(labels, o.label)
	}
	return labels
}

// newDatedTestCertificate 生成一张自签证书。days 即「这张证书应当被读成剩余几天」；
// days <= 0 时给出一张已经过期的。
//
// 到期时间落在那一天的正中间而不是整数天上：remainingDays 向上取整，正好压在整数天上时，
// 从这里生成到 Reload 真正读它之间过去的那点时间会让结果差 1 天，测试便会偶发地失败。
func newDatedTestCertificate(t *testing.T, domain string, days int) ([]byte, []byte) {
	t.Helper()
	notAfter := time.Now().Add(-time.Hour)
	if days > 0 {
		notAfter = time.Now().Add(time.Duration(days)*24*time.Hour - 12*time.Hour)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-2 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}
