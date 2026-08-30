package cert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"mantou/internal/config"
	"mantou/internal/logx"
)

type testConfigWriter struct {
	mu  sync.Mutex
	cfg config.Config
}

func (w *testConfigWriter) Update(mutate func(*config.Config)) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	mutate(&w.cfg)
	return nil
}

// UpdateState 在测试里与 Update 等价：真实实现的差别只在持久化目标
// （state.json 而非 config.json）与落盘时机，对内存语义没有影响。
func (w *testConfigWriter) UpdateState(mutate func(*config.Config)) error {
	return w.Update(mutate)
}

func (w *testConfigWriter) Get() *config.Config {
	w.mu.Lock()
	defer w.mu.Unlock()
	cfg := w.cfg
	return &cfg
}

// Snapshot 在测试里同样返回值拷贝：真实实现返回共享的只读快照，
// 而测试断言只读取字段，返回拷贝可额外保证测试用例之间不会互相影响。
func (w *testConfigWriter) Snapshot() *config.Config { return w.Get() }

type countingIssuer struct {
	calls int
}

func (i *countingIssuer) Issue(context.Context, config.Certificate, *config.ACMEAccount, string, map[string]string, func(string)) ([]byte, []byte, error) {
	i.calls++
	return nil, nil, nil
}

func TestRenewDueSkipsCertificateOutsideWindow(t *testing.T) {
	cfg := newACMETestConfig(func(c *config.Certificate) {
		c.AutoRenew = true
		c.RenewBeforeDays = 30
	})
	m := New(logx.New(logx.Options{}), t.TempDir(), cfg)
	defer m.Close()
	issuer := &countingIssuer{}
	m.SetIssuer(issuer)
	m.store.mu.Lock()
	m.store.byID["cert1"] = &storedCert{notAfter: time.Now().Add(31 * 24 * time.Hour)}
	m.store.mu.Unlock()

	result, err := m.RenewDue(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result != "已续期 0 张证书" {
		t.Fatalf("unexpected result: %s", result)
	}
	if issuer.calls != 0 {
		t.Fatalf("issuer called %d times", issuer.calls)
	}
}

// 续期检查的触发判定：一分钟 ticker 会漂移、宿主会休眠，
// 因此不能要求"当前分钟恰好等于续期时刻"，而应"过了时刻且今天没跑过就补跑"。
func TestRenewCheckDueCatchesUpAfterMissedTargetMinute(t *testing.T) {
	m := New(logx.New(logx.Options{}), t.TempDir(), &testConfigWriter{})
	defer m.Close()

	day := func(h, min int) time.Time { return time.Date(2026, 8, 19, h, min, 0, 0, time.Local) }

	if m.renewCheckDue("cert1", "03:00", day(2, 59)) {
		t.Fatal("未到续期时刻不应触发")
	}
	// 03:00 那一分钟被整个跳过（GC 停顿 / 休眠 / CPU 限流），05:30 的心跳必须补跑。
	if !m.renewCheckDue("cert1", "03:00", day(5, 30)) {
		t.Fatal("错过目标分钟后应补跑")
	}
	// 当天此后不再重复触发。
	if m.renewCheckDue("cert1", "03:00", day(5, 31)) {
		t.Fatal("同一天不应重复触发")
	}
	// 各证书独立计日：另一张证书的较晚时刻不受影响。
	if !m.renewCheckDue("cert2", "05:00", day(5, 31)) {
		t.Fatal("不同证书应各自独立判定")
	}
	// 次日重新开始。
	if !m.renewCheckDue("cert1", "03:00", day(3, 0).AddDate(0, 0, 1)) {
		t.Fatal("次日应重新触发")
	}
}

// 未设置续期时刻时用默认 03:00；时刻非法（脏数据）也退回默认，而不是永远跳过续期。
func TestRenewCheckDueFallsBackToDefaultTime(t *testing.T) {
	m := New(logx.New(logx.Options{}), t.TempDir(), &testConfigWriter{})
	defer m.Close()

	at := func(h, min int) time.Time { return time.Date(2026, 8, 19, h, min, 0, 0, time.Local) }
	if m.renewCheckDue("empty", "", at(2, 59)) {
		t.Fatal("空续期时刻应按默认 03:00 判定")
	}
	if !m.renewCheckDue("empty", "", at(3, 0)) {
		t.Fatal("到达默认 03:00 应触发")
	}
	if m.renewCheckDue("bad", "25:99", at(2, 59)) {
		t.Fatal("非法续期时刻应退回默认 03:00 判定")
	}
	if !m.renewCheckDue("bad", "25:99", at(3, 1)) {
		t.Fatal("非法续期时刻不应导致永久跳过续期")
	}
}

// 证书被删除后，其续期检查记录应随重载一并清理，不在内存里长期残留。
func TestReloadPrunesRenewCheckRecords(t *testing.T) {
	m := New(logx.New(logx.Options{}), t.TempDir(), &testConfigWriter{})
	defer m.Close()

	if !m.renewCheckDue("gone", "03:00", time.Date(2026, 8, 19, 4, 0, 0, 0, time.Local)) {
		t.Fatal("首次判定应触发")
	}
	if err := m.Reload(&config.Config{}); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	remaining := len(m.lastRenewCheck)
	m.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("已删除证书的检查记录未清理，剩余 %d 条", remaining)
	}
}

func TestRemainingDaysRoundsUp(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.Local)
	if got := remainingDays(now.Add(30*24*time.Hour+time.Second), now); got != 31 {
		t.Fatalf("expected 31 remaining days, got %d", got)
	}
	if got := remainingDays(now.Add(-time.Second), now); got != 0 {
		t.Fatalf("expected expired certificate to have 0 remaining days, got %d", got)
	}
}

func TestRenewalDueUsesRoundedRemainingDays(t *testing.T) {
	now := time.Date(2026, 3, 1, 3, 30, 0, 0, time.Local)
	if !renewalDueAt(now.Add(30*24*time.Hour), 30, now) {
		t.Fatal("expected certificate at the renewal boundary to be due")
	}
	if renewalDueAt(now.Add(30*24*time.Hour+time.Second), 30, now) {
		t.Fatal("expected certificate with 31 rounded remaining days not to be due")
	}
}

func TestStorePathsRejectTraversal(t *testing.T) {
	store := NewStore(t.TempDir())
	if _, _, err := store.Paths("../secret"); err == nil {
		t.Fatal("expected invalid certificate ID error")
	}
}

func TestStoreSaveValidatesTemporaryFilesBeforeReplacing(t *testing.T) {
	store := NewStore(t.TempDir())
	oldCert, oldKey := newStoreTestCertificate(t, "old.example.com", 1)
	if err := store.Save("cert1", oldCert, oldKey); err != nil {
		t.Fatal(err)
	}

	_, mismatchedKey := newStoreTestCertificate(t, "other.example.com", 2)
	if err := store.Save("cert1", oldCert, mismatchedKey); err == nil {
		t.Fatal("expected mismatched certificate pair error")
	}

	assertStoredCertificatePair(t, store, "cert1", oldCert, oldKey, "old.example.com")
}

func TestStoreSaveRemovesPreviousDomainIndex(t *testing.T) {
	store := NewStore(t.TempDir())
	oldCert, oldKey := newStoreTestCertificate(t, "old.example.com", 1)
	if err := store.Save("cert1", oldCert, oldKey); err != nil {
		t.Fatal(err)
	}
	newCert, newKey := newStoreTestCertificate(t, "new.example.com", 2)
	if err := store.Save("cert1", newCert, newKey); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Resolve("old.example.com"); ok {
		t.Fatal("old domain index must be removed after certificate replacement")
	}
	if _, ok := store.Resolve("new.example.com"); !ok {
		t.Fatal("new domain index was not loaded")
	}
}

func TestReloadClearsRemovedCertificateIndexes(t *testing.T) {
	dir := t.TempDir()
	cfg := &testConfigWriter{}
	m := New(logx.New(logx.Options{}), dir, cfg)
	defer m.Close()
	certPEM, keyPEM := newStoreTestCertificate(t, "removed.example.com", 1)
	if err := m.store.Save("removed", certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	if err := m.Reload(&config.Config{}); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.ResolveID("removed"); ok {
		t.Fatal("removed certificate ID must not remain indexed after reload")
	}
	if _, ok := m.Resolver()("removed.example.com"); ok {
		t.Fatal("removed certificate domain must not remain indexed after reload")
	}
}

func TestStoreSaveRollsBackWhenPrivateKeyReplacementFails(t *testing.T) {
	store := NewStore(t.TempDir())
	oldCert, oldKey := newStoreTestCertificate(t, "old.example.com", 1)
	if err := store.Save("cert1", oldCert, oldKey); err != nil {
		t.Fatal(err)
	}
	newCert, newKey := newStoreTestCertificate(t, "new.example.com", 2)
	keyPath := store.keyPath("cert1")
	originalRename := store.rename
	failed := false
	store.rename = func(oldPath, newPath string) error {
		if newPath == keyPath && !failed {
			failed = true
			return errors.New("replace private key failed")
		}
		return originalRename(oldPath, newPath)
	}

	if err := store.Save("cert1", newCert, newKey); err == nil || !strings.Contains(err.Error(), "replace private key failed") {
		t.Fatalf("expected private key replacement error, got %v", err)
	}

	assertStoredCertificatePair(t, store, "cert1", oldCert, oldKey, "old.example.com")
}

func assertStoredCertificatePair(t *testing.T, store *Store, id string, certPEM, keyPEM []byte, domain string) {
	t.Helper()
	storedCertPEM, storedKeyPEM, err := store.Export(id, true)
	if err != nil {
		t.Fatal(err)
	}
	if string(storedCertPEM) != string(certPEM) {
		t.Fatal("stored certificate changed after failed save")
	}
	if string(storedKeyPEM) != string(keyPEM) {
		t.Fatal("stored private key changed after failed save")
	}
	resolved, ok := store.Resolve(domain)
	if !ok || resolved.Leaf == nil || resolved.Leaf.Subject.CommonName != domain {
		t.Fatal("in-memory certificate changed after failed save")
	}
}

func newStoreTestCertificate(t *testing.T, domain string, serial int64) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
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
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

type blockingIssuer struct {
	started chan struct{}
	release chan struct{}
	onStart func()
	certPEM []byte
	keyPEM  []byte
	err     error
}

func (i *blockingIssuer) Issue(ctx context.Context, _ config.Certificate, _ *config.ACMEAccount, _ string, _ map[string]string, _ func(string)) ([]byte, []byte, error) {
	close(i.started)
	if i.onStart != nil {
		i.onStart()
	}
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-i.release:
		return i.certPEM, i.keyPEM, i.err
	}
}

func TestIssueAsyncPersistsOperationStatesAndRejectsDuplicate(t *testing.T) {
	cfg := newACMETestConfig()
	m := New(logx.New(logx.Options{}), t.TempDir(), cfg)
	defer m.Close()
	issuer := &blockingIssuer{started: make(chan struct{}), release: make(chan struct{}), err: context.DeadlineExceeded}
	m.SetIssuer(issuer)

	if err := m.IssueAsync("cert1", time.Minute); err != nil {
		t.Fatal(err)
	}
	state := cfg.Get().Certs[0].IssueStatus.State
	if state != "pending" && state != "running" {
		t.Fatalf("expected pending or running state, got %q", state)
	}
	<-issuer.started
	if state := cfg.Get().Certs[0].IssueStatus.State; state != "running" {
		t.Fatalf("expected running state, got %q", state)
	}
	if err := m.IssueAsync("cert1", time.Minute); err == nil {
		t.Fatal("expected duplicate issue request to be rejected")
	}
	close(issuer.release)
	deadline := time.Now().Add(time.Second)
	for cfg.Get().Certs[0].IssueStatus.State != "failed" && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if state := cfg.Get().Certs[0].IssueStatus.State; state != "failed" {
		t.Fatalf("expected failed state, got %q", state)
	}
}

func TestIssueAsyncHonorsTimeout(t *testing.T) {
	cfg := newACMETestConfig()
	m := New(logx.New(logx.Options{}), t.TempDir(), cfg)
	defer m.Close()
	issuer := &blockingIssuer{started: make(chan struct{}), release: make(chan struct{})}
	m.SetIssuer(issuer)

	if err := m.IssueAsync("cert1", 10*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	<-issuer.started
	deadline := time.Now().Add(time.Second)
	for cfg.Get().Certs[0].IssueStatus.State != "failed" && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	status := cfg.Get().Certs[0].IssueStatus
	if status.State != "failed" || !strings.Contains(status.Message, context.DeadlineExceeded.Error()) {
		t.Fatalf("expected deadline failure status, got %#v", status)
	}
}

func TestIssueAsyncRejectsManualRenewalOutsideWindow(t *testing.T) {
	cfg := newACMETestConfig(func(c *config.Certificate) { c.RenewBeforeDays = 30 })
	m := New(logx.New(logx.Options{}), t.TempDir(), cfg)
	defer m.Close()
	issuer := &countingIssuer{}
	m.SetIssuer(issuer)
	m.store.mu.Lock()
	m.store.byID["cert1"] = &storedCert{notAfter: time.Now().Add(30*24*time.Hour + time.Second)}
	m.store.mu.Unlock()

	err := m.IssueAsync("cert1", time.Minute)
	if err == nil || !strings.Contains(err.Error(), "当前剩余 31 天") {
		t.Fatalf("expected renewal window error with rounded-up days, got %v", err)
	}
	if issuer.calls != 0 {
		t.Fatalf("issuer called %d times", issuer.calls)
	}
}

func TestIssueAsyncUsesRenewStatusForExistingCertificate(t *testing.T) {
	cfg := newACMETestConfig(func(c *config.Certificate) { c.RenewBeforeDays = 30 })
	m := New(logx.New(logx.Options{}), t.TempDir(), cfg)
	defer m.Close()
	issuer := &blockingIssuer{started: make(chan struct{}), release: make(chan struct{}), err: context.DeadlineExceeded}
	m.SetIssuer(issuer)
	m.store.mu.Lock()
	m.store.byID["cert1"] = &storedCert{notAfter: time.Now().Add(10 * 24 * time.Hour)}
	m.store.mu.Unlock()

	if err := m.IssueAsync("cert1", time.Minute); err != nil {
		t.Fatal(err)
	}
	<-issuer.started
	state := cfg.Get().Certs[0]
	if state.RenewStatus.State != "running" {
		t.Fatalf("expected running renewal state, got %q", state.RenewStatus.State)
	}
	if state.IssueStatus.State != "" {
		t.Fatalf("issue state must remain unchanged, got %q", state.IssueStatus.State)
	}
	close(issuer.release)
	deadline := time.Now().Add(time.Second)
	for cfg.Get().Certs[0].RenewStatus.State != "failed" && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if state := cfg.Get().Certs[0].RenewStatus.State; state != "failed" {
		t.Fatalf("expected failed renewal state, got %q", state)
	}
}

func TestIssueAndRenewalShareCertificateLock(t *testing.T) {
	cfg := newACMETestConfig()
	m := New(logx.New(logx.Options{}), t.TempDir(), cfg)
	defer m.Close()
	issuer := &blockingIssuer{started: make(chan struct{}), release: make(chan struct{}), err: context.DeadlineExceeded}
	m.SetIssuer(issuer)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = m.Issue(context.Background(), "cert1")
	}()
	<-issuer.started

	if _, err := m.issueExclusive(context.Background(), "cert1", true); err == nil || !strings.Contains(err.Error(), "签发或续期中") {
		t.Fatalf("expected shared certificate lock error, got %v", err)
	}
	close(issuer.release)
	<-done
}

type selfWritingIssuer struct {
	cfg        *testConfigWriter
	certPEM    []byte
	keyPEM     []byte
	accountKey string
}

func (i *selfWritingIssuer) Issue(_ context.Context, _ config.Certificate, account *config.ACMEAccount, _ string, _ map[string]string, _ func(string)) ([]byte, []byte, error) {
	account.PrivateKeyPEM = i.accountKey
	_ = i.cfg.Update(func(c *config.Config) {
		for idx := range c.ACMEAccounts {
			if c.ACMEAccounts[idx].ID == account.ID {
				c.ACMEAccounts[idx].PrivateKeyPEM = i.accountKey
				return
			}
		}
	})
	return i.certPEM, i.keyPEM, nil
}

func TestFirstIssueAcceptsIssuerAccountKeyWriteBack(t *testing.T) {
	cfg := newACMETestConfig()
	m := New(logx.New(logx.Options{}), t.TempDir(), cfg)
	defer m.Close()
	certPEM, keyPEM := newStoreTestCertificate(t, "example.com", 1)
	issuer := &selfWritingIssuer{cfg: cfg, certPEM: certPEM, keyPEM: keyPEM, accountKey: "generated-account-key"}
	m.SetIssuer(issuer)

	result, err := m.Issue(context.Background(), "cert1")
	if err != nil {
		t.Fatal(err)
	}
	if result != "issue-success" {
		t.Fatalf("unexpected result: %s", result)
	}
	current := cfg.Get()
	if current.ACMEAccounts[0].PrivateKeyPEM != issuer.accountKey {
		t.Fatal("generated account key was not persisted")
	}
	if current.Certs[0].IssueStatus.State != "success" {
		t.Fatalf("expected success state, got %q", current.Certs[0].IssueStatus.State)
	}
	storedCert, storedKey, err := m.store.Export("cert1", true)
	if err != nil {
		t.Fatal(err)
	}
	if string(storedCert) != string(certPEM) || string(storedKey) != string(keyPEM) {
		t.Fatal("issued certificate pair was not saved")
	}
}

func TestIssueRejectsChangedACMEConfigBeforeSave(t *testing.T) {
	cfg := newACMETestConfig()
	m := New(logx.New(logx.Options{}), t.TempDir(), cfg)
	defer m.Close()
	release := make(chan struct{})
	close(release)
	issuer := &blockingIssuer{
		started: make(chan struct{}),
		release: release,
		certPEM: []byte("certificate"),
		keyPEM:  []byte("key"),
		onStart: func() {
			_ = cfg.Update(func(c *config.Config) {
				c.Certs = append([]config.Certificate(nil), c.Certs...)
				c.Certs[0].Domains = []string{"changed.example.com"}
			})
		},
	}
	m.SetIssuer(issuer)

	if _, err := m.Issue(context.Background(), "cert1"); err == nil || !strings.Contains(err.Error(), "关键 ACME 配置已变更") {
		t.Fatalf("expected changed ACME config error, got %v", err)
	}
	certPath, _, err := m.store.Paths("cert1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(certPath); !os.IsNotExist(err) {
		t.Fatalf("certificate must not be saved, stat error: %v", err)
	}
}

func TestIssueRejectsDeletedConfigBeforeSave(t *testing.T) {
	cfg := newACMETestConfig()
	m := New(logx.New(logx.Options{}), t.TempDir(), cfg)
	defer m.Close()
	release := make(chan struct{})
	close(release)
	issuer := &blockingIssuer{
		started: make(chan struct{}),
		release: release,
		certPEM: []byte("certificate"),
		keyPEM:  []byte("key"),
		onStart: func() {
			_ = cfg.Update(func(c *config.Config) {
				c.Certs = nil
			})
		},
	}
	m.SetIssuer(issuer)

	if _, err := m.Issue(context.Background(), "cert1"); err == nil || !strings.Contains(err.Error(), "配置已不存在") {
		t.Fatalf("expected deleted config error, got %v", err)
	}
}

func TestUpdateOperationStatusReturnsErrorWhenCertificateMissing(t *testing.T) {
	cfg := &testConfigWriter{}
	m := New(logx.New(logx.Options{}), t.TempDir(), cfg)
	defer m.Close()

	if err := m.updateOperationStatus("missing", false, "running", "正在签发", 0); err == nil || !strings.Contains(err.Error(), "找不到证书") {
		t.Fatalf("expected missing certificate error, got %v", err)
	}
}

// newACMETestConfig 返回一份配置齐备（域名 / ACME 账户 / DNS 凭证俱全）的 ACME 证书测试配置；
// mutate 可按需调整该证书的字段。配置必须齐备：issue 在向 CA 下单之前会执行 precheckIssue 预检，
// 缺少任一必需引用都会在调用签发器之前直接失败（签发器的 Issue 根本不会被调用）。
func newACMETestConfig(mutate ...func(*config.Certificate)) *testConfigWriter {
	cfg := &testConfigWriter{cfg: config.Config{
		Certs: []config.Certificate{{
			ID:             "cert1",
			Method:         "acme",
			Domains:        []string{"example.com"},
			ACMEChallenge:  "dns01",
			CredentialRef:  "credential1",
			ACMEAccountRef: "account1",
		}},
		ACMEAccounts: []config.ACMEAccount{{ID: "account1", CA: "letsencrypt", Email: "admin@example.com"}},
		Credentials:  []config.Credential{{ID: "credential1", Provider: "cloudflare", Secrets: map[string]string{"apiToken": "secret"}}},
	}}
	for _, fn := range mutate {
		fn(&cfg.cfg.Certs[0])
	}
	return cfg
}

// stubbornIssuer 模拟「context 已取消、但收尾还没做完」的签发器。
// 真实实现里就是这个形状：acme.go 注册的 TXT 清理回调刻意用 context.Background()
// + 30 秒超时，好在进程退出时也能把 _acme-challenge 记录删掉。
type stubbornIssuer struct {
	started  chan struct{}
	canceled chan struct{} // 观察到 ctx 被取消时关闭
	release  chan struct{} // 关闭后模拟「收尾完成」
}

func newStubbornIssuer() *stubbornIssuer {
	return &stubbornIssuer{
		started:  make(chan struct{}),
		canceled: make(chan struct{}),
		release:  make(chan struct{}),
	}
}

func (i *stubbornIssuer) Issue(ctx context.Context, _ config.Certificate, _ *config.ACMEAccount, _ string, _ map[string]string, _ func(string)) ([]byte, []byte, error) {
	close(i.started)
	<-ctx.Done()
	close(i.canceled)
	<-i.release
	return nil, nil, ctx.Err()
}

func TestCloseCancelsAndWaitsForInflightIssue(t *testing.T) {
	cfg := newACMETestConfig()
	m := New(logx.New(logx.Options{}), t.TempDir(), cfg)
	issuer := newStubbornIssuer()
	m.SetIssuer(issuer)

	// IssueAsync 的超时给足 30 分钟：这里要验证的是 Close 取消了它，而不是它自己超时。
	if err := m.IssueAsync("cert1", 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	<-issuer.started

	closed := make(chan struct{})
	go func() {
		_ = m.Close()
		close(closed)
	}()

	// Close 必须立刻取消在飞签发的 context（否则它会抱着 30 分钟超时空转）。
	select {
	case <-issuer.canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("Close 没有取消在飞签发的 context")
	}
	// 但在收尾完成前不得返回。
	select {
	case <-closed:
		t.Fatal("Close 在签发收尾之前就返回了")
	case <-time.After(50 * time.Millisecond):
	}

	close(issuer.release)
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("签发已收尾但 Close 仍未返回")
	}
}

func TestCloseGivesUpAfterGrace(t *testing.T) {
	original := closeGrace
	closeGrace = 30 * time.Millisecond
	t.Cleanup(func() { closeGrace = original })

	cfg := newACMETestConfig()
	m := New(logx.New(logx.Options{}), t.TempDir(), cfg)
	issuer := newStubbornIssuer()
	// 永不 release：模拟签发卡死。Close 应在 closeGrace 后放手，而不是永久挂住关机流程。
	t.Cleanup(func() { close(issuer.release) })
	m.SetIssuer(issuer)

	if err := m.IssueAsync("cert1", 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	<-issuer.started

	done := make(chan struct{})
	go func() {
		_ = m.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close 未在等待窗口后放手")
	}
}

func TestCloseIsIdempotentAndRejectsNewIssue(t *testing.T) {
	cfg := newACMETestConfig()
	m := New(logx.New(logx.Options{}), t.TempDir(), cfg)
	m.SetIssuer(&countingIssuer{})

	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	// 自更新路径会先显式 CloseAll 再 exec，exec 失败时 defer 里还会再调一次。
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if err := m.IssueAsync("cert1", time.Minute); err == nil {
		t.Fatal("关闭后仍受理了异步签发")
	}
	if _, err := m.Issue(context.Background(), "cert1"); err == nil {
		t.Fatal("关闭后仍受理了同步签发")
	}
}

// ---------- 续期检查日志的措辞（第 5 项） ----------

// 一张证书、一切正常时，这条日志必须正好是要求的那句话。
// 逐字比对不是吹毛求疵：这条日志是用户日常唯一能确认"续期这件事还在运转"的证据，
// 少一个数字就得去翻证书列表，那这条日志就白写了。
func TestRenewSummaryReadsAsSpecified(t *testing.T) {
	got := renewSummary([]renewOutcome{{
		label: "example.com", state: renewStateOK, known: true,
		remaining: 45, before: 30,
	}}, false)
	want := "证书自动续期检查完成，example.com 证书正常，当前剩余有效期 45 天，将在 15 天后自动续期。"
	if got != want {
		t.Fatalf("日志文案不符：\n实际 %s\n应为 %s", got, want)
	}
}

// 多张证书之间用「；」分隔。每一句里本身就有逗号，全用逗号连会糊成一句读不断的话。
func TestRenewSummarySeparatesCertsWithSemicolon(t *testing.T) {
	got := renewSummary([]renewOutcome{
		{label: "a.com", state: renewStateOK, known: true, remaining: 45, before: 30},
		{label: "b.com", state: renewStateRenewed, known: true, remaining: 90, before: 30},
	}, false)
	want := "证书自动续期检查完成，a.com 证书正常，当前剩余有效期 45 天，将在 15 天后自动续期；" +
		"b.com 已完成续期，当前剩余有效期 90 天，将在 60 天后自动续期。"
	if got != want {
		t.Fatalf("多张证书的文案不符：\n实际 %s\n应为 %s", got, want)
	}
}

// 四种结果各有各的说法，尤其"该续没续成"和"证书正常"不能长得一样。
func TestRenewOutcomeClausePerState(t *testing.T) {
	cases := []struct {
		name string
		out  renewOutcome
		want string
	}{
		{"正常", renewOutcome{label: "a.com", state: renewStateOK, known: true, remaining: 60, before: 30},
			"a.com 证书正常，当前剩余有效期 60 天，将在 30 天后自动续期"},
		{"已续期", renewOutcome{label: "a.com", state: renewStateRenewed, known: true, remaining: 90, before: 30},
			"a.com 已完成续期，当前剩余有效期 90 天，将在 60 天后自动续期"},
		{"续期失败", renewOutcome{label: "a.com", state: renewStateFailed},
			"a.com 续期失败"},
		{"未加载", renewOutcome{label: "a.com", state: renewStateUnloaded},
			"a.com 尚未加载到证书，暂无法判断有效期"},
	}
	for _, tc := range cases {
		if got := tc.out.clause(); got != tc.want {
			t.Errorf("%s：实际 %q，应为 %q", tc.name, got, tc.want)
		}
	}
}

// 续期成功但读不回新的到期时间时，不能报「剩余 0 天」——那是错的，
// 而且刚好是最容易引起误会的一种错（用户会以为续期把证书弄坏了）。
func TestRenewedWithoutFreshExpiryOmitsRemaining(t *testing.T) {
	got := renewOutcome{label: "a.com", state: renewStateRenewed, before: 30}.clause()
	if want := "a.com 已完成续期"; got != want {
		t.Fatalf("实际 %q，应为 %q", got, want)
	}
	if strings.Contains(got, "0 天") {
		t.Fatalf("读不到到期时间时不能报出天数：%q", got)
	}
}

// 剩余有效期不足「提前续期天数」时，不硬凑成「将在 0 天后自动续期」。
func TestNextHintNeverSaysZeroDays(t *testing.T) {
	for _, remaining := range []int{0, 10, 30} {
		got := renewOutcome{label: "a.com", state: renewStateOK, known: true, remaining: remaining, before: 30}.clause()
		if strings.Contains(got, "将在 0 天后") || strings.Contains(got, "将在 -") {
			t.Fatalf("remaining=%d 时文案不合理：%q", remaining, got)
		}
		if !strings.Contains(got, "下次检查时将自动续期") {
			t.Fatalf("remaining=%d 时应说明下次检查即续期：%q", remaining, got)
		}
	}
}

// 证书多的时候收口，别让日志面板上出现一行要横向拖动的字。
func TestRenewSummaryCapsNamedCerts(t *testing.T) {
	outs := make([]renewOutcome, 0, 10)
	for i := 0; i < 10; i++ {
		outs = append(outs, renewOutcome{
			label: string(rune('a'+i)) + ".com", state: renewStateOK, known: true,
			remaining: 45, before: 30,
		})
	}
	got := renewSummary(outs, false)
	if !strings.Contains(got, "另有 2 张证书检查完成") {
		t.Fatalf("未收口：%q", got)
	}
	if strings.Contains(got, "i.com") || strings.Contains(got, "j.com") {
		t.Fatalf("第 9、10 张不该逐个点名：%q", got)
	}
	if !strings.Contains(got, "h.com") {
		t.Fatalf("前 8 张应逐个点名：%q", got)
	}
	if n := strings.Count(got, "证书正常"); n != maxSummaryCerts {
		t.Fatalf("点名了 %d 张，应为 %d 张", n, maxSummaryCerts)
	}
}

// 名字空了退到域名；两个都空给固定说法，不把内部 ID 印进日志。
func TestCertLabelFallsBackToDomain(t *testing.T) {
	id := "c-8f3a1b2c4d5e"
	cases := []struct {
		name string
		cert config.Certificate
		want string
	}{
		{"有名字", config.Certificate{ID: id, Name: "我的证书", Domains: []string{"a.com"}}, "我的证书"},
		{"名字是空白", config.Certificate{ID: id, Name: "   ", Domains: []string{"a.com"}}, "a.com"},
		{"域名前有空白项", config.Certificate{ID: id, Domains: []string{"", " ", "b.com"}}, "b.com"},
		{"两者都空", config.Certificate{ID: id}, "未命名证书"},
	}
	for _, tc := range cases {
		got := certLabel(tc.cert)
		if got != tc.want {
			t.Errorf("%s：实际 %q，应为 %q", tc.name, got, tc.want)
		}
		if strings.Contains(got, id) {
			t.Errorf("%s：日志名字里不该出现内部 ID（%q）", tc.name, got)
		}
	}
}

// 本轮被关机或整轮超时打断时，开头不能写「检查完成」：这条日志汇报的只是已经查过的
// 那几张，写「完成」等于连没查的也一并宣布查过了——而下一次要排查"为什么某张证书
// 没续期"时，靠的正是这条日志说的话。
func TestRenewSummarySaysSoWhenRoundWasCutShort(t *testing.T) {
	outs := []renewOutcome{{label: "a.com", state: renewStateOK, known: true, remaining: 45, before: 30}}
	got := renewSummary(outs, true)
	if strings.Contains(got, "检查完成") {
		t.Fatalf("本轮没跑完，不能说「检查完成」：%q", got)
	}
	if !strings.HasPrefix(got, "证书自动续期检查提前结束") {
		t.Fatalf("应说明本轮提前结束：%q", got)
	}
	// 已经查过的那张仍要照常汇报，否则它今天在日志里就凭空消失了。
	if !strings.Contains(got, "a.com 证书正常，当前剩余有效期 45 天") {
		t.Fatalf("已查过的证书没被汇报：%q", got)
	}
}
