package cert

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// maxCertFileBytes 路径证书（Method="path"）单个文件的读取上限。
// 证书链 PEM 常见 2–8KB、私钥 1–3KB，256KB 已是极宽松的余量。
// 需要上限是因为这两个路径由用户在界面上填：os.ReadFile 对字符设备
// （如 /dev/zero，Stat 报告大小为 0）会一直把缓冲区扩下去，一次配置变更就能吃光内存。
const maxCertFileBytes = 256 << 10

// storedCert 是内存中一张已加载证书的运行态。
type storedCert struct {
	id       string
	tlsCert  tls.Certificate
	leaf     *x509.Certificate
	domains  []string
	notAfter time.Time
}

// Store 负责证书 PEM 文件的读写与内存索引（按域名匹配）。
//
// 落盘的内容是明文 PEM，不经 config 那套主密钥加密（`enc:v1:` / secretBox）。这是取舍，
// 不是漏项：证书文件要能被直接查看（`openssl x509 -in`）与被机器上别的软件直接使用。
//
// 代价必须写下来，因为它与主密钥方案自陈的威胁模型（"data 目录被整体带走"）正好相反：
// 一份 <id>.key 足以冒充该域名做 TLS，直到证书到期为止。也就是说 **s.dir 的敏感度与
// config.json 相同**——备份走面板的加密导出（证书与私钥都在里面），要直接拷目录就按
// "这份拷贝里有可用的私钥"对待。ACME 账户私钥（能代表你申请证书）反而是加密的，
// 这个不对称是有意的。README 的「凭证加密与配置主密钥」一节记着同一件事，改动请同步。
type Store struct {
	mu     sync.RWMutex
	fileMu sync.RWMutex
	dir    string
	byID   map[string]*storedCert
	byName map[string]nameClaim // 域名（含通配，键统一小写）→ 证书
	// staging 非 nil 表示正在整份重建索引：期间装载的证书写进它，旧索引照旧对外服务，
	// commitIndex 时整份换上去（见 beginIndexSwap）。
	staging *certIndex
	rename  func(string, string) error
}

// certIndex 一整份证书索引。
type certIndex struct {
	byID   map[string]*storedCert
	byName map[string]nameClaim
}

func newCertIndex() *certIndex {
	return &certIndex{byID: make(map[string]*storedCert), byName: make(map[string]nameClaim)}
}

// nameClaim 一条「域名 → 证书」索引项。
//
// 记着这个名字是怎么来的：SAN 的 DNSNames，还是 Subject.CommonName。
// 两者撞车时得有个说法，见 claimWins。
type nameClaim struct {
	cert  *storedCert
	viaCN bool
}

// nameKey 归一化索引键。域名大小写不敏感（RFC 4343），而 SNI 里的大小写由客户端决定，
// 证书里的 DNSNames 也不保证是小写的（自签与内部 CA 签出大写域名并不罕见）。
// 两侧都折成小写，才不会出现"证书明明覆盖了这个域名，握手却说无可用证书"。
func nameKey(d string) string { return strings.ToLower(strings.TrimSpace(d)) }

// NewStore 创建证书存储，dir 为证书文件目录（data/certs）。
func NewStore(dir string) *Store {
	return &Store{
		dir:    dir,
		byID:   make(map[string]*storedCert),
		byName: make(map[string]nameClaim),
		rename: os.Rename,
	}
}

func (s *Store) certPath(id string) string { return filepath.Join(s.dir, id+".crt") }
func (s *Store) keyPath(id string) string  { return filepath.Join(s.dir, id+".key") }

func validCertID(id string) bool {
	return id != "" && filepath.Base(id) == id && id != "." && id != ".."
}

func (s *Store) Paths(id string) (string, string, error) {
	if !validCertID(id) {
		return "", "", fmt.Errorf("无效的证书 ID")
	}
	certPath, err := filepath.Abs(s.certPath(id))
	if err != nil {
		return "", "", err
	}
	keyPath, err := filepath.Abs(s.keyPath(id))
	if err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

func (s *Store) Export(id string, includePrivateKey bool) ([]byte, []byte, error) {
	s.fileMu.RLock()
	defer s.fileMu.RUnlock()

	certPath, keyPath, err := s.Paths(id)
	if err != nil {
		return nil, nil, err
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("读取证书文件失败: %w", err)
	}
	if !includePrivateKey {
		return certPEM, nil, nil
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("读取私钥文件失败: %w", err)
	}
	return certPEM, keyPEM, nil
}

// Save 将证书与私钥 PEM 写入磁盘并加载到内存索引。
//
// 两个文件都是明文 PEM，权限分开：证书 0644（本就是公开信息），私钥 0600。
// 明文落盘的取舍与它的代价见 Store 的注释。
func (s *Store) Save(id string, certPEM, keyPEM []byte) error {
	if !validCertID(id) {
		return fmt.Errorf("无效的证书 ID")
	}

	s.fileMu.Lock()
	defer s.fileMu.Unlock()

	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return err
	}
	certTmp, err := writeTempFile(s.dir, id+"-*.crt", certPEM, 0o644)
	if err != nil {
		return err
	}
	defer os.Remove(certTmp)
	keyTmp, err := writeTempFile(s.dir, id+"-*.key", keyPEM, 0o600)
	if err != nil {
		return err
	}
	defer os.Remove(keyTmp)

	sc, err := loadStoredCert(id, certTmp, keyTmp)
	if err != nil {
		return err
	}
	if err := s.replaceFiles(s.certPath(id), s.keyPath(id), certTmp, keyTmp); err != nil {
		return err
	}
	s.setIndexed(sc)
	return nil
}

func writeTempFile(dir, pattern string, data []byte, perm os.FileMode) (string, error) {
	file, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", err
	}
	name := file.Name()
	if err := file.Chmod(perm); err != nil {
		file.Close()
		os.Remove(name)
		return "", err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		os.Remove(name)
		return "", err
	}
	if err := file.Close(); err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}

func (s *Store) replaceFiles(certPath, keyPath, certTmp, keyTmp string) error {
	certBackup, err := s.backupFile(certPath)
	if err != nil {
		return err
	}
	keyBackup, err := s.backupFile(keyPath)
	if err != nil {
		return errors.Join(err, s.restoreFile(certPath, certBackup))
	}

	if err := s.rename(certTmp, certPath); err != nil {
		return errors.Join(err, s.restoreFiles(certPath, keyPath, certBackup, keyBackup))
	}
	if err := s.rename(keyTmp, keyPath); err != nil {
		removeErr := os.Remove(certPath)
		if os.IsNotExist(removeErr) {
			removeErr = nil
		}
		return errors.Join(err, removeErr, s.restoreFiles(certPath, keyPath, certBackup, keyBackup))
	}

	if certBackup != "" {
		_ = os.Remove(certBackup)
	}
	if keyBackup != "" {
		_ = os.Remove(keyBackup)
	}
	return nil
}

func (s *Store) backupFile(path string) (string, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	file, err := os.CreateTemp(s.dir, filepath.Base(path)+"-*.bak")
	if err != nil {
		return "", err
	}
	backup := file.Name()
	if err := file.Close(); err != nil {
		os.Remove(backup)
		return "", err
	}
	if err := os.Remove(backup); err != nil {
		return "", err
	}
	if err := s.rename(path, backup); err != nil {
		return "", err
	}
	return backup, nil
}

func (s *Store) restoreFile(path, backup string) error {
	if backup == "" {
		return nil
	}
	return s.rename(backup, path)
}

func (s *Store) restoreFiles(certPath, keyPath, certBackup, keyBackup string) error {
	certErr := s.restoreFile(certPath, certBackup)
	keyErr := s.restoreFile(keyPath, keyBackup)
	if certErr == nil && keyErr != nil && certBackup != "" {
		if err := s.rename(certPath, certBackup); err != nil {
			certErr = errors.Join(certErr, err)
		}
	}
	return errors.Join(certErr, keyErr)
}

// LoadAll 从磁盘加载全部证书（按已知 ID 列表）。
func (s *Store) LoadAll(ids []string) {
	for _, id := range ids {
		if !validCertID(id) {
			// 非法 ID（含路径遍历 ../ 或空）跳过，避免加载时越出证书目录。
			continue
		}
		if err := s.load(id); err != nil {
			// 缺失或损坏的证书跳过，不阻断启动。
			continue
		}
	}
}

// LoadFromFiles 从任意磁盘路径读取证书对并以 id 建立索引（method=path 使用，不复制到存储目录）。
func (s *Store) LoadFromFiles(id, certFile, keyFile string) error {
	if !validCertID(id) {
		return fmt.Errorf("无效的证书 ID")
	}
	certPEM, keyPEM, err := readCertPairFiles(certFile, keyFile)
	if err != nil {
		return err
	}
	// index 里的 parseStoredCert 就是「证书 + 配套私钥」那道校验：解析不出来就不建索引。
	return s.index(id, certPEM, keyPEM)
}

// ReadVerifiedPair 从任意磁盘路径读出一对证书文件，校验它们确实是
// 「一张证书 + 与之配套的私钥」，通过后返回原始 PEM。
//
// 校验不是为了挑剔格式。这两个路径由用户在界面上填，而导出接口会把读到的内容
// 原样回给调用方：不校验的话，「新建一张 path 证书指向 /etc/shadow → 调一次导出」
// 就是一次任意文件读，读取权限等于面板进程权限（常是 root）。要求私钥与证书配得上，
// 则连「指向 /root/.ssh/id_rsa」这类本身是合法 PEM 的文件也一并挡掉。
//
// 能用的路径证书本来就满足这个条件——通不过的话 Reload 那侧就加载不了它，
// 面板里也用不上——所以这里不会拦下任何一份可用的配置。
func (s *Store) ReadVerifiedPair(certFile, keyFile string) ([]byte, []byte, error) {
	certPEM, keyPEM, err := readCertPairFiles(certFile, keyFile)
	if err != nil {
		return nil, nil, err
	}
	// id 只用于填充返回的索引项，这里只要它的校验结果，故传空串。
	if _, err := parseStoredCert("", certPEM, keyPEM); err != nil {
		return nil, nil, err
	}
	return certPEM, keyPEM, nil
}

// readCertPairFiles 读取一对路径证书文件，各自受 maxCertFileBytes 限制。
func readCertPairFiles(certFile, keyFile string) ([]byte, []byte, error) {
	certPEM, err := readCertFile(certFile)
	if err != nil {
		return nil, nil, fmt.Errorf("读取证书文件失败: %w", err)
	}
	keyPEM, err := readCertFile(keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("读取私钥文件失败: %w", err)
	}
	return certPEM, keyPEM, nil
}

// readCertFile 读取一个路径证书文件，最多 maxCertFileBytes 字节。
// 超限按错误返回而不是截断：截断会把「路径指错了」伪装成「PEM 解析失败」。
func readCertFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// 多读 1 字节，用于区分「刚好等于上限」（合法）与「超出上限」。
	data, err := io.ReadAll(io.LimitReader(f, maxCertFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxCertFileBytes {
		return nil, fmt.Errorf("文件超过 %dKB，不像证书文件", maxCertFileBytes>>10)
	}
	return data, nil
}

// load 读取单张证书并建立索引。
func (s *Store) load(id string) error {
	if !validCertID(id) {
		return fmt.Errorf("无效的证书 ID")
	}
	s.fileMu.RLock()
	defer s.fileMu.RUnlock()

	sc, err := loadStoredCert(id, s.certPath(id), s.keyPath(id))
	if err != nil {
		return err
	}
	s.setIndexed(sc)
	return nil
}

func loadStoredCert(id, certPath, keyPath string) (*storedCert, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	return parseStoredCert(id, certPEM, keyPEM)
}

// index 解析证书对并写入内存索引。
func (s *Store) index(id string, certPEM, keyPEM []byte) error {
	sc, err := parseStoredCert(id, certPEM, keyPEM)
	if err != nil {
		return err
	}
	s.setIndexed(sc)
	return nil
}

func parseStoredCert(id string, certPEM, keyPEM []byte) (*storedCert, error) {
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("解析证书对失败: %w", err)
	}
	leaf, err := leafFromPEM(certPEM)
	if err != nil {
		return nil, err
	}
	tlsCert.Leaf = leaf

	return &storedCert{
		id:       id,
		tlsCert:  tlsCert,
		leaf:     leaf,
		domains:  leaf.DNSNames,
		notAfter: leaf.NotAfter,
	}, nil
}

// beginIndexSwap 开始整份重建索引：之后装载的证书写进旁边那份新索引，
// 由 commitIndex 一次换上去。
//
// 不能改成"先清空再逐个装载"（原来就是那样）：清空之后到装完之间有一个窗口，
// 期间任何 TLS 握手都取不到证书，浏览器直接报握手失败。而这个窗口是每次保存配置
// 都会经过的——证书越多、路径证书要读的磁盘文件越多，窗口越长。
func (s *Store) beginIndexSwap() {
	s.mu.Lock()
	s.staging = newCertIndex()
	s.mu.Unlock()
}

// commitIndex 把重建好的索引换上去。没在重建中则什么都不做。
func (s *Store) commitIndex() {
	s.mu.Lock()
	if s.staging != nil {
		s.byID, s.byName = s.staging.byID, s.staging.byName
		s.staging = nil
	}
	s.mu.Unlock()
}

func (s *Store) setIndexed(sc *storedCert) {
	s.mu.Lock()
	defer s.mu.Unlock()

	byID, byName := s.byID, s.byName
	if s.staging != nil {
		byID, byName = s.staging.byID, s.staging.byName
	}

	// 同一个 ID 的旧条目先摘掉，否则改了域名的证书会把旧域名一直留在索引里。
	//
	// 摘掉之后不去"让原本输给它的证书重新认领这个名字"：索引里不留败者。代价是
	// 删掉一张证书后，另一张同样覆盖该域名的证书要等下一次整份重建（保存配置或重启）
	// 才会接上——而删证书本身就会触发一次重建，所以够了。
	if previous, ok := byID[sc.id]; ok {
		for name, claim := range byName {
			if claim.cert == previous {
				delete(byName, name)
			}
		}
	}
	byID[sc.id] = sc

	now := time.Now()
	claim := func(name string, viaCN bool) {
		key := nameKey(name)
		if key == "" {
			return
		}
		next := nameClaim{cert: sc, viaCN: viaCN}
		if cur, ok := byName[key]; ok && !claimWins(cur, next, now) {
			return
		}
		byName[key] = next
	}
	for _, d := range sc.leaf.DNSNames {
		claim(d, false)
	}
	claim(sc.leaf.Subject.CommonName, true)
}

// claimWins 判断 next 该不该顶掉 cur 占着的那个域名。
//
// 原来是无条件覆盖，于是两张覆盖同一域名的证书（换签期间新旧并存、或一张通配加一张
// 单域名）谁生效取决于装载顺序，而装载顺序来自配置里的排列——用户在列表里拖一下顺序，
// 线上用的证书就换了一张，界面上没有任何地方说明这件事。更糟的是过期的那张也能赢，
// 表现为"明明装了新证书，浏览器还说证书过期"。
//
// 优先级从高到低：
//
//  1. SAN（DNSNames）压过 CommonName。CN 早已废弃（RFC 2818 起就不该用它做域名匹配，
//     Chrome 58+ 直接忽略），一张 CN 恰好撞上的证书不该顶掉正经在 SAN 里写着这个域名的。
//  2. 没过期的压过已过期的。
//  3. 都有效（或都过期）时，到期晚的赢——换签期间新旧并存，该用新的那张。
//  4. 完全并列时按 ID 定序。纯粹为了确定性：并列还让装载顺序说话的话，同一份配置
//     两次启动可能用不同的证书，而这种问题没人查得出来。
func claimWins(cur, next nameClaim, now time.Time) bool {
	if cur.cert == nil {
		return true
	}
	if cur.viaCN != next.viaCN {
		return cur.viaCN
	}
	curValid, nextValid := now.Before(cur.cert.notAfter), now.Before(next.cert.notAfter)
	if curValid != nextValid {
		return nextValid
	}
	if !next.cert.notAfter.Equal(cur.cert.notAfter) {
		return next.cert.notAfter.After(cur.cert.notAfter)
	}
	return next.cert.id < cur.cert.id
}

// Resolve 依据 SNI 域名返回匹配证书，支持通配符 *.example.com。
func (s *Store) Resolve(serverName string) (*tls.Certificate, bool) {
	cert, _, ok := s.ResolveWithID(serverName)
	return cert, ok
}

// ResolveWithID 与 Resolve 行为一致，但额外返回匹配到的证书 ID，供调用方做启用状态判定
// （禁用证书不应被面板 HTTPS / Web 服务引用）。
func (s *Store) ResolveWithID(serverName string) (*tls.Certificate, string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	name := nameKey(serverName)
	if claim, ok := s.byName[name]; ok {
		return &claim.cert.tlsCert, claim.cert.id, true
	}
	// 通配匹配：a.example.com → *.example.com
	if wildcard := wildcardOf(name); wildcard != "" {
		if claim, ok := s.byName[wildcard]; ok {
			return &claim.cert.tlsCert, claim.cert.id, true
		}
	}
	return nil, "", false
}

func (s *Store) ResolveID(id string) (*tls.Certificate, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sc, ok := s.byID[id]
	if !ok {
		return nil, false
	}
	return &sc.tlsCert, true
}

// Info 返回某证书的域名与到期时间。
func (s *Store) Info(id string) (domains []string, notAfter time.Time, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sc, ok := s.byID[id]
	if !ok {
		return nil, time.Time{}, false
	}
	return sc.domains, sc.notAfter, true
}

// leafFromPEM 从证书链 PEM 中解析首个（叶子）证书。
func leafFromPEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("无效的证书 PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

// wildcardOf 返回域名对应的一级通配形式。
func wildcardOf(name string) string {
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			return "*" + name[i:]
		}
	}
	return ""
}
