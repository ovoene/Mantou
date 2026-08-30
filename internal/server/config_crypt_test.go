package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"mantou/internal/config"
	"mantou/internal/logx"
	"mantou/internal/modules/cert"
)

func TestEncryptedBackupRoundTripIncludesUploads(t *testing.T) {
	cfg := &config.Config{Auth: config.Auth{Username: "admin", PasswordHash: "hash"}}
	uploads := []FileBackup{{Path: "images/background.png", Data: []byte("image-data")}}
	data, err := EncryptBackup("admin", "password", cfg, []CertBackup{}, uploads)
	if err != nil {
		t.Fatal(err)
	}

	restored, certs, restoredUploads, err := DecryptBackup(data, "admin", "password")
	if err != nil {
		t.Fatal(err)
	}
	if restored.Auth.Username != cfg.Auth.Username {
		t.Fatalf("unexpected username: %s", restored.Auth.Username)
	}
	if certs == nil || len(certs) != 0 {
		t.Fatalf("expected complete empty certificate list, got %#v", certs)
	}
	if len(restoredUploads) != 1 || restoredUploads[0].Path != uploads[0].Path || string(restoredUploads[0].Data) != string(uploads[0].Data) {
		t.Fatalf("unexpected uploads: %#v", restoredUploads)
	}
}

func TestDecryptBackupRejectsUnsupportedParameters(t *testing.T) {
	cfg := &config.Config{Auth: config.Auth{Username: "admin", PasswordHash: "hash"}}
	data, err := EncryptBackup("admin", "password", cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var env cryptEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	env.Iter++
	data, err = json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := DecryptBackup(data, "admin", "password"); err == nil {
		t.Fatal("expected unsupported encryption parameters to be rejected")
	}
}

func TestValidateBackupResourcesRejectsUnsafeUploadPath(t *testing.T) {
	cfg := &config.Config{Auth: config.Auth{Username: "admin", PasswordHash: "hash"}}
	if err := validateBackupResources(cfg, nil, []FileBackup{{Path: "../config.json", Data: []byte("x")}}); err == nil {
		t.Fatal("expected traversal path to be rejected")
	}
	if safeBackupPath("C:/config.json") {
		t.Fatal("expected volume path to be rejected")
	}
	if safeBackupPath(`nested\config.json`) {
		t.Fatal("expected backslash path to be rejected")
	}
}

func TestValidateBackupResourcesRejectsMissingCertificate(t *testing.T) {
	cfg := &config.Config{Certs: []config.Certificate{{ID: "missing"}}}
	if err := validateBackupResources(cfg, []CertBackup{}, []FileBackup{}); err == nil {
		t.Fatal("expected missing certificate resource to be rejected")
	}
}

func TestRestoreBackupResourcesConvertsPathCertificate(t *testing.T) {
	dataDir := t.TempDir()
	manager := config.NewManager(filepath.Join(dataDir, "config.json"))
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM := newBackupTestCertificate(t)
	module := cert.New(logx.New(logx.Options{}), filepath.Join(dataDir, "certs"), manager)
	defer module.Close()
	s := &Server{deps: Deps{DataDir: dataDir, Cert: module}}
	cfg := &config.Config{Certs: []config.Certificate{{ID: "external", Method: "path", CertPath: "old.crt", KeyPath: "old.key"}}}

	tx, err := s.restoreBackupResources(cfg, []CertBackup{{ID: "external", Method: "path", CertPEM: string(certPEM), KeyPEM: string(keyPEM)}}, []FileBackup{})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.commit(); err != nil {
		t.Fatal(err)
	}
	if cfg.Certs[0].Method != "file" || cfg.Certs[0].CertPath != "" || cfg.Certs[0].KeyPath != "" {
		t.Fatalf("path certificate was not converted: %#v", cfg.Certs[0])
	}
	if _, _, err := module.Export(cfg.Certs[0], true); err != nil {
		t.Fatal(err)
	}
}

func newBackupTestCertificate(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "backup.example.com"},
		DNSNames:     []string{"backup.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func TestCollectUploadBackupsIncludesNestedFiles(t *testing.T) {
	dataDir := t.TempDir()
	path := filepath.Join(dataDir, "uploads", "nested", "image.webp")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}

	files, err := collectUploadBackups(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Path != "nested/image.webp" || string(files[0].Data) != "content" {
		t.Fatalf("unexpected files: %#v", files)
	}
}
