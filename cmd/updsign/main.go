// Command updsign 生成 Ed25519 密钥对，并对 mantou 自更新包签名。
//
// 与 internal/server/api_update.go 的 verifyUpdateSignature 严格对齐：
//   - 签名对象：二进制的 SHA-256 摘要；
//   - 签名：Ed25519 原始 64 字节（非 base64），写入与二进制同名的 .sig 文件；
//   - 公钥：base64 编码的 32 字节，配置到 mantou「设置 → 在线更新 → 自更新包签名公钥」。
//
// 用法：
//
//	updsign gen                         生成密钥对（私钥保存到 update-signing.key，公钥打印到 stdout）
//	updsign sign -key <key> <bin> <sig>  对 <bin> 的 SHA-256 摘要签名并写入 <sig>
//
// 私钥文件 update-signing.key 需妥善保密、切勿提交到版本库（.gitignore 已忽略）。
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

const defaultKeyFile = "update-signing.key"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "gen":
		if err := gen(defaultKeyFile); err != nil {
			fmt.Fprintln(os.Stderr, "生成密钥失败:", err)
			os.Exit(1)
		}
	case "sign":
		keyFile := defaultKeyFile
		rest := os.Args[2:]
		if len(rest) >= 2 && rest[0] == "-key" {
			keyFile = rest[1]
			rest = rest[2:]
		}
		if len(rest) != 2 {
			usage()
			os.Exit(2)
		}
		if err := sign(keyFile, rest[0], rest[1]); err != nil {
			fmt.Fprintln(os.Stderr, "签名失败:", err)
			os.Exit(1)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `用法:
  updsign gen                          生成 Ed25519 密钥对（私钥保存到 update-signing.key）
  updsign sign -key <key> <bin> <sig>   对 <bin> 的 SHA-256 摘要签名并写入 <sig>`)
}

// gen 生成密钥对；私钥文件已存在则不覆盖（只打印其公钥），避免公钥反复变化导致配置失效。
func gen(keyFile string) error {
	if _, err := os.Stat(keyFile); err == nil {
		if err := printPub(keyFile); err != nil {
			return err
		}
		fmt.Printf("（私钥 %s 已存在，如需重新生成请先删除该文件）\n", keyFile)
		return nil
	}
	seed := make([]byte, ed25519.SeedSize) // 32 字节
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	// 私钥仅保存 32 字节 seed（hex），可经 NewKeyFromSeed 还原完整私钥。
	if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(seed)), 0o600); err != nil {
		return err
	}
	fmt.Printf("已生成自更新签名密钥对，私钥保存到 %s\n", keyFile)
	fmt.Printf("公钥（base64，配置到 mantou「设置 → 在线更新 → 自更新包签名公钥」）:\n%s\n",
		base64.StdEncoding.EncodeToString(pub))
	return nil
}

func printPub(keyFile string) error {
	priv, err := loadKey(keyFile)
	if err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	fmt.Printf("公钥（base64）:\n%s\n", base64.StdEncoding.EncodeToString(pub))
	return nil
}

// loadKey 从 32 字节 seed 恢复完整私钥。seed 支持 hex（64 字符）或 base64（标准/URL-safe，
// 含或不含 padding）两种编码，并容忍首尾空白，避免用户误用 base64 时签名失败。
func loadKey(keyFile string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	s := strings.TrimSpace(string(data))
	// 1) hex：32 字节 seed 的 64 字符 hex
	if seed, err := hex.DecodeString(s); err == nil && len(seed) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(seed), nil
	}
	// 2) base64（标准/URL-safe，含或不含 padding）：32 字节 seed
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if seed, err := enc.DecodeString(s); err == nil && len(seed) == ed25519.SeedSize {
			return ed25519.NewKeyFromSeed(seed), nil
		}
	}
	return nil, fmt.Errorf("私钥文件 %s 格式无效（应为 32 字节的 hex 或 base64 字符串）", keyFile)
}

func sign(keyFile, bin, sig string) error {
	priv, err := loadKey(keyFile)
	if err != nil {
		return err
	}
	f, err := os.Open(bin)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	signature := ed25519.Sign(priv, h.Sum(nil))
	if err := os.WriteFile(sig, signature, 0o644); err != nil {
		return err
	}
	fmt.Printf("已签名: %s → %s\n", bin, sig)
	return nil
}
