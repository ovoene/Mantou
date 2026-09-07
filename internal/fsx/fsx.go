// Package fsx 放数据目录相关的文件系统小工具。
//
// 独立成包只为一件事：目录权限这件事必须全仓一个口径。它原先散在五处
// （data 根、配置、日志、证书、上传），各写一个 os.MkdirAll(…, 0o755)，
// 于是"收紧一下"要改五处、漏一处不会有任何报错，只是那一处一直敞着。
package fsx

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// DirMode 是数据目录的权限位：0700，只有属主进得去。
//
// 为什么不是通常的 0755：data 目录里躺着 config.json（含各模块凭据的密文）、
// master.key（解开那些密文的唯一钥匙）、证书私钥、日志与上传的图片。文件本身
// 权限是对的（密钥类 0600），但目录 0755 意味着同机的任何一个用户都能列出这些
// 文件、读到文件名与大小——面板有哪些证书、哪几个域名、什么时候续过期，
// 这些都不需要读文件内容就能看出来。目录一关，这条路就没了。
//
// 面板自己以属主身份读写，不需要组或其他用户的任何权限；把证书交给同机的
// nginx 之类另一个服务用也不受影响：私钥本来就是 0600，非 root 的进程原先
// 也读不到，而 root 不受权限位约束。
const DirMode os.FileMode = 0o700

// EnsureDir 保证 path 及其各级父目录存在，且权限收紧到 DirMode。
//
// 返回的错误只来自创建失败——那意味着接下来的写入一定也不会成功，调用方该当真；
// 权限收紧失败不进返回值（见 Tighten）：那种情况下目录仍然可用，只是比预期宽松，
// 为它中断启动或让一次上传失败，代价比它本身大。
func EnsureDir(path string) error {
	if err := os.MkdirAll(path, DirMode); err != nil {
		return err
	}
	// 尽力而为。想拿到这一步的结果（比如为了记一条日志）就直接调 Tighten。
	_ = Tighten(path)
	return nil
}

// Tighten 去掉一个既有目录上「组」与「其他用户」的所有权限位，只保留属主那三位。
//
// 单独一步是因为 os.MkdirAll 只给它**新建**的那几级设权限：升级上来的安装里
// data 目录早就以 0755 存在了，光把 MkdirAll 的参数改成 0700 对它毫无作用——
// 那批用户会以为自己已经关上了门。
//
// 只收紧、不放宽：属主位、以及 setgid/sticky 这类高位一概照原样留着。前者是为了
// 不把一个刻意设成 0500 的只读目录改成可写；后者在某些共享部署里是有意为之的。
//
// 已经收紧的目录直接返回，不发那次 chmod：在只读挂载上，一次无谓的 chmod 会
// 换回一个错误，让调用方报一句其实什么都不用做的告警。
//
// Windows 上 os.Chmod 只能改「只读」属性，这里等于一次空操作——那边的访问控制
// 走 ACL，不由权限位表达。
func Tighten(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&0o077 == 0 {
		return nil
	}
	return os.Chmod(path, fi.Mode()&^0o077)
}

// TightenTree 把 root 及其下**每一层**目录都收紧到 DirMode。
//
// 为什么光有 Tighten(root) 不够：Tighten 只管一层，而 data 下面几个子目录都是
// 「写入那一刻才建」的——certs/ 在保存证书时（internal/modules/cert/store.go），
// uploads/ 在上传背景图时（internal/server/api_account.go）。于是从旧版本升上来的
// 安装里，这两个目录会一直停在 0755，直到用户下一次续证书或换背景图为止；
// 一个只用端口转发的实例可能永远等不到那一刻，而里面正躺着证书私钥。
// 启动时走一遍，把"什么时候收紧"从"下次写入"变成"下次启动"。
//
// 顺带收紧导入回滚留下的 `uploads.restore-old-<纳秒>` 之类残留：那里面是同一批
// 用户数据，只是名字不同（见 internal/app.ReclaimRestoreLeftovers）。
//
// 尽力而为，且不因为某一层失败就停下：错误全部收集起来一并返回，调用方拿它记一条
// 告警即可。目录比预期宽松是该被看见的问题，但不是"面板不能启动"那个量级的问题。
// root 本身不存在时返回 nil——那是首次启动的正常形态。
func TightenTree(root string) error {
	if _, err := os.Stat(root); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	var errs []error
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// 某一层读不动（权限、挂载点出错）：记下来跳过它，别让整棵树停在这里。
			errs = append(errs, err)
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		if tightenErr := Tighten(path); tightenErr != nil {
			errs = append(errs, tightenErr)
		}
		return nil
	})
	if walkErr != nil {
		errs = append(errs, walkErr)
	}
	return errors.Join(errs...)
}
