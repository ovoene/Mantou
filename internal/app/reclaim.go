package app

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"mantou/internal/logx"
)

// 导入事务把被替换掉的原目录改名成 `<目录名>.restore-old-<纳秒>`（见 server.restoreBackupResources
// 与 server.restoreDirectory）。这里只认这一种名字：
//   - `.<目录名>-restore-<随机>` 是还没启用的暂存，可能只写了一半，捡回来等于拿半份数据顶替原件；
//   - `.<目录名>-restore-discard-<纳秒>` 是回滚时挪开的、**已经被否决**的导入数据，
//     捡回来正好把用户拒绝的那一份装上。
//
// 三个前缀的分工同时写在 server.storageLeftoverKind 的注释里，改名字要一起改。
const restoreOldInfix = ".restore-old-"

// reclaimDirs 是导入时**整体替换**的两个目录，也就是存在"改名换上/换回"窗口的两个。
// 名字与 internal/server（uploads）、internal/app.Build（certs）里的字面量一致。
var reclaimDirs = []string{"certs", "uploads"}

// ReclaimRestoreLeftovers 在启动时把导入回滚过程中掉在窗口里的目录捡回来。
//
// 要救的是这个场景：导入配置失败触发回滚，回滚把 `uploads/`（或 `certs/`）挪开、正准备把
// `uploads.restore-old-<纳秒>` 改回原位时，进程被杀或断电。落盘上就只剩那个带时间戳的目录，
// 而**没有任何代码会再去动它**——面板重启后背景图全丢（证书目录则是私钥全丢），
// 用户在「存储占用」里看到的还是一个标着"可清理"的目录，一点就真删了。
//
// 判定条件刻意收得很紧，只处理"不含歧义、且当前无法自愈"的那一种：
//
//  1. 规范目录**不存在**。存在就什么都不做——那要么是导入成功了（旁边的 restore-old 是等着
//     被 commit 删掉的原件），要么是回滚已经走完。两种情况下现役数据都在位，不该去碰。
//  2. 旁边有形如 `<目录名>.restore-old-<纳秒>` 的**目录**。多个就取纳秒最大的那个：
//     时间戳是回滚开始时生成的，最新的那次才是造成当前缺口的那次。
//
// 每一步失败都只告警不中止：捡不回来是"少了目录"，而这本来就是崩溃已经造成的状态，
// 让整个面板起不来只会更糟。相应地，捡回来是一件**要留痕**的事——用户的背景图或证书
// 在他不知道的时候消失过一次，日志里得有一条能对上。
func ReclaimRestoreLeftovers(dataDir string, log *logx.Logger) {
	if dataDir == "" {
		return
	}
	for _, name := range reclaimDirs {
		reclaimRestoreDir(dataDir, name, log)
	}
}

// reclaimRestoreDir 处理单个目录。分成一个函数是为了让"这一个失败不影响另一个"成为默认行为。
func reclaimRestoreDir(dataDir, name string, log *logx.Logger) {
	root := filepath.Join(dataDir, name)
	if _, err := os.Stat(root); err == nil {
		return // 现役目录在位，没有缺口
	} else if !errors.Is(err, os.ErrNotExist) {
		// 既不是"不存在"也不是"存在"（权限、路径里有非目录、挂载点出错）：
		// 这时看不清缺口在哪，不能凭猜去改名。
		log.Warn("检查数据目录失败，跳过导入残留回收", "dir", root, "err", err.Error())
		return
	}
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		log.Warn("读取数据目录失败，跳过导入残留回收", "dir", dataDir, "err", err.Error())
		return
	}
	prefix := name + restoreOldInfix
	newest, newestStamp := "", int64(-1)
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		// 时间戳解析不出来的一律跳过：那不是本程序生成的名字，无从判断新旧，
		// 更不该把它当成原件装上去。它仍会出现在「存储占用」里，由用户处置。
		stamp, convErr := strconv.ParseInt(strings.TrimPrefix(entry.Name(), prefix), 10, 64)
		if convErr != nil {
			continue
		}
		if stamp > newestStamp {
			newest, newestStamp = entry.Name(), stamp
		}
	}
	if newest == "" {
		return // 目录不存在但也没有可回收的残留：正常的首次启动就是这样
	}
	if err := os.Rename(filepath.Join(dataDir, newest), root); err != nil {
		log.Error("回收导入回滚残留失败，目录仍然缺失", "dir", root, "from", newest, "err", err.Error())
		return
	}
	// 用 Warn 而不是 Info：这条日志对应的是"上一次导入回滚没走完"，属于该被看见的异常，
	// 而不是每次启动都会有的例行动作。
	log.Warn("上次导入回滚未完成，已把原目录恢复回来", "dir", root, "from", newest)
}
