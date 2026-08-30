package restart

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
)

// CheckExecutable 在动手换进程之前，先确认 path 现在还拉得起来。
//
// 换进程有一种特别难受的失败形态：面板监听、各模块监听、运行态落盘都已经收尾，
// 到最后一步执行新映像时才发现文件不在了。**此时没有任何回退路径**——配置管理器
// 已经 Close、模块已经 CloseAll，进程只能退出。用户只是想重启一次，
// 结果失去了整个程序（没有外部守护时它再也起不来）。
//
// 所以这一眼要在拆之前看。会碰到的情形就两类：
//   - 二进制被删掉或改名（Linux 上此时 os.Executable() 返回的是 "…/mantou (deleted)"，
//     这个路径 stat 不到）；
//   - 可执行位被拿掉（同步 / 解包 / 挂载参数变动都可能造成）。
//
// 这不是原子保证：检查通过之后文件仍可能在几毫秒内消失，那种情形只能由上面那条
// os.Exit 兜底。它要挡住的是"已经处于这个状态好一会儿了"的那一类——而实际会碰到的
// 正是这一类。
//
// 放在 restart 包里是因为需要它的两方（cmd/mantou 注入回调、面板的立即重启接口）
// 都已经依赖这个包；各写一份的话，迟早只有一份被改对。
func CheckExecutable(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("程序路径为空")
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("找不到程序文件（可能已被删除或改名）：%w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("程序路径指向的是目录：%s", path)
	}
	// Windows 上文件模式位没有可执行含义（Go 一律报成 0666/0777），只查存在与类型。
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("程序文件没有可执行权限：%s", path)
	}
	return nil
}
