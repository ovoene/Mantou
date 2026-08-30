package metrics

import (
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// 容器整体内存占用。
//
// 为什么要单独读一遍：面板从前显示的是本进程的 RSS（proc.MemoryInfo），而 docker stats
// 那一列显示的是整个容器的占用——两个数天生不一样，后者通常更大，因为它把这些也算在内：
//
//   - 容器读写文件产生的页缓存（日志、配置、被读进来的那部分二进制）；
//   - 内核为这个容器分配的内存（套接字缓冲、slab 等）；
//   - 容器里除本程序之外的进程（入口脚本，或临时进到容器里的一个 shell）。
//
// 用户对着 docker stats 看的就是那一列，所以卡片上的数字应当与它对得上。
//
// 取值口径与 docker stats 逐字一致：
//
//	cgroup v2：memory.current 减去 memory.stat 里的 inactive_file
//	cgroup v1：memory.usage_in_bytes 减去 memory.stat 里的 total_inactive_file
//
// 减掉 inactive_file 是 docker 自己的做法，不是我们的发明：那部分是随时可回收的干净
// 页缓存，算进"占用"会让一个只是读过几百 MB 文件的容器看着像在漏内存。
//
// 读不到就返回 false，调用方退回本进程 RSS——Windows、macOS 以及直接在机器上跑二进制
// 的情形都没有这些文件，那时"本进程占用"本来就是对的口径。

const (
	// cgroupMount 容器里 cgroup 文件系统的挂载点。
	// v2 是统一层级，内存文件直接在里面；v1 每个控制器一个子目录，内存的是 memory/。
	cgroupMount   = "/sys/fs/cgroup"
	cgroupV1Mount = "/sys/fs/cgroup/memory"
)

// cgroupMemFiles 一组「用量 + 明细 + 要减掉的那一项」。
type cgroupMemFiles struct {
	usage       string
	stat        string
	inactiveKey string
}

// containerMemBytes 返回整个容器的内存占用（字节）。不在容器里、或读不到时返回 false。
func containerMemBytes() (uint64, bool) {
	// 必须先确认真的在容器里，这一步不能省。
	//
	// cgroup v1 的那两个路径在**宿主机上同样存在**，而在宿主机上它们指的是根内存
	// cgroup——也就是整台机器的用量。不加这道判断，直接在 Linux 机器上跑二进制时，
	// 「内存占用」会显示成整机几十 GB，而且看不出错在哪。
	// （cgroup v2 的根 cgroup 没有 memory.current，那一路本来就读不到，但判断照样加上，
	// 免得日后有人只看代码不看这段注释。）
	if !insideContainer() {
		return 0, false
	}
	return firstReadableCgroupMem(cgroupMemCandidates(selfCgroupPaths()))
}

// firstReadableCgroupMem 按给定顺序取第一组读得通的。顺序即优先级，见 cgroupMemCandidates。
func firstReadableCgroupMem(files []cgroupMemFiles) (uint64, bool) {
	for _, f := range files {
		if v, ok := readCgroupMem(f.usage, f.stat, f.inactiveKey); ok {
			return v, true
		}
	}
	return 0, false
}

// cgroupMemCandidates 按优先级列出要依次尝试的那几组文件。
//
// 为什么不能只读挂载点根下的 memory.current：那只在「容器有自己的 cgroup 命名空间」时
// 才指向本容器。docker 的 --cgroupns 在不少环境里是 host（cgroup v1 的宿主机上是默认值，
// 内核或 docker 版本偏旧时也会退到它），此时容器里看到的 /sys/fs/cgroup 是**宿主机的
// cgroup 根**，本容器那一份在它下面的某个子目录里——而那个子目录的路径，
// 恰好写在 /proc/self/cgroup 里。
//
// 于是两种情形对应两种候选：
//
//	命名空间是 private：/proc/self/cgroup 里是 "/"，挂载点根就是本容器，读根即可；
//	命名空间是 host：   /proc/self/cgroup 里是 "/docker/<id>" 那样的路径，要拼上去才对。
//
// 顺序上「拼路径的」必须排在「读根的」前面。v1 的根在 host 命名空间下是读得通的，
// 只是读出来的是整台机器——先试根就会拿到一个大得离谱的数，还不会报错。
func cgroupMemCandidates(v2Path, v1Path string) []cgroupMemFiles {
	var out []cgroupMemFiles
	// 这些是 Linux 的绝对路径，用 path 而不是 filepath 拼：filepath 在 Windows 上会拼出
	// 反斜杠，而这几个路径的形态不该跟着编译目标变（测试在 Windows 上跑也得是同一个串）。
	add := func(dir, usage, inactiveKey string) {
		out = append(out, cgroupMemFiles{
			usage:       path.Join(dir, usage),
			stat:        path.Join(dir, "memory.stat"),
			inactiveKey: inactiveKey,
		})
	}
	if nested(v2Path) {
		add(path.Join(cgroupMount, v2Path), "memory.current", "inactive_file")
	}
	add(cgroupMount, "memory.current", "inactive_file")
	if nested(v1Path) {
		add(path.Join(cgroupV1Mount, v1Path), "memory.usage_in_bytes", "total_inactive_file")
	}
	add(cgroupV1Mount, "memory.usage_in_bytes", "total_inactive_file")
	return out
}

// nested 判断 /proc/self/cgroup 给出的路径是否指向挂载点根之下的某一层。
// 空的和 "/" 都等于根，拼上去只是同一个目录，不必多试一遍。
func nested(path string) bool {
	return path != "" && path != "/"
}

// selfCgroupPaths 从 /proc/self/cgroup 里取出本进程所在的 cgroup 路径。
//
// 每行格式是「层级号:控制器列表:路径」，v2 那行的层级号是 0 且控制器列表为空：
//
//	0::/docker/2f1a…            ← v2
//	11:memory:/docker/2f1a…     ← v1 的内存控制器
//	9:cpu,cpuacct:/docker/2f1a… ← 控制器列表可以是逗号分隔的多个
//
// 两个都取：同一台机器上只会有一种生效，但判断哪一种生效不如两条路都留着——
// 反正后面是按文件存不存在来挑的。
func selfCgroupPaths() (v2, v1 string) {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", ""
	}
	return parseSelfCgroup(string(b))
}

// parseSelfCgroup 是上面那个函数的解析部分，单独拆出来是为了能不依赖真的 /proc 去测。
func parseSelfCgroup(content string) (v2, v1 string) {
	for _, line := range strings.Split(content, "\n") {
		id, rest, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		controllers, cgPath, ok := strings.Cut(rest, ":")
		if !ok || cgPath == "" {
			continue
		}
		switch {
		case id == "0" && controllers == "":
			v2 = cgPath
		case slices.Contains(strings.Split(controllers, ","), "memory"):
			v1 = cgPath
		}
	}
	return v2, v1
}

// readCgroupMem 读一组「用量 − 非活跃文件页」。
func readCgroupMem(usagePath, statPath, inactiveKey string) (uint64, bool) {
	usage, ok := readUintFile(usagePath)
	if !ok {
		return 0, false
	}
	inactive := statField(statPath, inactiveKey)
	// 两个文件不是同一瞬间读的，理论上可能读出 inactive 比 usage 还大。
	// 无符号相减会绕成一个天文数字，宁可少减。
	if inactive > usage {
		return usage, true
	}
	return usage - inactive, true
}

// readUintFile 读一个只含十进制整数的文件。
// cgroup v2 在没有上限时会把 memory.max 写成 "max"，用量文件不会，但仍按解析失败处理。
func readUintFile(path string) (uint64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// statField 从 memory.stat 里取一项（「键 空格 值」每行一项）。取不到当 0——
// 少减一项只是数字偏大一点，而整块读不到时上一层已经退回本进程 RSS 了。
func statField(path, key string) uint64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		name, value, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok || name != key {
			continue
		}
		v, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		if err != nil {
			return 0
		}
		return v
	}
	return 0
}

// containerHints 判定"在容器里"的几处痕迹。
//
// 前两个文件是容器运行时自己放进去的标记（docker 与 podman 各一个），最省事也最准。
// 后面那一串是给带 cgroup 命名空间之外的情形留的退路：v1 下 /proc/self/cgroup 的每一行
// 都带着容器 ID 所在的那段路径。两类都查不到就当不在容器里——那时退回本进程 RSS 是安全的
// 默认，宁可少显示一点也不能把整机用量当成自己的。
var containerHints = []string{"/docker", "docker-", "containerd", "kubepods", "/lxc", "libpod", "/podman"}

// insideContainer 只判断一次。
//
// 「跑在不跑在容器里」在进程活着的这段时间内不会变，而 containerMemBytes 是每个采样
// 周期都会调的。不缓存的话，Windows 与直接跑二进制的 Linux 上就变成每隔几秒白做
// 两次 stat 加一次读文件——一直到进程退出。省下的开销微不足道，但这类"每个周期都在
// 问一个答案不会变的问题"的写法，本身就是后面性能问题的来源。
var insideContainer = sync.OnceValue(inContainer)

func inContainer() bool {
	for _, marker := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(marker); err == nil {
			return true
		}
	}
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return false
	}
	s := string(b)
	for _, hint := range containerHints {
		if strings.Contains(s, hint) {
			return true
		}
	}
	return false
}
