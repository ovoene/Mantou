package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"mantou/internal/app"
	"mantou/internal/config"
	"mantou/internal/logx"
	"mantou/internal/metrics"
	"mantou/internal/restart"
	"mantou/internal/server"
	"mantou/internal/version"
	"mantou/web"
)

// 版本号 / 官网地址 / 编译时间由 version 包提供：version.go 维护默认值，构建脚本
// 生成的 gen.go 经 init() 在编译期覆盖 Version / BuildTime。不再通过 -ldflags 注入，
// 以避免含空格的版本号被 shell/链接器拆断。

func main() {
	var (
		dataDir     string
		showVersion bool
	)
	flag.StringVar(&dataDir, "data", envOr("MANTOU_DATA_DIR", "data"), "数据目录（配置、日志、上传等）")
	flag.BoolVar(&showVersion, "version", false, "打印版本并退出")
	flag.Parse()

	if showVersion {
		fmt.Println("Mantou", version.Load().Version)
		return
	}

	if err := run(dataDir); err != nil {
		fmt.Fprintln(os.Stderr, "启动失败:", err)
		os.Exit(1)
	}
}

func run(dataDir string) error {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return fmt.Errorf("创建数据目录失败: %w", err)
	}

	// 1. 配置。
	cfgMgr := config.NewManager(filepath.Join(dataDir, "config.json"))
	if err := cfgMgr.Load(); err != nil {
		return err
	}
	cfg := cfgMgr.Snapshot()

	// 2. 日志（控制台 + 轮转文件 + 内存环形缓冲）。
	// 「日志最大条数」（cfg.Settings.Log.MaxEntries）是全程序日志量的唯一总开关，
	// 这里把同一个数字同时交给磁盘文件与内存环，两者各自独立地不超过该条数。
	// 磁盘另有固定 5MB 体积上限（logx.LogMaxSizeMB）与条数并行，先到先轮转；
	// 且不保留历史备份（logx.LogMaxBackups = 0），把日志目录占用严格限制在 5MB 以内。
	// 访问事件环由 webservice 模块在 Reload 时读取同一字段（见 Module.SetAccessCap）。
	logFile, err := logx.NewRotatingFile(filepath.Join(dataDir, "logs", "mantou.log"), cfg.Settings.Log.MaxEntries)
	if err != nil {
		return fmt.Errorf("初始化日志文件失败: %w", err)
	}
	defer logFile.Close()

	log := logx.New(logx.Options{
		Levels:     cfg.Settings.Log.Levels,
		Console:    cfg.Settings.Log.Console,
		MaxEntries: cfg.Settings.Log.MaxEntries,
		FileWriter: logFile,
	})
	logx.SetGlobal(log)
	log.Info("Mantou 启动中", "version", version.Load().Version, "dataDir", dataDir)

	// 一次性存储升级：Web 服务子项的 Basic 认证口令从明文改为 bcrypt 哈希。
	// 必须早于第 4 步的模块启动——Web 服务起来就要用这个字段校验访问了。
	app.MigrateWebBasicAuth(cfgMgr, log)

	// 手工编辑 config.json / 导入备份都不经过接口层校验，故在模块启动前把发送参数
	// 非法的网络唤醒设备禁掉：否则它们会每拍发一次注定失败（甚至打到公网）的包。
	app.SanitizeWOLDevices(cfgMgr, log)

	// 运行态（各规则的最近状态/时间戳）是合并落盘的：退出前必须把窗口内未写出的部分刷盘，
	// 否则最后几秒的状态变化会丢失。注册在日志之后，使 LIFO 顺序下本次刷盘先于日志文件关闭，
	// 失败时还能留下记录。
	defer func() {
		if err := cfgMgr.Close(); err != nil {
			log.Error("运行态落盘失败", "error", err.Error())
		}
	}()

	// 3. 指标采集。
	collector := metrics.NewCollector(180, 2*time.Second, version.Load().Version)
	collector.Start()
	defer collector.Stop()

	// 4. 功能模块（DDNS/Web 服务/端口转发/WOL/计划任务/证书）。
	application := app.Build(log, cfgMgr, dataDir)
	application.ReloadAll()
	defer application.CloseAll()

	// 5. 前端静态资源。
	webFS, err := web.FS()
	if err != nil {
		return fmt.Errorf("加载前端资源失败: %w", err)
	}

	// 6. HTTP 服务器。
	baseDeps := application.ServerDeps(server.Deps{
		Config:  cfgMgr,
		Log:     log,
		Metrics: collector,
		WebFS:   webFS,
		DataDir: dataDir,
		LogFile: logFile,
	})

	return servePanels(baseDeps, log)
}

func servePanels(baseDeps server.Deps, log *logx.Logger) error {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	// 自更新：请求用磁盘上已替换的新二进制替换当前进程映像（路径由 handleSelfUpdate 传入）。
	execCh := make(chan string, 1)
	baseDeps.RestartExec = func(path string) error {
		// 入队之前先确认这个二进制还拉得起来。
		//
		// 这是唯一还能说"不"的位置：一旦入队，下面的消费者会依次关掉面板监听、
		// 落盘运行态、关闭各模块，然后才执行新映像；到那一步失败就只剩 os.Exit 一条路，
		// 而调用方（立即重启 / 定时重启）想要的只是重启一次，不该因此失去整个程序。
		if err := restart.CheckExecutable(path); err != nil {
			return err
		}
		select {
		case execCh <- path:
			return nil
		default:
			return fmt.Errorf("已有待执行的进程替换请求")
		}
	}

	// 定时重启：到点了走与自更新完全相同的那条通道，只是二进制还是自己。
	// 复用 execCh 顺带带来一个好处——自更新与定时重启天然互斥，不会同时动进程。
	if exePath, err := os.Executable(); err != nil {
		// 拿不到自身路径就没法拉起新进程。这里只告警不阻止启动：
		// 定时重启不可用远不至于让整个程序起不来。
		log.Warn("无法定位程序自身路径，定时重启与手动重启将不可用", "error", err.Error())
	} else {
		scheduler := restart.New(restart.Options{
			Store: baseDeps.Config,
			Log:   log,
			Fire:  func() error { return baseDeps.RestartExec(exePath) },
		})
		scheduler.Start()
		defer scheduler.Stop()
	}

	for {
		restartCh := make(chan struct{}, 1)
		var restartOnce sync.Once
		deps := baseDeps
		deps.RestartPanel = func() {
			restartOnce.Do(func() { restartCh <- struct{}{} })
		}
		srv := server.New(deps)
		errCh := make(chan error, 1)
		go func() { errCh <- srv.Start() }()

		select {
		case err := <-errCh:
			return err
		case sig := <-sigCh:
			log.Info("收到退出信号，正在关闭", "signal", sig.String())
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			err := srv.Shutdown(ctx)
			cancel()
			return err
		case <-restartCh:
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			err := srv.Shutdown(ctx)
			cancel()
			if err != nil {
				return fmt.Errorf("优雅关闭面板失败: %w", err)
			}
			if err := <-errCh; err != nil {
				return err
			}
			log.Info("面板已在进程内重启")
		case path := <-execCh:
			// 换进程：先优雅关闭监听释放端口，再用 path 指向的二进制替换当前进程映像。
			// 三个来源共用这一条：自更新（path 是新二进制）、立即重启与定时重启（path 是自己）。
			// execSelf 成功则不返回（进程被接管，PID 不变、argv/环境保留，
			// 无论是否有外部守护都能自动重启）。
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			shErr := srv.Shutdown(ctx)
			cancel()
			if shErr != nil {
				log.Error("优雅关闭面板失败，仍尝试替换进程", "error", shErr.Error())
			}
			// 等待监听真正关闭（Start 的监听 goroutine 退出），最多再等 3s 兜底。
			select {
			case <-errCh:
			case <-time.After(3 * time.Second):
				log.Warn("等待监听关闭超时，仍尝试替换进程")
			}
			log.Info("正在用新二进制替换进程映像", "path", path)
			// syscall.Exec 不会执行 defer，必须显式收尾。
			// 一是把合并窗口内未落盘的运行态写出，否则升级后各规则的最近状态倒退；
			// 二是关闭 Web 服务 / 端口转发等模块监听，否则这些 socket 默认非 CLOEXEC
			// 会跨 exec 继承给新进程，升级后因端口仍被占用导致服务无法启动。
			if baseDeps.Config != nil {
				if e := baseDeps.Config.Close(); e != nil {
					log.Warn("运行态落盘失败", "error", e.Error())
				}
			}
			if baseDeps.Modules != nil {
				baseDeps.Modules.CloseAll()
			}
			if e := execSelf(path); e != nil {
				// 走到这里已经没有回退：监听关了、模块关了、配置管理器也 Close 了，
				// 继续留在这个循环里得到的是一个什么都不做的空壳进程。
				// 能提前拒绝的情形由 RestartExec 里的 CheckExecutable 挡在拆解之前，
				// 这里剩下的是"检查通过之后文件才出问题"那一类。
				log.Error("替换进程映像失败，进程将退出", "error", e.Error())
				os.Exit(1)
			}
		}
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
