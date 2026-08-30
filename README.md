# mantou

[English](./README.en.md) · 简体中文

**mantou** 是一个自己架、自己管的网络工具面板。它不挑硬件、也不依赖某个特定的路由系统，装在你自己的机器上就能用。打开浏览器就是一个中英双语、外观可以随意调的管理界面，把几件常做的网络事情放在一处：让域名一直指向你家变动的宽带地址、把外网访问转到内网的服务上、端口转发、远程开机、定时执行、申请和续期 HTTPS 证书，以及接收外部系统推来的消息并转发到你自己的通道上。

> 交付形式是**一个可执行文件**：前端界面已经打包在里面，不需要另外装数据库或中间件，也支持用 Docker 跑。

## 功能

- **总览** —— 一眼看到这台机器的处理器 / 内存 / 磁盘占用、上下行网速与走势，以及本机信息。
- **动态域名** —— 家里宽带的公网地址会变。它定时看一眼当前地址，一变就自动去域名服务商那里把解析记录改过来，域名就一直指得对。
- **Web 服务** —— 把一个域名的访问转给内网里的某个服务（反向代理），或者直接托管一个静态网页；也可以在这一层收 HTTPS。
- **端口转发** —— 把本机某个端口收到的流量原样转到另一台机器的端口上，支持 TCP 与 UDP，也支持 IPv6 与 IPv4 互转。
- **网络唤醒** —— 给局域网里关着的机器发一个开机信号，可以手动点，也可以定时。
- **计划任务** —— 到点自动做一件事：刷新动态域名、唤醒设备、续期证书、发一个 HTTP 请求。
- **证书** —— 自动申请与续期 HTTPS 证书（走**域名验证**方式，支持泛域名证书）。
- **消息路由** —— 给外部系统一个接收地址，收到消息后按你配的规则取字段、套模板、决定发不发，再转到你自己的通道上。
- **凭证** —— 域名服务商的账号密钥集中存一处，动态域名与证书两个模块共用，不用在每条规则里重复填。
- **设置** —— 账户、外观、日志、备份与恢复、在线更新等。

界面是**自己设计的**：颜色、背景图、模糊程度、圆角、字号都能在设置里调，改一处立刻能看到效果，明暗主题都有，调好的样子还能导出成文件换机再导进来。必须登录才能进。

## 技术栈

- 后端：Go（Gin、gopsutil、`golang.org/x/crypto/acme`、robfig/cron）
- 前端：Vue 3 + Vite + TypeScript + Element Plus + ECharts + vue-i18n
- 部署：一个可执行文件，界面已经打包在里面；也提供 Docker 镜像（支持 amd64 与 arm64）

## 快速开始

```bash
# Docker（compose）
docker compose up -d

# Docker（手动）
docker run -d --name mantou \
  -p 25666:25666 \
  -v $(pwd)/data:/data \
  --restart unless-stopped \
  mantou:latest

# 源码构建
make build && ./bin/mantou --data ./data
```

浏览器打开 `http://<宿主机IP>:25666`，首次访问进入初始化向导，设置管理员账户。面板端口保存在 `config.json`（在「设置 → 常规」中修改，重启后生效）。

## 下载后怎么运行（各平台 / 各架构）

从 Releases 页下载对应平台的压缩包（哪个文件对应哪个平台，见下面第 7 节的表格）。不确定该下哪个，先看机器架构：

```bash
uname -m     # Linux / macOS：x86_64 → 选 amd64，aarch64 或 arm64 → 选 arm64
```

Windows 在「设置 → 系统 → 系统信息」里看"系统类型"，写着 x64 就选 amd64。

两个可用参数：`--data` 指定数据目录（不传则用当前目录下的 `data/`，也可用环境变量 `MANTOU_DATA_DIR`）、`--version` 打印版本后退出。

### Linux（amd64 / arm64）

```bash
tar -xzf mantou-linux-amd64.tar.gz     # ARM 机器换成 mantou-linux-arm64.tar.gz
chmod +x mantou
./mantou --data ./data
```

包里除了 `mantou`，配置了签名密钥的话还有一个 `mantou.sig`，那是给在线更新验签用的，不影响直接运行。

要开机自启、后台常驻，用 systemd：

```bash
sudo mv mantou /usr/local/bin/
sudo tee /etc/systemd/system/mantou.service >/dev/null <<'EOF'
[Unit]
Description=mantou
After=network-online.target

[Service]
ExecStart=/usr/local/bin/mantou --data /var/lib/mantou
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl enable --now mantou
```

### macOS（arm64 = Apple Silicon / amd64 = Intel）

```bash
tar -xzf mantou-darwin-arm64.tar.gz    # Intel 机器换成 mantou-darwin-amd64.tar.gz
chmod +x mantou
xattr -d com.apple.quarantine mantou   # 去掉「从网上下载」标记
./mantou --data ./data
```

第三步不能省：浏览器下载的可执行文件带隔离属性，直接运行会被拦住并提示无法验证开发者。

### Windows amd64（x64）

解压 `mantou-windows-amd64.zip` 得到 `mantou.exe`，双击即可，它会在同目录建 `data\`。要指定数据目录就在命令行里跑：

```
mantou.exe --data D:\mantou\data
```

首次运行时 Windows 防火墙会弹窗询问，要点允许，否则局域网里的其它设备访问不到。

### Docker（多架构，两种架构用同一条命令）

镜像发布成多架构清单，`docker pull` 会按当前机器架构自动取对应的那一份——**amd64 和 arm64 用完全一样的命令，不需要加任何参数**：

```bash
docker pull ghcr.io/ovoene/mantou:latest

docker run -d --name mantou \
  -p 25666:25666 \
  -v $(pwd)/data:/data \
  --restart unless-stopped \
  ghcr.io/ovoene/mantou:latest
```

只有一种情况需要显式指定：在 amd64 机器上想拉 arm64 那一份（或反过来），用来交叉验证。

```bash
docker pull --platform linux/arm64 ghcr.io/ovoene/mantou:latest
```

想确认拉到的到底是哪一份，以及清单里有哪些架构：

```bash
docker image inspect ghcr.io/ovoene/mantou:latest --format '{{.Os}}/{{.Architecture}}'
docker manifest inspect ghcr.io/ovoene/mantou:latest
```

> 镜像在 ghcr.io 上默认是私有的，拉取前需要先 `docker login ghcr.io`，或者由仓库主人在 Settings → Packages 里把包可见性设为 Public。
>
> 容器默认网络下网络唤醒不管用，原因见文末「注意事项与已知限制」。

## 构建、打包与发布

本节介绍从源码构建、本地打包、到推送 GitHub 后自动出多平台二进制与 Docker 镜像的完整流程。

### 1. 环境准备（需要安装的资源）

| 依赖 | 版本要求 | 用途 |
|------|---------|------|
| Go | ≥ 1.25（go.mod 下限，推荐 1.26） | 编译后端二进制 |
| Node.js + npm | ≥ 20（推荐 22 LTS） | 构建前端 `web/dist` |
| make + tar | Linux / macOS | Makefile 打包脚本 |
| Docker（可选） | 20.10+ | 构建镜像 / 容器运行 |
| git | 任意 | 发布到 GitHub |

各平台安装：

- **Linux**（Debian/Ubuntu）：`sudo apt install golang-go nodejs npm make`；Docker 用官方脚本或发行版仓库安装。
- **macOS**：`brew install go node`（`make` 随 Xcode 命令行工具自带）；Docker 安装 Docker Desktop。
- **Windows 10**：安装 [Go](https://go.dev/dl/)、[Node.js](https://nodejs.org/)（含 npm）、[Git for Windows](https://git-scm.com/)（自带 bash 与 tar）。Win10 已内置 `tar`（bsdtar）。打包用 `package.bat`（等价于 `make package`）；Docker 可选装 Docker Desktop。

> 项目是「Go 后端 + Vue 前端」单仓库，最终产出是内嵌前端的**单一静态二进制**；`node_modules` 仅构建期需要，不随产物下发。

### 2. 生成签名密钥对并配置公钥（自更新签名）

mantou 的自更新包使用 **Ed25519** 签名，防止更新包被投毒。首次打包会自动生成密钥对，也可手动生成：

```bash
# 手动生成（或直接跑 make package / package.bat 自动生成）
go run ./cmd/updsign gen
# 输出：私钥保存到 update-signing.key；公钥（base64）打印在终端
```

把打印出的 **公钥（base64）** 配置到 mantou 面板：

```
设置 → 在线更新 → 自更新包签名公钥
```

- **私钥 `update-signing.key` 必须保密**，切勿提交或外泄（`.gitignore` 已忽略）。它是 32 字节种子的 hex 字符串。
- 只要公钥不变（即不删除 `update-signing.key` 重新生成），已配置的 mantou 就能一直校验你签的更新包。
- 想更换密钥：删除 `update-signing.key` 重新生成，再把新公钥更新到面板。

### 3. 用 Makefile 构建与打包（Linux / macOS）

```bash
make build                          # 构建本机二进制到 bin/mantou（先构建前端）
make run                            # 构建并运行（数据目录 ./data）
make dev                            # 前端热更新开发（Vite）
make package                        # 一键打包：前端 + 交叉编译 linux/amd64+arm64 + 签名 + tar.gz
make package PKG_GOARCH=arm64       # 只打单个架构
make docker                         # 构建 Docker 镜像（本机架构）
make tidy                           # 补全 go.sum
make check                          # 提交前门禁：gofmt + go vet + go build + go test（与 CI 一致）
make clean                          # 清理构建产物
```

> `make check` 与 [`.github/workflows/ci.yml`](./.github/workflows/ci.yml) 的 Go 作业逐条对应，本地跑通再推，就不会因为忘了 `gofmt -w` 在 CI 上红一轮。注意 `gofmt -l` 发现问题时**仍返回退出码 0**，所以门禁里是显式判空后 `exit 1`——自己写检查脚本时容易踩这个坑。

`make package` 的产物（可被面板「设置/关于 → 上传更新包」直接消费）：

```
mantou-Ver 1.0.0-linux-amd64.tar.gz   # 内含 mantou + mantou.sig
mantou-Ver 1.0.0-linux-arm64.tar.gz
```

> 版本号 / 编译时间在构建期注入；首次运行会生成签名密钥并提示配置公钥。

### 4. 用 package.bat 打包（Windows）

在项目根目录打开 CMD 或 PowerShell：

```bat
package.bat            :: 打包 linux/amd64 + linux/arm64
package.bat arm64      :: 只打指定架构（如 "amd64" 或 "arm64"）
```

产物与 `make package` 一致（Windows 版把版本号里的空格转成下划线，如 `mantou-Ver_1.0.0-linux-amd64.tar.gz`）。首次运行同样会生成密钥对并打印公钥。

前置：`go`、`npm`、`tar`（Win10+ 自带）需在 PATH 中；脚本默认使用国内 Go 模块代理 `goproxy.cn`。

### 5. 用 Docker 构建

```bash
# 方式一：make 封装
make docker

# 方式二：直接 docker build（可注入版本号与镜像源）
docker build \
  --build-arg VERSION="Ver 1.0.0" \
  --build-arg MIRROR=docker.1ms.run/library/ \
  --build-arg GOPROXY=https://goproxy.cn,direct \
  --build-arg NPM_REGISTRY=https://registry.npmmirror.com \
  -t mantou:latest .

# 方式三：compose
docker compose up -d --build
```

多阶段构建：`node:22-alpine`（前端）→ `golang:1.26-alpine`（后端）→ `alpine:3.24`（运行），最终镜像约 18–25 MB。国内网络卡在拉基础镜像时，用 `MIRROR` 前缀切换加速站。

### 6. 交叉编译不同平台二进制

| 目标平台 | GOOS / GOARCH | 产物 |
|----------|---------------|------|
| Linux amd64（x86_64） | `linux/amd64` | `mantou-linux-amd64` |
| Linux arm64（aarch64，树莓派 / ARM 服务器） | `linux/arm64` | `mantou-linux-arm64` |
| macOS amd64（Intel） | `darwin/amd64` | `mantou-darwin-amd64` |
| macOS arm64（Apple Silicon） | `darwin/arm64` | `mantou-darwin-arm64` |
| Windows amd64（x64，Windows 10/11） | `windows/amd64` | `mantou-windows-amd64.exe` |

手动交叉编译示例（需先构建前端）：

```bash
cd web && npm install && npm run build:only && cd ..
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o bin/mantou.exe ./cmd/mantou
```

> 上表平台矩阵已内置到 GitHub Actions（见下），推一个 tag 即可自动产出全部二进制，无需本地逐平台编译。
> 注意「产物」一列是二进制文件名；Actions 发布到 Releases 页上的是压缩包，文件名见第 7 节的表格。

### 7. 发布到 GitHub（自动构建 + 自动 Docker）

仓库已提供 [`.github/workflows/release.yml`](./.github/workflows/release.yml)：推送版本标签后，GitHub 自动完成「多平台二进制编译 + 自更新包签名 + 多架构 Docker 镜像 + 创建 GitHub Release」。

**7.1 首次准备**

```bash
# 在项目根目录初始化并首次提交（若尚未是 git 仓库）
git init
git add .
git commit -m "init mantou"
```

> 提示：`internal/version/gen.go` 是构建脚本临时生成的（构建后自动删除），已在 `.gitignore` 中忽略，无需提交。

然后到 GitHub 新建一个空仓库（如 `yourname/mantou`），关联并推送：

```bash
git remote add origin https://github.com/<你的用户名>/mantou.git
git branch -M main
git push -u origin main
```

**7.2 配置 Secrets（可选但推荐）**

GitHub 仓库 → **Settings → Secrets and variables → Actions** → 点 **New repository secret**（选 **Repository secrets** 这一层级，**不是**左侧栏的 Environments）：

| Secret | 是否必需 | 说明 |
|--------|---------|------|
| `UPDATE_SIGNING_KEY` | 可选 | 自更新签名**私钥**，即 `update-signing.key` 文件内容（64 位 hex）。⚠️ 注意：这里填**私钥**，不是公钥；公钥（base64 串）是配置到面板「设置 → 在线更新 → 自更新包签名公钥」用的 |
| `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN` | 可选 | 若要同时推送 Docker Hub（默认只推 ghcr.io）。光配这两个还不够：还要按 `release.yml` 里「同时推送到 Docker Hub」那段注释的说明，取消登录步骤的注释并在镜像标签里加上 `docker.io/<用户名>/mantou` |

**7.3 发布一个新版本**

推荐使用一键发布脚本（自动完成「提交 → 打 tag → 推送」，并智能处理同名 tag 冲突）。按你的环境选择对应命令：

**① Windows 命令提示符（cmd）或 PowerShell** —— 用 `release.bat`：

```bat
cd /d F:\你的项目目录\mantou
release.bat 1.2.0
rem 或不带参数，交互式输入版本号：
release.bat
```

> 注意：在 Windows 的 cmd / PowerShell 里**不要**直接敲 `bash release.sh`——cmd 的 `bash` 会指向 WSL，未装 WSL 发行版时会报 `/bin/bash` 找不到。`release.bat` 内部会自动定位 Git Bash 并执行 `release.sh`，推荐用它。

**② Windows Git Bash / Linux / macOS** —— 用 `release.sh`：

- Windows 打开 Git Bash：在项目文件夹空白处**右键 → Git Bash Here**（或在开始菜单搜索 "Git Bash"）。
- 进入项目目录后执行：

```bash
# Windows Git Bash 里盘符写法不同，例如 F:\Google\mantou 对应 /f/Google/mantou
cd /f/Google/mantou
bash release.sh 1.2.0       # 指定版本号
bash release.sh             # 不带参数，交互式输入版本号
# 也可以加执行权限后直接运行：chmod +x release.sh && ./release.sh 1.2.0
```

**版本号说明**：输入 `1.2.0`、`v1.2.0`、`Ver 1.2.0` 均可，脚本统一规范化为 app 版本 `Ver 1.2.0` 与 git tag `v1.2.0`。

**脚本做的事**：校验版本号格式 → 自动 `git init`（若尚未初始化）→ 配置远程仓库 origin → 检测本地与远程同名 tag（存在则提示是否删除）→ 同步 app 版本号到 `package.bat` / `Makefile` → 提交并推送分支与 tag。

方式二：手动执行（不用脚本）：

```bash
# 1) 提交改动
git add . && git commit -m "release x.y.z"

# 2) 打版本标签并推送（标签形如 v1.0.0）
git tag v1.0.0
git push origin v1.0.0
```

推送后 GitHub Actions 自动运行 `build-and-release` 工作流。产物分两类：

**一、GitHub Release 附件** —— 5 个平台的二进制压缩包（Linux / macOS 是 `.tar.gz`，Windows 是 `.zip`）：

| 文件名 | 适用平台 | 压缩包里是什么 |
|--------|----------|----------------|
| `mantou-linux-amd64.tar.gz` | Linux amd64（x86_64） | `mantou`（+ `mantou.sig`※） |
| `mantou-linux-arm64.tar.gz` | Linux arm64（aarch64，树莓派 / ARM 服务器） | `mantou`（+ `mantou.sig`※） |
| `mantou-darwin-amd64.tar.gz` | macOS amd64（Intel） | `mantou` |
| `mantou-darwin-arm64.tar.gz` | macOS arm64（Apple Silicon） | `mantou` |
| `mantou-windows-amd64.zip` | Windows amd64（x64，Windows 10/11） | `mantou.exe` |

> ※ 只有仓库配置了 `UPDATE_SIGNING_KEY`（见上文「2. 生成签名密钥对并配置公钥」）时，两个 Linux 包里才附带签名文件；没配置就只有裸二进制，这样的包只有在面板里打开「允许未验签的更新包」之后才会被接收（见下文「没填签名公钥时默认不接收更新包」）。macOS 与 Windows 版本不参与签名。
>
> Windows 版下载到的是 zip，解压后才是 `mantou.exe`。

**二、Docker 镜像** —— 推送到 `ghcr.io/<用户名>/mantou`，多架构（`linux/amd64` + `linux/arm64`），**只有 `latest` 一个标签**，不发版本号标签。

`latest` 是一个移动标签，始终指向最近一次发布的那一版。要回退到旧版本，从 **Releases** 页下载对应版本的二进制包，而不是拉旧镜像。想知道手上这个 `latest` 是哪一版，看面板「关于」页，或直接查镜像标签：

```bash
docker image inspect ghcr.io/<你的用户名>/mantou:latest --format '{{index .Config.Labels "org.opencontainers.image.version"}}'
```

在 Actions 页手动触发（Run workflow）而不是推标签时：二进制照样会编译，但只留在那次运行的 Artifacts 里，不创建 Release；镜像仍然推 `latest`（手动触发就是为了「上次推挂了再来一遍」）。

在仓库 **Actions** 页可实时查看进度，**Releases** 页下载二进制；镜像拉取：

```bash
docker pull ghcr.io/<你的用户名>/mantou:latest
```

> ghcr.io 是 GitHub 自带的容器仓库，无需额外注册。要让他人公开拉取，在仓库 Settings → Packages 里把包可见性设为 Public。

## 运行状态

容器只有 `running` / `stop` 这两个默认状态，不会出现 `healthy` / `unhealthy`；镜像里没有内置健康检查，程序也**没有**任何可供外部探活的地址。

这是有意的：一个免登录的探活地址等于向任何人确认「这个端口后面有个东西在跑」，而这正是扫端口的人想要的第一条信息，面板没有理由免费提供。

未鉴权可达的只剩登录流程本身绕不开的那几处：登录页的静态文件、`/api/init/status`（前端靠它决定显示初始化向导还是登录表单）、`/api/init/setup` 与 `/api/auth/login`。其余全部在登录之后——包括用户上传的背景图（`/uploads/`）。

想知道它在不在跑，用容器运行时自己的进程状态就够了：

```bash
docker ps
```

> 状态列显示 `Up` 就是进程在跑。要确认面板功能正常，登录进去看一眼总览页——那一页本来就是给这件事用的，而且它在登录之后。

至于那个状态标签本身：Docker 从不因为 `unhealthy` 去重启容器；部分路由器系统（如 MikroTik RouterOS）的容器功能里，自动重启也只看进程有没有退出，同样不看这个标签。真正会消费它的是「多个容器之间的依赖启动顺序」和「负载均衡摘掉坏实例」——单台自托管面板没有谁在消费它。

## 资源占用（内存 / 磁盘）

程序就是一个可执行文件，不带数据库、不带中间件、也不依赖任何外部服务，所以占用很低，而且**算得出来**。

### 一句话结论

**平时十几兆到几十兆；真正会把内存顶上去的是同时有多少条连接在跑，不是你开了几个功能。**
给它 **128 MB** 够绝大多数场景；要扛比较重的转发流量就给 **256 MB**。不要压到 64 MB 以下。

### 内存分三段看

- **刚启动、什么都没配、没有流量**：约 **15–25 MB**。
- **家用 / 小办公**（面板加几条转发或几个站点，流量不大）：约 **30–80 MB**。
- **压力上来**（大量并发连接、传大文件）：可能到 **100–200 MB** 甚至更多。Go 自己会回收，不会一路涨上去不回头。

### 平时那十几兆花在哪

下面这些都有**明确的上限**，不会随时间无限长大。写在括号里的是它对应的设置项。

| 项 | 上限 | 说明 |
| --- | --- | --- |
| 执行历史 | 1 MB | 消息处理结果的最近记录 |
| 收到的原文留存 | **0–3 MB，默认 2**（「消息路由 → 模块设置 → 原文留存」） | 被拒收或被丢弃的消息，把对方发来的原文留一份，查"为什么没收到"时全靠它。填 0 就是不留 |
| 待重试的发送队列 | 1 MB | 发失败等着重试的消息 |
| 两份日志 | 默认约 **0.7–0.9 MB**，拉满约 **3.4–4.7 MB**（「设置 → 日志 → 日志最大条数」，默认 1000 条、范围 100–5000） | 一个开关同时管着：网站访问记录、程序自己的运行日志、以及磁盘上的日志文件。改完立刻生效、不用重启；调小就只留最新的那些 |
| 运行统计 | 1 MB | 各模块的计数（收了多少、成功多少） |
| 试运行抓包 | 每个接收地址最多留一份，正文最多 256 KB | 调试用。试运行 10 分钟自动停，抓到的样本最多留 3 小时，到点真删掉 |
| 按来源限速用的计数 | 约 1.8 MB | 两处各一张表，各最多 8192 个来源 |

前三项加起来最多 **5 MB**（出厂默认 4 MB），是硬上限：条数满了或者字节满了，就从最旧的开始丢。

### 会把内存顶上去的是连接

- **端口转发**：每条连接约 **64 KB** 的搬运缓冲（收发各 32 KB，用完就还回池子里）。单个端口最多 1024 条连接，全部规则合起来最多 4096 条。单个端口打满约 64 MB。
- **反向代理**：默认**边收边发**，不会把整个网页先存下来再给你，所以每个正在传的响应约 **32 KB**。单个监听端口最多 2000 条连接。

所以估内存要按「你实际会跑到多少条同时连接」来估。动态域名、计划任务、证书这些是"到点做一下"的活，平时几乎不占内存。

### 在线更新几乎不吃内存，但要一点临时磁盘

更新包是**边下边解边写**的（压缩包既不整个读进内存、也不整个存到盘上），所以内存基本不动。它需要的临时磁盘约 **30 MB**，最坏不超过 **80 MB**：新的程序文件（约 13 MB）+ 签名文件 + 旧程序的备份，成功或失败都会立刻清掉。

注意这些临时文件放在**程序自己所在的目录**，不是数据目录——替换程序要求新旧文件在同一个磁盘分区上。Windows 不支持在线覆盖更新（接口直接返回 501），请手动换掉程序文件再重启。

### 该分配多少内存

直接跑或用 Docker 跑，给 **128 MB** 就能满足绝大多数场景；要扛比较重的转发流量，给 **256 MB** 留余量。**不要**压到 64 MB 以下，流量高峰时可能被系统直接杀掉。

镜像和 `docker-compose.yml` 里已经预设了 `GOMEMLIMIT=200MiB`。这是个**软**上限：内存快到这个数时，程序会更勤地回收并把内存还给系统，而不是被杀掉；compose 另外配了 256M 的硬上限兜底。设这个软上限的好处很实在——流量高峰把一堆搬运缓冲撑起来之后，占用会**缩回去**，而不是一直停在峰值附近，看起来像漏了内存。要更大就用 `-e GOMEMLIMIT=512MiB` 覆盖。

### 磁盘

- **程序本体**：一个可执行文件约 **13 MB**；下载的压缩包约 **4.7–5.1 MB**。
- **数据目录**（`--data` 指定，容器里默认是 `/data`）：配置文件 + 运行状态文件（都是几十 KB）+ 日志（**单个文件最多 5 MB，而且不留历史备份，所以日志目录最多就占 5 MB**）+ 证书（几 KB 到几 MB）+ 你上传的背景图和备份文件。日常通常 **不到 50 MB**。
- **Docker 镜像**：约 **18–25 MB**。
- **只有构建机才需要的**：前端依赖 `node_modules` 约 198 MB + Go 工具链。这些都不会跟着发布包下发，最终那个可执行文件里只打包了编译好的界面。

> 实际部署只要一个程序文件（或一个镜像）加一个数据目录，留 **100 MB 磁盘**绰绰有余。

> 数据目录里没人再用的文件（换掉的背景图、删掉证书后剩下的文件、导入中断留下的暂存目录）可以在「设置 → 备份与恢复 → 存储占用」里看到并清掉，不需要自己进目录翻。

### 什么时候会写磁盘

数据目录里有两个文件，职责分得很清楚，这决定了写盘的频率：

- **配置文件** `config.json` —— 面板设置、各模块的规则、账号密钥。**只在你点保存的时候写**，写法是"先写临时文件、刷到盘、再整个换过去"，所以断电不会留下半截或空文件。平时完全不动，它的修改时间就等于"配置上次被改是什么时候"。
- **运行状态文件** `state.json` —— 各条规则最近拿到的地址、最近一次结果、下次什么时候执行、证书申请到哪一步。这些是程序自己不断产出的，所以特意不跟配置放一起：变化先在内存里生效（面板上看到的永远是最新的），写盘按 **5 秒**合并一次，一轮探测里变了好几次也只写一次。程序正常退出前会强制写一次。
  代价是被强制杀掉时，最多丢 5 秒内的**状态显示**，下一轮就自己补回来了——**配置数据不受影响**。

> 备份请用面板的「设置 → 备份与恢复 → 导出配置」（里面含完整的账号密钥，见下一节）。如果是直接复制数据目录，那么 `config.json` 必须和 `master.key` **一起**复制。`state.json` 随时能重建，导入备份时会被忽略，不会把别的机器的历史状态带进来。

## 密钥怎么存的（`master.key`）

配置文件里那些"被人拿到就麻烦了"的字段**不是明文存的**，每个都单独加密过，存进去长这样：`enc:v1:…`。

| 字段 | 被人拿到会怎样 |
| --- | --- |
| 域名服务商的账号密钥 | 可以改你整个域名的解析 |
| 申请证书用的账户私钥 | 可以用你的身份去申请证书 |
| 登录会话的签名密钥 | 可以伪造出一个管理员身份 |
| 二次验证密钥（预留字段，界面暂未开放） | 可以算出有效的动态验证码 |

其他字段（端口、各种规则、外观设置）还是明文，所以配置文件照样能直接打开看——端口写错了、规则填重了这类问题，翻文件就能看出来。

**加密只管配置文件，不管证书目录。** 申请下来的证书和它的私钥是单独存成文件的（`<编号>.crt` 和 `<编号>.key`），内容是明文。这么做是有原因的：排查问题时能直接打开看，机器上别的软件（比如 nginx）也能直接拿这两个文件用。但代价要一起知道：**一份 `.key` 就足以冒充这个域名**，直到证书过期为止。所以**证书目录和配置文件一样敏感**：备份请用面板的导出功能（证书和私钥都在里面），要直接拷数据目录就当"这份拷贝里有能用的私钥"对待——别放进代码仓库，也别塞进随手发给别人的快照或镜像里。

- **密钥文件在哪**：数据目录下的 `master.key`，第一次需要时自动生成，权限只给当前用户。
- **不想让它落到盘上**：设置环境变量 `MANTOU_MASTER_KEY`，它优先于密钥文件，这时磁盘上根本不会有 `master.key`——适合用容器自带的密钥管理，或者由 systemd 单独把密钥传进来。
- **为什么要加密**：文件权限只防得住"同一台机器上的其他普通用户"。现实里最常见的泄露方式是**整个文件被带走**：拷贝数据目录做备份、把数据盘挂到别处排查、宿主机快照被分发、不小心把数据目录提交进了仓库。这些情况下文件权限一点用都没有。
- **它挡不住什么**：如果对方同时拿到了配置文件**和** `master.key`（两个就在同一个目录里），加密就没用了。它挡的是"只拿到配置文件"这一大类情况。想要更强的隔离就用上面那个环境变量。

### 备份与换机

两条路，选一条：

1. **用面板导出（推荐，换机就能用）**：「设置 → 备份与恢复 → 导出配置」。导出的整个文件是加密的，密钥由**你的登录账户名 + 登录密码**推算出来。所以**换到新机器导进去就能直接用**：外观、皮肤、各模块规则、账号密钥一起回来，不需要把 `master.key` 一起带走，导入方会用它自己新生成的密钥重新加密存盘。代价是**忘了当时导出用的账号和密码就恢复不了**。
   > 导入之后请用**备份里那一套账户名和密码**登录（登录账户会跟着备份一起覆盖）。导入时会**强制沿用新机器本地的**会话签名密钥，不采用备份里那把——否则任何人都能做一份"签名密钥已知"的备份，导进去就能伪造管理员身份。所以如果备份里的账户名和当前不一样，当前这个登录状态会立刻失效，需要重新登录一次。
2. **直接拷数据目录**：`config.json` 和 `master.key` 必须**一起**拷。只恢复了配置文件的话，程序**一启动就会报错并告诉你怎么处理**，不会闷着不说——不然域名解析和证书续期会在下一个周期里冒出一堆"账号验证失败"，那时候排查起来麻烦得多。这条路下证书私钥是明文跟着走的，请按上一节那句"这份拷贝里有能用的私钥"对待。

### `master.key` 丢了怎么办

按代价从小到大：

1. 用面板导出的那份加密备份重新导入（里面有完整的账号密钥）——首选。
2. 把原来的 `master.key` 找回来（旧的数据目录副本、磁盘快照、镜像层里都有可能还留着）。
3. 都没有：把 `config.json` 里所有以 `enc:v1:` 开头的值改成 `""`，启动后在面板里把这几处账号密钥重新填一遍。**其他配置（端口、Web 服务/转发/计划任务的规则、外观设置）完好无损**，只是要重新填一次密钥、重新登录一次。


## 注意事项与已知限制

下面这些都是设计上的取舍或者平台本身的限制，不是你配错了。遇到对应现象先看这里。

### 用 Docker 默认网络时，网络唤醒不管用

开机信号是靠**局域网广播**发出去的：程序会把本机所有能广播的网卡都找出来，各自发一遍。而 Docker 默认的桥接网络里，容器只看得见自己那块虚拟网卡，广播只在容器内部那个小网段里打转，**根本到不了你要唤醒的那台机器所在的局域网**。这时面板会显示"发送成功"——因为信号确实发出去了，只是发错了网段。

解决办法（Linux 宿主机）：让容器直接用宿主机的网络，把 `docker-compose.yml` 里 `network_mode: host` 那行的注释去掉，并删掉 `ports` 那一段。**Windows / macOS 上的 Docker Desktop 不支持这个模式**，桌面系统请直接在机器上跑程序文件（`./bin/mantou --data ./data`），这也是最省事的做法。

### 容器里是用 root 跑的

镜像没有降权，容器里的进程是 root。原因是 Web 服务和端口转发要能占用**任意**端口（包括 80、443 这类需要特权的端口），开机唤醒还要发广播——自己架的网络工具基本都是这么做的。

想降权也行，代价是失去一部分能力：

```bash
# 只保留"能占用特权端口"这一项能力，用普通用户跑
docker run -d --name mantou \
  --user 1000:1000 \
  --cap-add NET_BIND_SERVICE \
  -p 25666:25666 -v $(pwd)/data:/data mantou:latest
```

注意：`--user` 要求数据目录对这个用户可写（`chown -R 1000:1000 ./data`）；网络唤醒在"非 root + 桥接网络"下基本没法用；在线更新要覆盖程序文件，非 root 时会因为目录不可写而失败（这时请改用"拉新镜像、重建容器"的方式升级）。

### Windows 上不能在线覆盖更新

在 Windows 上，上传更新包会直接被拒绝并提示手动替换。这是 Windows 自己的规矩决定的：正在运行的程序文件没法被改名覆盖，Linux 那套"解包 → 一步换过去"在 Windows 上不成立。Windows 下请先停掉程序、换掉 `mantou.exe`、再启动。Linux 和 macOS 不受影响。

### 没填签名公钥时默认不接收更新包

更新包能不能被应用，由「设置 → 在线更新」里两处一起决定：填了「自更新包签名公钥」，上传的包就必须附带同名 `.sig` 且验签通过；公钥留空时，还收不收包由「允许未验签的更新包」这个开关说话，而**它默认是关的**。也就是说，刚装好、什么都没配的状态下，上传更新包会被直接拒绝，面板「关于」页也会一直挂一条提示条写明这一点。要在不验签的情况下更新，得自己去把那个开关打开——这条路能直接换掉你的程序文件，所以它不默认开着。怎么生成密钥、公钥填哪里，见上文那一节。

> 打开那个开关之后，包本身仍要过好几道检查：体积上限、里面的文件条数上限、同名文件不许重复、架构必须和当前机器一致，最后还要拿新文件试跑一次。但这些只能挡住"坏掉的包"，挡不住"被人精心换过的包"——那必须靠验签。

### 百度智能云 DNS 没在真实环境上验证过

签名算法是严格照官方文档实现的，也有单元测试盯着；但"增删改查解析记录"那几个接口的地址和字段，是按常规约定写的，**没在真实账号上跑通过**。如果你用百度云的域名、遇到解析更新失败，问题几乎一定在那几个地址或字段上，改一个文件就能调好，不影响签名逻辑，也不影响其他服务商（阿里云、腾讯云（DNSPod）、Cloudflare 这些都验证过了）。欢迎带上接口返回的内容提 issue。

### 「访问日志」记的是访问这件事，不是每一个请求

Web 服务页的访问日志刻意**不逐个请求记**，记的是几件事：连上了、断开了、出错了、被规则拒了、周期性探测。同一个来源在 **10 分钟**内的重复事件会合并成一条，另外还有整体的写入速率上限。

这是故意的：打开一个网页可能产生几十个请求（网页 + 脚本 + 样式 + 图片），逐个记的话几秒钟就把缓冲冲满了，真正有用的"谁什么时候访问了哪个站、有没有被拒"反而被挤掉，而且访问量一大，记日志本身就成了拖慢的原因。**所以这里的条数不能当访问量看，也别指望它替代专业 Web 服务器的访问日志**——需要完整到每个请求的日志，请在上游或者后端应用那边记。

### 要给站点加账号密码，得先开 HTTPS

Web 服务（反向代理 / 静态网页）可以额外加一道**账号密码**：访问者先输入账号密码，通过了才转给后端。它**默认关闭**，而且是每条 Web 服务子项各自的开关——只有这条子项**开了 HTTPS**，面板上才会出现这个开关。

原因很直接：这种认证方式会把账号密码放在**每一个**请求里带过去，而且**等于明文**。走普通 HTTP 就是把密码在网络上反复广播。所以干脆把它和 HTTPS 绑在一起，而不是留给用户自己判断。

相应地，**开 HTTPS 会自动一并打开"强制 HTTPS"**（普通 HTTP 访问自动跳到 HTTPS），不用再手动勾——否则 HTTP 那个端口还能访问，密码照样会明文过网。密码在配置里是**不可逆的哈希**，看不出原文。

### 面板的 HTTPS 开关来回切之后要重新登录一次

面板记录登录状态的那块数据，按连接方式分成两个不同的名字：普通连接用一个，HTTPS 连接用另一个（后者带浏览器强制要求的安全前缀）。

这不是讲究，而是为了绕开浏览器的一条规则：**普通连接不允许创建或覆盖一条同名的"仅安全连接可用"的记录，删也删不掉**。如果两种连接方式共用一个名字，那么"先开面板 HTTPS → 再关掉 → 继续用 `http://域名` 访问"之后，浏览器里 HTTPS 时期留下的那条会把新发的同名记录整个挡掉，而服务端在普通连接上既覆盖不了也删不掉它——表现就是**输入正确的账号密码后界面闪一下又回到登录页，而日志里写着"登录成功"**（这时换成用 IP 访问反而正常，因为记录是按域名分开存的，IP 那边没有残留）。分成两个名字之后，这种冲突从结构上就不可能发生了。

代价只有一处：**切换面板的 HTTPS 开关之后，当前的登录状态不会自动延续，需要重新登录一次**（换了连接方式就等于换了一条记录）。另外，为了兼容老版本，旧名字仍然会被**读取**（不再写入），所以从旧版本升级不会把已经登录的人踢下线。
