#!/usr/bin/env bash
# ============================================================================
# mantou 本地打包脚本
#
#   输入版本号 → 构建前端 → 交叉编译 linux/amd64 + linux/arm64 → Ed25519 签名 → tar.gz
#
# 产物：项目根目录的 mantou-Ver_x.y.z-linux-<架构>.tar.gz（内含 mantou 与 mantou.sig），
#       可直接在面板「关于 → 上传更新包」里使用。
#
# 只在本机打包：不提交、不打 tag、不推送 GitHub——那是 release.sh
#（Windows 上是「发布到GitHub.bat」）的事。两个脚本互不调用。
#
# 用法：
#   Windows：双击或运行「本地打包更新包.bat」，它会找到 Git Bash 来执行本脚本
#   Git Bash / Linux：
#     bash package.sh                 交互式输入版本号（直接回车沿用默认）
#     bash package.sh 1.2.0           指定版本号，不再询问
#     bash package.sh 1.2.0 arm64     指定版本号，只打 arm64
#     bash package.sh arm64           只打 arm64，版本号交互输入
#   版本号写 1.2.0 / v1.2.0 / "Ver 1.2.0" 都行，统一成 "Ver 1.2.0"（规则与 release.sh 相同）。
#   Linux / macOS 上也可以用 make package，产物相同。
#
# 为什么打包逻辑放在 bash 里、而不是直接写在 .bat 里：
#   cmd 读含中文（UTF-8）的批处理不可靠——会把行切错，注释的半截被当成命令执行；
#   随控制台代码页（中文 Windows 默认 936）不同，坏的地方还不一样。bash 读 UTF-8 脚本
#   没有这个问题，所以 .bat 只保留纯 ASCII 的外壳（找到 Git Bash 再调本脚本），
#   与「发布到GitHub.bat」→ release.sh 是同一个做法。
#
# 前置：go、npm、tar 在 PATH 中（Windows 上装好 Go、Node.js、Git for Windows 即可）。
# ============================================================================
set -euo pipefail

# 从任何目录启动都以项目根目录为准（双击 .bat 时当前目录不一定是这里）。
cd "$(dirname "$0")"

# 默认版本号：发布时由 release.sh 第 8 步同步成刚发布的那一版，所以打包时直接回车
# 就是"和最近一次发布同一个版本号"。手动改这一行也可以。
# 这一行的写法要保持 DEFAULT_VERSION="Ver x.y.z"，release.sh 按这个格式查找与替换。
DEFAULT_VERSION="Ver 1.0.11"

APP="mantou"
BIN_DIR="bin"
PKG_GOOS="linux"

# ---------- 颜色输出（与 release.sh 同一套） ----------
C_RED='\033[31m'; C_GREEN='\033[32m'; C_YELLOW='\033[33m'; C_CYAN='\033[36m'; C_RESET='\033[0m'
info() { echo -e "${C_CYAN}[信息]${C_RESET} $*"; }
ok()   { echo -e "${C_GREEN}[成功]${C_RESET} $*"; }
warn() { echo -e "${C_YELLOW}[提示]${C_RESET} $*"; }
err()  { echo -e "${C_RED}[错误]${C_RESET} $*" >&2; }

usage() {
  cat <<EOF

本地打包：在本机编译 Mantou，打出 Linux 自更新包（不会提交或推送 GitHub）

用法：
  本地打包更新包.bat  /  bash package.sh                   按提示输入版本号（直接回车沿用默认 ${DEFAULT_VERSION}）
  本地打包更新包.bat 1.2.0  /  bash package.sh 1.2.0       指定版本号，不再询问
  本地打包更新包.bat 1.2.0 arm64                           指定版本号，只打 arm64
  本地打包更新包.bat arm64                                 只打 arm64，版本号按提示输入

版本号写 1.2.0 / v1.2.0 / "Ver 1.2.0" 都可以。默认打 amd64 与 arm64 两个架构。
要把新版本发布到 GitHub，请改用「发布到GitHub.bat」（或 bash release.sh）。
EOF
}

# 版本号规范化与校验：与 release.sh 第 1 步逐字相同，两边认的写法必须一致。
normalize_version() {
  printf '%s' "$1" \
    | sed -E 's/^[[:space:]]*[Vv][Ee][Rr][[:space:]]+//' \
    | sed -E 's/^[[:space:]]*[vV]//' \
    | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//'
}
valid_version() {
  printf '%s' "$1" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z]+)*$'
}

# ---------- 0. 参数：带点的是版本号，其余是架构名 ----------
ARG_VER=""
ARCHS=()
for a in "$@"; do
  case "$a" in
    -h|--help|/\?) usage; exit 0 ;;
    *.*) ARG_VER="$a" ;;
    *)
      # 也接受 "amd64 arm64" 这样一个带空格的参数（旧 package.bat 的写法）。
      # 用 read -ra 拆，不用 for x in $a：后者会把 * 之类当通配符展开成文件名。
      read -ra parts <<< "$a"
      ARCHS+=("${parts[@]}")
      ;;
  esac
done
[ ${#ARCHS[@]} -eq 0 ] && ARCHS=(amd64 arm64)
for x in "${ARCHS[@]}"; do
  # 架构名会进文件名与 GOARCH，只允许小写字母和数字。
  case "$x" in
    *[!a-z0-9]*) err "架构名无效：$x（例如 amd64、arm64）"; exit 1 ;;
  esac
done

echo
echo "============================================================"
echo "  Mantou 本地打包：编译并生成 Linux 自更新包"
echo "  （只在本机打包，不会提交或推送任何东西到 GitHub）"
echo "============================================================"

# ---------- 1. 前置检查 ----------
command -v go  >/dev/null 2>&1 || { err "PATH 中找不到 go，请先安装 Go"; exit 1; }
command -v npm >/dev/null 2>&1 || { err "PATH 中找不到 npm，请先安装 Node.js"; exit 1; }
command -v tar >/dev/null 2>&1 || { err "PATH 中找不到 tar"; exit 1; }
[ -f go.mod ] && [ -d web ] || { err "找不到 go.mod 或 web 目录，本脚本要放在项目根目录"; exit 1; }

# ---------- 2. 版本号 ----------
if [ -n "$ARG_VER" ]; then
  CORE_VERSION="$(normalize_version "$ARG_VER")"
  if ! valid_version "$CORE_VERSION"; then
    err "版本号格式无效：${ARG_VER}（应为 1.2.3 这样的三段数字，可带 v / Ver 前缀，可带 -beta1 这类后缀）"
    exit 1
  fi
else
  while :; do
    echo
    info "默认版本号：${DEFAULT_VERSION}（最近一次发布同步过来的）"
    RAW_VER=""
    INPUT_ENDED=0
    if ! read -r -p "请输入本次打包的版本号（如 1.2.0，直接回车沿用默认）：" RAW_VER; then
      INPUT_ENDED=1 # 输入已结束（非交互运行、管道已读完）：按"直接回车"处理
      echo
    fi
    if [ -z "$(printf '%s' "$RAW_VER" | tr -d '[:space:]')" ]; then
      RAW_VER="$DEFAULT_VERSION"
    fi
    CORE_VERSION="$(normalize_version "$RAW_VER")"
    valid_version "$CORE_VERSION" && break
    err "版本号格式无效：${RAW_VER}（应为 1.2.3 这样的三段数字，可带 v / Ver 前缀，可带 -beta1 这类后缀）"
    # 输入已经结束、或默认值本身就写错了：再问也问不出别的结果，直接退出，免得死循环。
    if [ "$INPUT_ENDED" = 1 ] || [ "$RAW_VER" = "$DEFAULT_VERSION" ]; then
      exit 1
    fi
  done
fi
VERSION="Ver ${CORE_VERSION}"
# 文件名里的版本号不带空格（空格换成下划线），与 Makefile / 旧 package.bat 一致。
ARCHIVE_VER="Ver_${CORE_VERSION}"

# ---------- 3. 构建环境（模块代理 / 工具链 / 编译时间） ----------
# 模块代理：默认用国内镜像；你自己设过 GOPROXY / GOSUMDB 的话以你的为准。
# 依赖的完整性仍由 go.sum 校验（-mod=readonly），镜像给错内容只会让构建失败。
export GOPROXY="${GOPROXY:-https://goproxy.cn,direct}"
export GOSUMDB="${GOSUMDB:-off}"
# 强制用本机安装的 Go：不让 go 按 go.mod 自动下载、切换到别的工具链版本，
# 于是"打包用的是哪个 Go"只取决于本机装的那一个——下面的汇总里会把它打印出来。
# 本机 Go 需满足 go.mod 的下限（go 1.26.0）；建议用该版本线的最新补丁版。
export GOTOOLCHAIN="${GOTOOLCHAIN:-local}"
GO_VER="$(go env GOVERSION)"
BUILD_TIME="$(date '+%Y-%m-%d %H:%M:%S')"
EXE="$(go env GOEXE)" # Windows 上是 .exe，签名工具是在本机运行的，要带上它

echo
echo "------------------------------------------------------------"
echo "  打包版本：${VERSION}"
echo "  目标架构：${ARCHS[*]}（${PKG_GOOS}）"
echo "  使用的 Go：${GO_VER}"
echo "  编译时间：${BUILD_TIME}"
echo "  产物位置：项目根目录 ${APP}-${ARCHIVE_VER}-${PKG_GOOS}-<架构>.tar.gz"
echo "------------------------------------------------------------"
if [ "$VERSION" != "$DEFAULT_VERSION" ]; then
  warn "版本号与默认值 ${DEFAULT_VERSION} 不同；之后若要发布到 GitHub，请在发布时输入同一个版本号。"
fi

# ---------- 4. 构建前端（web/dist） ----------
# 用 npm ci 而不是 npm install：严格按 package-lock.json 安装、绝不改写它。
# npm install 可能顺手改写锁文件，而 release.sh 是 git add -A 提交的，
# 一次打包就可能把没人审过的依赖变更带上 GitHub。
echo
info "[1/3] 构建前端……"
(cd web && npm ci && npm run build:only)

# ---------- 5. 自更新签名：编译签名工具，确保 Ed25519 密钥对存在 ----------
# 第一次运行会随机生成密钥对并打印公钥；私钥存在 update-signing.key（绝不能提交或外传）。
# 之后一直复用同一把私钥，面板里配置过的公钥才持续有效。
echo
info "[2/3] 准备签名工具与密钥……"
mkdir -p "$BIN_DIR"
UPDSIGN="${BIN_DIR}/updsign${EXE}"
go build -trimpath -mod=readonly -o "$UPDSIGN" ./cmd/updsign
if [ -f update-signing.key ]; then
  info "使用已有的签名私钥：update-signing.key"
else
  info "正在生成自更新签名密钥对……"
  "$UPDSIGN" gen
  echo
  warn "请把上面打印的公钥配置到 Mantou 面板：设置 → 在线更新 → 自更新包签名公钥"
fi

# 打包用的 tar。GNU tar（Git Bash、Linux）显式写死权限与属主：
#   - mantou 记成 0755，解压后直接能运行（Windows 上的文件没有可执行位，不指定就是 0644）；
#   - 属主记成 0/0，不把本机的用户名（如 Administrator）写进发出去的包里。
# 其它 tar（macOS 的 bsdtar）不认这些参数，退回普通写法——那边本来就该用 make package。
pack() {
  local out="$1"
  if tar --version 2>/dev/null | grep -q 'GNU tar'; then
    local tmp="${out%.gz}"
    rm -f "$tmp"
    tar --format=gnu --owner=0 --group=0 --numeric-owner --mode=0755 -cf "$tmp" -C "$BIN_DIR" "$APP"
    tar --format=gnu --owner=0 --group=0 --numeric-owner --mode=0644 -rf "$tmp" -C "$BIN_DIR" "${APP}.sig"
    gzip -9 -f "$tmp"
  else
    tar -czf "$out" -C "$BIN_DIR" "$APP" "${APP}.sig"
  fi
}

# ---------- 6. 逐个架构：交叉编译 + 签名 + 打包 ----------
echo
info "[3/3] 编译并打包……"
for ARCH in "${ARCHS[@]}"; do
  echo
  info "== 编译 ${PKG_GOOS}/${ARCH} =="

  # 版本号与编译时间写进 internal/version/gen.go。这个文件刻意留在盘上：之后在本机直接
  # go build，也带着与这次打包相同的版本号与编译时间。它在 .gitignore 里，不会进提交。
  # 直接按 gofmt 的格式写（tab 缩进），再跑一次 go fmt 兜底：CI 与 make check 的
  # gofmt 门禁会扫到它，格式不对就会指着一个谁都没编辑过的文件报错。
  printf 'package version\n\n// Code generated by the build script. DO NOT EDIT.\nfunc init() {\n\tVersion = "%s"\n\tBuildTime = "%s"\n}\n' \
    "$VERSION" "$BUILD_TIME" > internal/version/gen.go
  go fmt ./internal/version/ >/dev/null

  # 不跑 go mod tidy：打包不该改写 go.mod / go.sum（理由同上面的 npm ci）。
  # -mod=readonly 让过期的 go.sum 直接报错，而不是被悄悄"修好"——与 CI、Dockerfile 一致。
  CGO_ENABLED=0 GOOS="$PKG_GOOS" GOARCH="$ARCH" \
    go build -trimpath -mod=readonly -ldflags "-s -w" -o "${BIN_DIR}/${APP}" ./cmd/mantou

  # 签名：对二进制的 SHA-256 摘要做 Ed25519 签名，以 mantou.sig 一起打进包里；
  # 面板配置了签名公钥时，上传更新包会校验它。
  "$UPDSIGN" sign -key update-signing.key "${BIN_DIR}/${APP}" "${BIN_DIR}/${APP}.sig"

  OUT="${APP}-${ARCHIVE_VER}-${PKG_GOOS}-${ARCH}.tar.gz"
  pack "$OUT"
  ok "已生成 ${OUT}"
done

echo
echo "============================================================"
ok "全部完成：${VERSION}，产物在项目根目录："
for ARCH in "${ARCHS[@]}"; do
  echo "    ${APP}-${ARCHIVE_VER}-${PKG_GOOS}-${ARCH}.tar.gz"
done
echo "  在面板「关于 → 上传更新包」选择对应架构的那一个即可。"
echo "============================================================"
