#!/usr/bin/env bash
# ============================================================================
# mantou 一键发布脚本
#
#   提交代码 → 打 tag → 推送到 GitHub → 触发 Actions 自动构建 Docker + 二进制 + Release
#
# 用法：
#   bash release.sh 1.2.0    指定版本号
#   bash release.sh          不带参数，交互式输入版本号
#   （Windows 用 release.bat，它会自动调用本脚本）
#
# 版本号约定：
#   输入 "1.2.0" / "v1.2.0" / "Ver 1.2.0" 均可，统一规范化为：
#     app 版本 "Ver 1.2.0"（自动同步写入 package.bat / Makefile）
#     git tag  "v1.2.0"（推送到远程，CI 从 tag 提取出 "Ver 1.2.0"）
#
# 关键交互点（脚本会停下来等你确认/输入）：
#   1. 版本号确定后 → 生成 commit-message.txt 并打开编辑器，等你写好提交信息保存
#   2. git 身份未配置时 → 提示输入 user.name / user.email
#   3. 当前 origin 与目标仓库不一致时 → 询问是否切换
#   4. 同名 tag 冲突 → 询问是否删除重打 / 重推
#   5. 工作区无改动时 → 询问是否用 commit-message.txt 改写当前提交的信息
#   6. 推送前远程不可达时 → 警告并询问是否仍要推送
#
# 说明：本脚本只负责「提交 + 打 tag + 推送」，真正的打包（Docker 多架构镜像、
#       多平台二进制、GitHub Release）由 GitHub Actions 在 tag 推送后自动完成。
#       如需本地生成 tar.gz 自更新包，请另跑 `package.bat`（Windows）或 `make package`。
# ============================================================================
set -euo pipefail

REPO_URL="https://github.com/ovoene/Mantou"

# ---------- 颜色输出 ----------
C_RED='\033[31m'; C_GREEN='\033[32m'; C_YELLOW='\033[33m'; C_CYAN='\033[36m'; C_RESET='\033[0m'
info() { echo -e "${C_CYAN}[信息]${C_RESET} $*"; }
ok()   { echo -e "${C_GREEN}[成功]${C_RESET} $*"; }
warn() { echo -e "${C_YELLOW}[警告]${C_RESET} $*"; }
err()  { echo -e "${C_RED}[错误]${C_RESET} $*"; }

# ---------- 0. 前置检查 ----------
command -v git >/dev/null 2>&1 || { err "未找到 git，请先安装 Git"; exit 1; }
[ -f go.mod ] || { err "请在项目根目录运行本脚本（需存在 go.mod）"; exit 1; }

# ---------- 1. 版本号 ----------
if [ $# -ge 1 ]; then
  RAW_VERSION="$1"
else
  read -r -p "请输入版本号（如 1.2.0，同时作为 app 版本与远程 tag）：" RAW_VERSION
fi

# 规范化：去 "Ver "/"ver " 前缀 → 去 "v"/"V" 前缀 → 去首尾空白
CORE_VERSION=$(printf '%s' "$RAW_VERSION" \
  | sed -E 's/^[[:space:]]*[Vv][Ee][Rr][[:space:]]+//' \
  | sed -E 's/^[[:space:]]*[vV]//' \
  | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')

if ! printf '%s' "$CORE_VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z]+)*$'; then
  err "版本号格式无效：$RAW_VERSION（应为 1.2.3 形式）"
  exit 1
fi

TAG="v${CORE_VERSION}"
APP_VER="Ver ${CORE_VERSION}"

info "app 版本：${APP_VER}"
info "git tag ：${TAG}"
info "远程仓库：${REPO_URL}"

# ---------- 2. 提交信息（先写好，存成 UTF-8 文件） ----------
# 放在最前面，而不是等到临提交那一步，是因为下面第 8 步会改写 package.bat / Makefile
# 的版本号——那时工作区必然是脏的，"有没有东西要提交"这个判断就没了参考价值。
# 先把信息准备好，后面无论走"新建提交"还是"改写上一个提交"都直接拿来用。
#
# 为什么不在命令行里直接输入：这台机器 cmd 的代码页是 936（GBK），中文经 read 读进来
# 就是 GBK 字节，提交上去是乱码；而 Git for Windows 里没带 iconv，脚本内没法转码。
# 写进文件、由编辑器按 UTF-8 存盘，是唯一稳的路。顺带解决另外两件：提交信息可以写多行，
# 署名行也能落在末尾（单行 git commit -m 做不到）。
MSG_FILE="commit-message.txt"
CO_AUTHOR="Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
DEFAULT_MSG="release: ${APP_VER}"

if [ -f "$MSG_FILE" ]; then
  info "沿用已存在的 ${MSG_FILE}（上一次跑到一半退出时留下的）"
else
  printf '%s\n\n%s\n' "$DEFAULT_MSG" "$CO_AUTHOR" > "$MSG_FILE"
  ok "已生成 ${MSG_FILE}：第一行是提交标题，空一行之后是署名"
fi

# 尽量替你打开（记事本会一直占着，直到你关掉它）。打不开也不影响，下面还会停下来等确认。
if [ -n "${EDITOR:-}" ]; then
  "$EDITOR" "$MSG_FILE" || true
elif command -v notepad.exe >/dev/null 2>&1; then
  notepad.exe "$MSG_FILE" || true
else
  warn "没找到可用的编辑器，请自己打开 ${MSG_FILE} 编辑后回来"
fi

read -r -p "提交信息已写好、并以 UTF-8 编码保存？[回车继续 / q 取消] " ans
if [ "$ans" = "q" ] || [ "$ans" = "Q" ]; then
  err "已取消"
  exit 1
fi

# 记事本存 UTF-8 时会在开头加 BOM、行尾用 CRLF：BOM 会跟着跑进提交标题里，一并清掉。
sed -i '1s/^\xEF\xBB\xBF//' "$MSG_FILE"
sed -i 's/\r$//' "$MSG_FILE"

if [ -z "$(sed -n '1p' "$MSG_FILE" | tr -d '[:space:]')" ]; then
  err "${MSG_FILE} 第一行（提交标题）是空的，写好再重跑"
  exit 1
fi
# 署名必须单独成行落在末尾、且前面隔一个空行，GitHub 才认它是共同作者。
if ! grep -qF "$CO_AUTHOR" "$MSG_FILE"; then
  printf '\n%s\n' "$CO_AUTHOR" >> "$MSG_FILE"
  info "已补上署名行"
fi
ok "提交信息就绪"

# ---------- 3. 初始化 git（若尚未 init） ----------
if [ ! -d .git ]; then
  info "尚未 git init，正在初始化…"
  git init -b main 2>/dev/null || git init
fi

# ---------- 4. 配置/检查远程仓库（是否需要切换仓库） ----------
if git remote get-url origin >/dev/null 2>&1; then
  CUR_URL=$(git remote get-url origin)
  if [ "$CUR_URL" != "$REPO_URL" ]; then
    warn "当前 origin = $CUR_URL"
    warn "目标仓库 = $REPO_URL"
    read -r -p "是否切换 origin 到目标仓库？[y/N] " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
      git remote set-url origin "$REPO_URL"
      ok "已切换 origin"
    else
      warn "保持当前 origin（$CUR_URL），继续使用它推送"
    fi
  fi
else
  git remote add origin "$REPO_URL"
  ok "已配置远程仓库 origin"
fi

# ---------- 5. 检查 git 身份（提交必需，未配置则交互输入） ----------
if [ -z "$(git config user.name 2>/dev/null)" ]; then
  warn "git user.name 未配置（提交必需）"
  read -r -p "请输入你的名字（git user.name）：" GIT_NAME
  if [ -n "$GIT_NAME" ]; then
    git config user.name "$GIT_NAME"
    ok "已设置 user.name = $GIT_NAME"
  else
    err "未输入名字，无法继续"
    exit 1
  fi
fi
if [ -z "$(git config user.email 2>/dev/null)" ]; then
  warn "git user.email 未配置（提交必需）"
  read -r -p "请输入你的邮箱（git user.email）：" GIT_EMAIL
  if [ -n "$GIT_EMAIL" ]; then
    git config user.email "$GIT_EMAIL"
    ok "已设置 user.email = $GIT_EMAIL"
  else
    err "未输入邮箱，无法继续"
    exit 1
  fi
fi

# ---------- 6. 同步远程 tag（容错：首次推送/离线可忽略） ----------
info "同步远程仓库…"
git fetch --tags origin 2>/dev/null || warn "暂无法连接远程（首次推送可忽略）"

# ---------- 7. 智能检查 tag 冲突 ----------
if git tag -l "$TAG" | grep -q .; then
  warn "本地已存在 tag：$TAG"
  read -r -p "是否删除本地 tag 并重新打？[y/N] " ans
  if [[ "$ans" =~ ^[Yy]$ ]]; then
    git tag -d "$TAG"
    ok "已删除本地 tag $TAG"
  else
    err "已取消（本地 tag 已存在）"
    exit 1
  fi
fi

if git ls-remote --tags origin "refs/tags/$TAG" 2>/dev/null | grep -q .; then
  warn "远程已存在 tag：$TAG（可能对应已发布的 Release）"
  read -r -p "是否删除远程 tag 并重新推送？[y/N] " ans
  if [[ "$ans" =~ ^[Yy]$ ]]; then
    git push origin --delete "$TAG"
    ok "已删除远程 tag $TAG"
  else
    err "已取消（远程 tag 已存在）"
    exit 1
  fi
fi

# ---------- 8. 同步 app 版本号到本地打包脚本（保持本地打包与 CI 一致） ----------
# 只在版本号确实不一致时才动文件。原因：这个 sed 是 MSYS2 版的，读文件时会把 \r 全吃掉，
# 写回来只有 \n——哪怕替换前后内容一字不差，package.bat 也会从 CRLF 变成 LF，
# 于是 git status 报出一个只差行尾的假改动（第一次运行就是被这个假改动带崩的）。
if [ -f package.bat ]; then
  CUR_VER="$(sed -n 's/^set VERSION=//p' package.bat | head -1 | tr -d '\r')"
  if [ "$CUR_VER" = "$APP_VER" ]; then
    info "package.bat 版本号已是 ${APP_VER}"
  else
    sed -i "s/^set VERSION=.*/set VERSION=${APP_VER}/" package.bat
    # 把上面被 sed 吃掉的 \r 补回来：.gitattributes 里 *.bat 声明的是 eol=crlf，
    # 而 cmd.exe 跑纯 LF 的批处理在 goto / 多行块上有已知的踩坑。
    sed -i 's/\r*$/\r/' package.bat
    info "已同步 package.bat 版本号为 ${APP_VER}"
  fi
fi
if [ -f Makefile ]; then
  CUR_VER="$(sed -n 's/^VERSION[[:space:]]*?=[[:space:]]*//p' Makefile | head -1 | tr -d '\r')"
  if [ "$CUR_VER" = "$APP_VER" ]; then
    info "Makefile 版本号已是 ${APP_VER}"
  else
    sed -i "s/^VERSION[[:space:]]*?=.*/VERSION    ?= ${APP_VER}/" Makefile
    info "已同步 Makefile 版本号为 ${APP_VER}"
  fi
fi

# ---------- 9. 提交（用第 2 步写好的那份信息） ----------
# 先把改动全部入暂存区，再判断"到底有没有真改动"，这个顺序不能颠倒。
# 反面教材（第一次运行就死在这）：判断用的是 `git status --porcelain` 非空，
# 它把上一步那个只差行尾的 package.bat 算成改动，于是走了"新建提交"这条路；
# 可 git add 会按 .gitattributes 归一化行尾，入库内容与 HEAD 一模一样，
# 紧接着的 git commit 判定 "nothing to commit" 并退出 1 —— set -e 当场把脚本掐掉，
# 后面的 push 与打 tag 根本没跑到。
# 所以判断只认"暂存区与 HEAD 之间的差异"：假改动骗不到它，未跟踪文件也算得进去
# （不能改用 git diff 不带 --cached，那个看不见未跟踪文件，首次提交会被漏掉）。
git add -A

# 兜底检查：暂存区里不许出现凭据文件。
# 这一条不能只靠 .gitignore——上面那句是 git add -A，等于说「哪些文件不上传」完全由那份
# 排除清单决定，于是那份清单本身就成了一个安全控制项：谁不小心动一行，或者谁把密钥换个
# 位置放（比如把 master.key 挪出 data/），推上去就是公开泄露，而 GitHub 上的历史删不干净
# （tag、fork、各级缓存都还留着旧对象）。所以在推之前按文件名再拦一次。
# 查索引而不是工作区：索引就是紧接着要提交的那份内容，.gitignore 已经在上一句里生效过了。
CRED_HITS="$(git ls-files -c |
  grep -Ei '(^|/)(update-signing\.key|master\.key|\.env(\..*)?)$|\.(key|pem|crt|p12|pfx)$|^data/' || true)"
if [ -n "$CRED_HITS" ]; then
  err "暂存区里有疑似凭据文件，已中止发布（这些内容一旦推上 GitHub 就删不干净）："
  echo "$CRED_HITS" | sed 's/^/    /'
  echo ""
  err "先确认 .gitignore 是否被改动过；确实该提交的话，用 git rm --cached 移出暂存区再重跑。"
  exit 1
fi

if ! git rev-parse -q --verify HEAD >/dev/null 2>&1; then
  # 仓库里还没有任何提交：无论如何都要提交这一次，否则 push HEAD 会报
  # "src refspec HEAD does not match any"。
  HAS_CHANGES=1
elif git diff --cached --quiet HEAD; then
  HAS_CHANGES=0
else
  HAS_CHANGES=1
fi

MSG_USED=0
if [ "$HAS_CHANGES" = "1" ]; then
  info "本次将提交以下改动："
  git status --short
  echo ""
  git commit -F "$MSG_FILE"
  MSG_USED=1
  ok "已提交：$(sed -n '1p' "$MSG_FILE")"
else
  info "没有需要新建提交的改动——要发布的内容已经在上一个提交里了"
  # 这时唯一能让第 2 步那份信息生效的办法，是改写上一个提交的信息。
  # 注意：那个提交若已经推送过，改写后本地与远程就分叉了，第 11 步的 push 会被拒绝
  # （本脚本不会替你强推）。没推过（比如刚删库重建）则不受影响。
  HEAD_SHORT="$(git rev-parse --short HEAD 2>/dev/null || echo '?')"
  read -r -p "是否用 ${MSG_FILE} 改写当前提交（${HEAD_SHORT}）的信息？[y/N] " ans
  if [[ "$ans" =~ ^[Yy]$ ]]; then
    git commit --amend -F "$MSG_FILE"
    MSG_USED=1
    ok "已改写提交信息"
  else
    info "保留当前提交信息不变"
  fi
fi

# 信息已经进提交了，草稿留着只会在下一次发布时被当成"上次留下的"而误用。
if [ "$MSG_USED" = "1" ]; then
  rm -f "$MSG_FILE"
else
  warn "${MSG_FILE} 没有被用上，已保留在项目根目录（下次运行会沿用它）"
fi

# ---------- 10. 推送前检查远程连通性（登录 / 凭证 / 网络 / 仓库存在性） ----------
info "检查远程仓库连通性…"
if git ls-remote --heads origin >/dev/null 2>&1; then
  ok "远程仓库可访问"
else
  warn "无法访问远程仓库 ${REPO_URL}"
  warn "可能原因：未登录 GitHub、凭证过期/缺失、仓库不存在、网络不通"
  read -r -p "是否仍尝试推送？[y/N] " ans
  if [[ ! "$ans" =~ ^[Yy]$ ]]; then
    err "已取消推送"
    exit 1
  fi
fi

# ---------- 11. 推送分支 + tag ----------
info "推送分支…"
git push -u origin HEAD

info "创建并推送 tag ${TAG}…"
git tag "$TAG"
git push origin "$TAG"

ok "发布完成！已推送 tag ${TAG}"
info "GitHub Actions 将自动构建：Docker 多架构镜像 + 多平台二进制 + GitHub Release"
warn "提示：若尚未配置签名 secret，请到仓库 Settings → Secrets and variables → Actions"
warn "      添加 UPDATE_SIGNING_KEY（值 = 本地 update-signing.key 文件内容），"
warn "      否则 Linux 更新包将不带 .sig 签名。"
