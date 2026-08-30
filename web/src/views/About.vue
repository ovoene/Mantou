<script setup lang="ts">
import { onActivated, reactive, ref, computed, h, defineComponent, onBeforeUnmount } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import PageCard from '@/components/PageCard.vue'
import api from '@/api/client'
import { actions } from '@/api/resources'
import { useAuthStore } from '@/stores/auth'
import { useSystemStore } from '@/stores/system'

const { t } = useI18n()
const auth = useAuthStore()
const system = useSystemStore()

// 自更新倒计时提示组件：挂载后从 5 倒数，归零自动刷新页面。
// 用独立组件承载响应式，确保 ElMessage 内文本能实时更新——不依赖消息槽对渲染函数的 reactivity 处理。
const SelfUpdateCountdown = defineComponent({
  setup() {
    const remaining = ref(5)
    const timer = setInterval(() => {
      // 减到 1 就直接刷新，不再往下渲染：否则浏览器会先把「0 秒」这一帧画出来才跳转。
      if (remaining.value <= 1) {
        clearInterval(timer)
        location.reload()
        return
      }
      remaining.value -= 1
    }, 1000)
    onBeforeUnmount(() => clearInterval(timer))
    return () => h('span', t('about.restartCountdown', { n: remaining.value }))
  },
})

// 项目仓库（owner/name），默认 ovoene/Mantou；可在「设置 → 在线更新」通过 GitHubRepo 覆盖。
// 既恢复此前的 GitHub 自动检测/链接默认行为，又满足「仓库可配置、不写死」。
const repoBase = computed(() => {
  const r = (update.githubRepo || '').trim()
  return r || 'ovoene/Mantou'
})
// 项目主页地址：以配置仓库为准，支持直接填完整 URL。
const repoUrl = computed(() => {
  const r = repoBase.value.trim()
  if (/^https?:\/\//i.test(r)) return r
  return 'https://github.com/' + r
})
// 新版本号点击跳转：优先用后端返回的 releaseUrl（配置项 > GitHub 返回的下载页），
// 否则回退到项目仓库的 Releases 页（恢复此前的默认行为）。
const releaseLink = computed(() => {
  const u = (system.check?.releaseUrl || '').trim()
  if (/^https?:\/\//i.test(u)) return u
  return repoUrl.value + '/releases'
})

// ---- 「程序说明」里的运行说明（折叠块，默认收起） ----
// 镜像地址跟着上面那个仓库配置走，且一律小写：ghcr 的路径不接受大写，
// release.yml 里也是先把 github.repository 转小写再推的，两边保持一致。
const imageRef = computed(() => {
  const raw = repoBase.value.trim()
  const m = raw.match(/github\.com\/([^/]+\/[^/?#]+)/i)
  const slug = (m ? m[1] : raw).replace(/\.git$/i, '').replace(/^\/+|\/+$/g, '')
  return 'ghcr.io/' + slug.toLowerCase()
})

// 当前运行环境，形如 linux/amd64，取自版本信息那一栏同一个来源。
// 取不到就是空串，此时下面一条都不会标「当前」，不会误标成别的平台。
const currentPlat = computed(() => {
  const os = system.versionInfo?.os
  const arch = system.versionInfo?.arch
  return os && arch ? `${os}/${arch}` : ''
})

// 各平台的取包与启动步骤。plat 与 currentPlat 相符的那一条标「当前」。
// Docker 那条不给 plat：容器里跑的仍是 linux 的二进制，标在对应的 Linux 行上更准。
//
// name 一律以架构名开头，且用的就是压缩包文件名里那个词（amd64 / arm64），
// 括号里才是各平台惯用的别称（x86_64 与 aarch64 是 uname -m 的输出，Intel /
// Apple Silicon 是苹果自己的叫法）。写「Linux x64」分不出该下哪个包——
// Linux 两个架构都有包，而 x64 这个词只出现在别称里。
// 括号用半角：这几个名字是固定写法、中英文共用一份，而里面全是拉丁字符，
// 半角在英文界面里也读得通，全角只在中文里合适。
const runGuides = computed(() => [
  {
    id: 'linux-amd64',
    plat: 'linux/amd64',
    name: 'Linux amd64 (x86_64)',
    cmd: 'tar -xzf mantou-linux-amd64.tar.gz\nchmod +x mantou\n./mantou --data ./data',
    note: '',
  },
  {
    id: 'linux-arm64',
    plat: 'linux/arm64',
    name: 'Linux arm64 (aarch64)',
    cmd: 'tar -xzf mantou-linux-arm64.tar.gz\nchmod +x mantou\n./mantou --data ./data',
    note: '',
  },
  {
    id: 'darwin-amd64',
    plat: 'darwin/amd64',
    name: 'macOS amd64 (Intel)',
    cmd: 'tar -xzf mantou-darwin-amd64.tar.gz\nchmod +x mantou\nxattr -d com.apple.quarantine mantou\n./mantou --data ./data',
    note: t('about.runNoteMac'),
  },
  {
    id: 'darwin-arm64',
    plat: 'darwin/arm64',
    name: 'macOS arm64 (Apple Silicon)',
    cmd: 'tar -xzf mantou-darwin-arm64.tar.gz\nchmod +x mantou\nxattr -d com.apple.quarantine mantou\n./mantou --data ./data',
    note: t('about.runNoteMac'),
  },
  {
    id: 'windows-amd64',
    plat: 'windows/amd64',
    name: 'Windows amd64 (x64)',
    cmd: 'mantou.exe --data D:\\mantou\\data',
    note: t('about.runNoteWin'),
  },
  {
    id: 'docker',
    plat: '',
    name: 'Docker',
    cmd:
      `docker pull ${imageRef.value}:latest\n` +
      `docker run -d --name mantou -p 25666:25666 -v $(pwd)/data:/data --restart unless-stopped ${imageRef.value}:latest`,
    note: t('about.runNoteDocker'),
  },
])

// 折叠块的展开项：空数组即默认收起。
const runOpen = ref<string[]>([])

// 复制命令。面板可能跑在 http 上（clipboard API 只在安全上下文可用），
// 所以留一条 textarea + execCommand 的退路，与消息路由页同一处理。
async function copyRunCmd(text: string) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text)
    } else {
      const ta = document.createElement('textarea')
      ta.value = text
      ta.style.position = 'fixed'
      ta.style.opacity = '0'
      document.body.appendChild(ta)
      ta.select()
      const ok = document.execCommand('copy')
      document.body.removeChild(ta)
      if (!ok) throw new Error('copy failed')
    }
    ElMessage.success(t('about.runCopied'))
  } catch {
    ElMessage.warning(t('about.runCopyFail'))
  }
}

// 在线更新配置（manifestUrl / releaseUrl / githubRepo / signKey / allowUnsignedUpdate）。
// 只读不写：这一页用它决定「上传更新包」是否可用、以及仓库链接指向哪里，改动仍在设置页。
const update = reactive({ manifestUrl: '', releaseUrl: '', githubRepo: '', signKey: '', allowUnsignedUpdate: false })
// 设置是否已加载完成：避免 signKey 初始为空串时，警示条在 loadSettings 返回前「先显示后隐藏」地闪一下。
const settingsLoaded = ref(false)
// 上传更新包当前是否可用：没配公钥、又没打开「允许未验签的更新包」时后端不接收（403），
// 前端同步置灰，免得用户传完 30MB 才看到被拒。设置未加载完时不置灰，避免闪一下。
const updateBlocked = computed(() => settingsLoaded.value && !update.signKey && !update.allowUnsignedUpdate)
const selfUpdating = ref(false)
const checking = ref(false)

async function loadSettings() {
  try {
    const s = await api.get<any>('/settings')
    if (s.update) {
      update.manifestUrl = s.update.manifestUrl ?? ''
      update.releaseUrl = s.update.releaseUrl ?? ''
      update.githubRepo = s.update.githubRepo ?? ''
      update.signKey = s.update.signKey ?? ''
      update.allowUnsignedUpdate = !!s.update.allowUnsignedUpdate
    }
  } catch {
    /* ignore */
  } finally {
    settingsLoaded.value = true
  }
}

// 进入页面即读取版本文件（版本号/官网地址/编译时间）并检测最新版本。
// 点击「检查更新」按钮时强制 force=true：跳过所有缓存，立即重新联网检测，
// 这样断网/限流等瞬态不可达状态不会被 30 分钟缓存挡住，点了按钮立刻重试。
async function checkUpdate(force = false) {
  checking.value = true
  try {
    await system.refreshUpdate(force)
  } finally {
    checking.value = false
  }
}

// 上传 tar.gz 更新包并执行自更新（非 Windows 生效）。
async function doSelfUpdate(opt: any) {
  const file = opt.file as File
  const name = (file.name || '').toLowerCase()
  if (!name.endsWith('.tar.gz') && !name.endsWith('.tgz')) {
    ElMessage.warning(t('about.uploadBadFile'))
    return
  }
  try {
    await ElMessageBox.confirm(t('about.uploadConfirm'), '', {
      confirmButtonText: t('common.confirm'),
      cancelButtonText: t('common.cancel'),
      type: 'warning',
    })
  } catch {
    return
  }
  selfUpdating.value = true
  ElMessage.info(t('about.uploading'))
  try {
    const fd = new FormData()
    fd.append('file', file)
    const resp = await actions.selfUpdate(fd)
    // 后端 respondOK 把 {ok,restarting} 包在 data 字段下：{ data: { ok, restarting } }
    // （actions.selfUpdate 走 api.raw，返回的是原始 axios 响应，故 resp.data 才是 HTTP body）。
    // 这里只做前端倒计时自动刷新，不触碰后端重启逻辑。
    const payload = (resp.data && typeof resp.data === 'object' && 'data' in resp.data) ? resp.data.data : resp.data
    if (payload?.restarting) {
      // 渲染独立倒计时组件：其内部 ref(5) 每秒递减，文本实时刷新；归零后自动刷新页面。
      ElMessage({
        message: h(SelfUpdateCountdown),
        type: 'success',
        duration: 0,
        showClose: false,
      })
    } else {
      ElMessage.success(t('about.uploadOk'))
    }
  } catch (e: any) {
    ElMessage.error(e?.response?.data?.error || e?.message || t('common.failed'))
  } finally {
    selfUpdating.value = false
  }
}

// 页面被激活（keep-alive 下首次挂载同样会触发一次，因此这里是唯一入口）。
//
// 三件事彼此不依赖，并发发出。原先是几个 await 首尾相接，其中 checkUpdate() 还要经后端
// 出网访问 GitHub——网络慢的时候，后面的版本信息全被它挡在身后，
// 这个页面因此是所有模块里首屏最慢的一个。
onActivated(() => {
  loadSettings()
  system.loadVersion()
  checkUpdate()
})
</script>

<template>
  <PageCard :title="t('about.title')" :subtitle="t('about.subtitle')">
    <!-- 标题旁项目图标：默认指向 GitHub 仓库（ovoene/Mantou，可由设置 GitHubRepo 覆盖），于新标签页打开。 -->
    <template #title-extra>
      <a
        v-if="repoUrl"
        :href="repoUrl"
        target="_blank"
        rel="noopener"
        class="gh-link"
        :title="repoUrl"
      >
        <svg viewBox="0 0 16 16" width="21" height="21" aria-hidden="true">
          <path
            fill="currentColor"
            d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8Z"
          />
        </svg>
      </a>
    </template>

    <!-- 第一排：上传更新包 -->
    <section class="about-row mt-glass">
      <div class="about-row-head">
        <span class="about-row-title">{{ t('about.uploadTitle') }}</span>
      </div>
      <p class="mt-subtle hint-block">{{ t('about.uploadDesc') }}</p>
      <el-alert
        v-if="updateBlocked"
        :title="t('about.signKeyMissing')"
        type="warning"
        :closable="false"
        show-icon
        style="margin: 8px 0"
      />
      <el-upload
        :show-file-list="false"
        :http-request="doSelfUpdate"
        accept=".tar.gz,.tgz,application/gzip"
        :disabled="selfUpdating || updateBlocked"
      >
        <el-button type="warning" :loading="selfUpdating" :disabled="updateBlocked">
          {{ t('about.uploadBtn') }}
        </el-button>
      </el-upload>
    </section>

    <!-- 版本信息：当前版本 / 当前架构 / 编译时间 一行三列（标签在上值在下），
         最新版本 独占一行在下方，在线更新检测尚未启用 置于最新版本下方；检查更新按钮淡蓝色填充。 -->
    <section class="about-row mt-glass">
      <div class="about-row-head">
        <span class="about-row-title">{{ t('about.versionInfo') }}</span>
      </div>
      <div class="ver-block">
        <div class="ver-row">
          <div class="ver-line">
            <span class="ver-label">{{ t('about.currentVersion') }}</span>
            <span class="ver-value">{{ system.versionInfo?.version || t('about.unknown') }}</span>
          </div>
          <div class="ver-line">
            <span class="ver-label">{{ t('about.currentArch') }}</span>
            <span class="ver-value">
              <template v-if="system.versionInfo?.os && system.versionInfo?.arch">
                {{ system.versionInfo.os }}/{{ system.versionInfo.arch }}
              </template>
              <span v-else class="mt-subtle">—</span>
            </span>
          </div>
          <div class="ver-line">
            <span class="ver-label">{{ t('about.compileTime') }}</span>
            <span class="ver-value">{{ system.versionInfo?.buildTime || t('about.unknown') }}</span>
          </div>
        </div>
        <div class="ver-line ver-line-wide">
          <span class="ver-label">{{ t('about.latestVersion') }}</span>
          <span class="ver-value">
            <template v-if="checking">
              <span class="mt-subtle">{{ t('about.checking') }}</span>
            </template>
            <template v-else-if="system.check">
              <!-- 远端有更新：红色加粗 + 动态徽标；已配置下载页则渲染外链，否则仅展示版本号。
                   徽标独立成小红方块，白色上箭头，外圈双层错位脉冲 + 整体弹性上下跳动 + 呼吸阴影。 -->
              <a v-if="system.check.hasUpdate && system.check.latestVersion && releaseLink"
                 :href="releaseLink" target="_blank" rel="noopener"
                 class="ver-latest is-new">
                Ver {{ system.check.latestVersion }}<span class="up-badge" aria-hidden="true">
                  <span class="up-badge-ring up-badge-ring-1"></span>
                  <span class="up-badge-ring up-badge-ring-2"></span>
                  <span class="up-badge-icon">
                    <svg viewBox="0 0 16 16" width="14" height="14" fill="none" xmlns="http://www.w3.org/2000/svg">
                      <path d="M8 13V3" stroke="currentColor" stroke-width="2.6" stroke-linecap="round"/>
                      <path d="M4 7.5L8 3L12 7.5" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                  </span>
                </span>
              </a>
              <span v-else-if="system.check.hasUpdate && system.check.latestVersion"
                    class="ver-latest is-new">
                Ver {{ system.check.latestVersion }}<span class="up-badge" aria-hidden="true">
                  <span class="up-badge-ring up-badge-ring-1"></span>
                  <span class="up-badge-ring up-badge-ring-2"></span>
                  <span class="up-badge-icon">
                    <svg viewBox="0 0 16 16" width="14" height="14" fill="none" xmlns="http://www.w3.org/2000/svg">
                      <path d="M8 13V3" stroke="currentColor" stroke-width="2.6" stroke-linecap="round"/>
                      <path d="M4 7.5L8 3L12 7.5" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                  </span>
                </span>
              </span>
              <!-- GitHub 接口限流（请求过于频繁）：与真断网区分，提示稍后再试 -->
              <span v-else-if="system.check.rateLimited" class="ver-latest is-offline">
                {{ t('about.rateLimited') }}
                <template v-if="system.check.retryAfterSec && system.check.retryAfterSec > 0">
                  （约 {{ Math.ceil(system.check.retryAfterSec / 60) }} 分钟）
                </template>
              </span>
              <!-- 网络不可达 / 网络异常：暗黄色加粗「当前网络不可用」，适配深浅主题 -->
              <span v-else-if="system.check.networkError" class="ver-latest is-offline">
                {{ t('about.networkUnavailable') }}
              </span>
              <!-- 无更新 / 检测不到任何版本：绿色加粗显示当前版本即最新 -->
              <span v-else class="ver-latest is-current">
                {{ system.versionInfo?.version || t('about.unknown') }}
              </span>
            </template>
            <span v-else class="mt-subtle">—</span>
          </span>
        </div>
      </div>
      <div class="ver-actions">
        <el-button class="check-btn" :loading="checking" @click="checkUpdate(true)">
          {{ t('overview.checkUpdate') }}
        </el-button>
      </div>
    </section>

    <!-- 第三排：程序说明。文案就在语言包里，不依赖运行目录下的任何文件（见 about.programDesc 上方注释） -->
    <section class="about-row mt-glass">
      <div class="about-row-head">
        <span class="about-row-title">{{ t('about.description') }}</span>
      </div>
      <p class="about-desc">{{ t('about.programDesc') }}</p>

      <!-- 怎么运行：默认收起，展开后按平台列出取包与启动命令，命令可一键复制。
           与当前运行环境（上面版本信息那一栏的 os/arch）相符的那一条标「当前」。 -->
      <el-collapse v-model="runOpen" class="run-collapse">
        <el-collapse-item name="run">
          <template #title>
            <span class="run-title">{{ t('about.runTitle') }}</span>
          </template>
          <p class="run-hint mt-subtle">{{ t('about.runHint') }}</p>
          <div
            v-for="g in runGuides"
            :key="g.id"
            class="run-item"
            :class="{ 'is-current': g.plat && g.plat === currentPlat }"
          >
            <div class="run-item-head">
              <span class="run-item-name">{{ g.name }}</span>
              <span v-if="g.plat && g.plat === currentPlat" class="run-badge">
                {{ t('about.runCurrent') }}
              </span>
              <el-button link class="run-copy" @click="copyRunCmd(g.cmd)">
                {{ t('about.runCopy') }}
              </el-button>
            </div>
            <pre class="run-cmd">{{ g.cmd }}</pre>
            <p v-if="g.note" class="run-note mt-subtle">{{ g.note }}</p>
          </div>
        </el-collapse-item>
      </el-collapse>
    </section>
  </PageCard>
</template>

<style scoped>
.about-row {
  padding: 16px 18px;
  margin-bottom: 16px;
  border-radius: var(--mt-card-radius, 14px);
}
.about-row-head {
  margin-bottom: 6px;
}
.about-row-title {
  font-size: 15px;
  font-weight: 640;
  color: var(--mt-text);
}
.about-desc {
  font-size: 14px;
  line-height: 1.7;
  color: var(--mt-text);
  white-space: pre-wrap;
  margin: 0;
}
/* 「怎么运行」折叠块：只用现成的主题变量，不引入新配色 */
.run-collapse {
  margin-top: 12px;
  border-top: none;
}
.run-title {
  font-size: 14px;
  font-weight: 600;
  color: var(--mt-text);
}
.run-hint {
  font-size: 13px;
  line-height: 1.6;
  margin: 0 0 10px;
}
.run-item {
  padding: 8px 10px;
  margin-bottom: 8px;
  border: 1px solid var(--mt-card-border);
  border-radius: var(--mt-radius-sm, 8px);
}
.run-item:last-child {
  margin-bottom: 0;
}
/* 当前运行环境那一条：只加主色描边，不改背景，免得在深浅两套主题里各调一遍 */
.run-item.is-current {
  border-color: var(--mt-primary);
}
.run-item-head {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 6px;
}
.run-item-name {
  font-size: 13px;
  font-weight: 640;
  color: var(--mt-text);
}
.run-badge {
  flex: none;
  padding: 1px 7px;
  border-radius: 6px;
  font-size: 11px;
  line-height: 1.5;
  color: #fff;
  background: var(--mt-primary);
}
.run-copy {
  margin-left: auto;
  font-size: 12px;
}
.run-cmd {
  margin: 0;
  padding: 8px 10px;
  border-radius: var(--mt-radius-sm, 8px);
  /* 中性灰底：同一个值在深浅主题下都能和卡片背景分开 */
  background: rgba(127, 127, 127, 0.12);
  color: var(--mt-text);
  font-family: ui-monospace, Menlo, Consolas, monospace;
  font-size: 12px;
  line-height: 1.75;
  white-space: pre-wrap;
  /* 窄栏里要换行，但优先断在空格处：用 break-all 会把 mantou:latest 断成两半，
     命令是要读、要复制的，断在词中间反而看不清。单个词真的超出一行时仍会断开。 */
  overflow-wrap: break-word;
}
.run-note {
  font-size: 12px;
  line-height: 1.6;
  margin: 6px 0 0;
}
/* el-collapse 的头部与内容容器由组件内部类控制，scoped 选择器到不了，必须 :deep */
.run-collapse :deep(.el-collapse-item__header),
.run-collapse :deep(.el-collapse-item__wrap) {
  background: transparent;
  border-bottom: none;
}
.run-collapse :deep(.el-collapse-item__content) {
  padding-bottom: 4px;
}
/* 最新版本状态：无更新/检测不到 → 绿色加粗（当前版本即最新）；有更新 → 红色加粗 + 动态上箭头 */
.ver-latest {
  font-size: 15px;
  font-weight: 700;
  line-height: 1.4;
}
.ver-latest.is-current {
  color: var(--el-color-success);
}
.ver-latest.is-new {
  color: var(--el-color-danger);
}
/* 有更新时整行可点击跳转最新版本 release 页：保留红字、去除默认链接样式、悬停提示 */
a.ver-latest.is-new {
  text-decoration: none;
  cursor: pointer;
  outline: none;
}
a.ver-latest.is-new:hover {
  text-decoration: underline;
  opacity: 0.85;
}
/* 网络不可达：暗黄/暗金加粗，深浅主题均清晰可见 */
.ver-latest.is-offline {
  color: #b8860b; /* 暗金，浅色背景下对比充足 */
  font-weight: 700;
}
:global(:root[data-theme='dark']) .ver-latest.is-offline {
  color: #e0a800; /* 深色背景提亮，保证可读 */
}
/* 新版本指示徽标：独立的红色圆角小方块，白色上箭头；外圈双层错位脉冲环 + 整体弹性上下跳动。
   设计要点：脱离纯文本风格，让「有更新」一眼可见；双层错位（0/0.9s）保证任何时刻都有一圈在扩散。 */
.up-badge {
  position: relative;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  margin-left: 6px;
  width: 24px;
  height: 24px;
  border-radius: 8px;
  background: linear-gradient(135deg, var(--el-color-danger) 0%, var(--el-color-danger-dark-2, #c45656) 100%);
  color: #fff;
  vertical-align: -3px;
  box-shadow:
    0 2px 8px rgba(245, 108, 108, 0.4),
    inset 0 -1px 0 rgba(0, 0, 0, 0.08);
  /* !important 覆盖 style.css 全局 (@media prefers-reduced-motion) 的 `* { animation: none !important }`，
     保证用户明确要的「有更新」指示器在任何环境下都动。 */
  animation: ver-up-bounce 1.4s cubic-bezier(0.34, 1.56, 0.64, 1) infinite !important;
  flex-shrink: 0;
}
.up-badge-icon {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  position: relative;
  z-index: 1;
}
.up-badge-icon svg {
  display: block;
}
/* 脉冲环：与徽标同尺寸绝对定位，扩散 + 淡出；两环错位 0.9s 形成连续涟漪 */
.up-badge-ring {
  position: absolute;
  inset: 0;
  border-radius: 8px;
  background: linear-gradient(135deg, var(--el-color-danger) 0%, var(--el-color-danger-dark-2, #c45656) 100%);
  opacity: 0.55;
  pointer-events: none;
  /* !important 同上：盖过全局减少动效守卫，强制脉冲环扩散 */
  animation: ver-up-pulse 1.8s ease-out infinite !important;
}
.up-badge-ring-2 {
  animation-delay: 0.9s;
}
@keyframes ver-up-bounce {
  0%,
  100% {
    transform: translateY(0) scale(1);
  }
  50% {
    transform: translateY(-4px) scale(1.06);
  }
}
@keyframes ver-up-pulse {
  0% {
    transform: scale(1);
    opacity: 0.55;
  }
  100% {
    transform: scale(1.7);
    opacity: 0;
  }
}
.hint-block {
  font-size: 12px;
  margin: 6px 0 12px;
}
/* 版本信息区：前三字段一行三列（标签在上值在下），最新版本独占一行 */
.ver-block {
  display: flex;
  flex-direction: column;
  gap: 14px;
  margin-bottom: 16px;
}
.ver-row {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 14px 28px;
}
.ver-line {
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.ver-label {
  font-size: 12px;
  color: var(--mt-text-soft);
}
.ver-value {
  font-size: 15px;
  font-weight: 600;
  color: var(--mt-text);
  line-height: 1.4;
}
/* 最新版本下方提示（如「在线更新检测尚未启用」），使用次级柔和色 */
.ver-note {
  margin: -6px 0 0;
  font-size: 12.5px;
  color: var(--mt-text-soft);
}
.ver-actions {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
}
/* 检查更新按钮：淡蓝色填充，文字使用品牌蓝保证可读（亮/暗模式自动切换） */
.check-btn {
  background-color: var(--el-color-primary-light-9);
  color: var(--el-color-primary);
  border-color: var(--el-color-primary-light-7);
}
.check-btn:hover {
  background-color: var(--el-color-primary-light-8);
  color: var(--el-color-primary);
}
.check-btn.is-loading,
.check-btn:focus {
  background-color: var(--el-color-primary-light-9);
  color: var(--el-color-primary);
}
@media (max-width: 560px) {
  .ver-row {
    grid-template-columns: 1fr;
  }
}
/* 标题旁的 GitHub 图标 */
.gh-link {
  display: inline-flex;
  align-items: center;
  margin-left: 8px;
  color: var(--mt-text);
  opacity: 0.7;
  transition: opacity 0.15s ease, color 0.15s ease;
}
.gh-link:hover {
  opacity: 1;
  color: var(--mt-primary);
}
</style>
