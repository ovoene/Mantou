<script setup lang="ts">
import { ref, computed, reactive, onMounted, onBeforeUnmount, watch } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import {
  Odometer,
  Connection,
  Monitor,
  Switch,
  AlarmClock,
  Timer,
  ChatDotRound,
  Lock,
  Key,
  Umbrella,
  Setting,
  InfoFilled,
  SwitchButton,
  Fold,
  Expand,
  User,
  ArrowDown,
} from '@element-plus/icons-vue'
import { useAuthStore } from '@/stores/auth'
import { prefetchView } from '@/router'
import AppBackdrop from '@/components/AppBackdrop.vue'
import LangSwitch from '@/components/LangSwitch.vue'
import TopClock from '@/components/TopClock.vue'

const { t } = useI18n()
const router = useRouter()
const route = useRoute()
const auth = useAuthStore()

const collapsed = ref(false)

const menu = [
  { name: 'overview', label: 'nav.overview', icon: Odometer },
  { name: 'ddns', label: 'nav.ddns', icon: Connection },
  { name: 'webservice', label: 'nav.webservice', icon: Monitor },
  { name: 'mroute', label: 'nav.mroute', icon: ChatDotRound },
  { name: 'forward', label: 'nav.forward', icon: Switch },
  { name: 'wol', label: 'nav.wol', icon: AlarmClock },
  { name: 'cron', label: 'nav.cron', icon: Timer },
  // 证书用挂锁（浏览器地址栏那一个，HTTPS 的通用符号），服务防护用伞。
  // 两者一度都是 Lock，菜单上就成了两个一模一样的图标；而"锁"表达的是加密而非拦截，
  // 所以让证书留着挂锁、换掉服务防护这一个。全表 12 个图标彼此不重复，也不与外壳上的
  // 折叠 / 用户 / 退出等图标撞。
  { name: 'cert', label: 'nav.cert', icon: Lock },
  { name: 'cred', label: 'nav.cred', icon: Key },
  { name: 'globalfirewall', label: 'nav.gfw', icon: Umbrella },
  { name: 'settings', label: 'nav.settings', icon: Setting },
  { name: 'about', label: 'nav.about', icon: InfoFilled },
]

const active = computed(() => (route.name as string) || 'overview')

// 预取各模块页面的代码块。
//
// 每个页面都是一份独立的 chunk（见 router/index.ts 的懒加载），第一次点某个模块时
// 浏览器要先把那一份下载下来、解析、执行，才轮到渲染——这段时间里点击是没有回应的，
// 表现就是"鼠标移过去点了，画面还停在上一页"。而这几份代码在首屏之后其实闲着都能取。
//
// 两个时机：鼠标移到菜单项上就取（真正要点它之前那 100~300 毫秒足够取回来），
// 以及首屏空闲时一条条把剩下的取完。刻意不并发全取：那会跟各页面的数据请求抢带宽，
// 首屏反而更慢。取回来的 chunk 由浏览器与 Vite 各自缓存，重复调用不会重复下载。
function idle(fn: () => void) {
  const ric = (window as any).requestIdleCallback as
    | ((cb: () => void, opts?: { timeout: number }) => void)
    | undefined
  if (typeof ric === 'function') ric(fn, { timeout: 2000 })
  else window.setTimeout(fn, 300)
}

function prefetchAll() {
  let i = 0
  const step = () => {
    if (i >= menu.length) return
    void prefetchView(menu[i++].name).then(() => idle(step))
  }
  idle(step)
}

// 顶栏实时时钟拆到 TopClock.vue：它每秒变一次，留在这里会让整个外壳每秒重渲染一遍。
onMounted(prefetchAll)

function go(name: string) {
  router.push({ name })
}
async function doLogout() {
  await auth.logout()
  router.replace({ name: 'login' })
}

// 顶栏管理员下拉菜单动作。
function onAdminCommand(cmd: string) {
  if (cmd === 'account') openAccount()
  else if (cmd === 'logout') doLogout()
}

// ---------- 侧栏只剩图标时的名称提示 ----------
//
// 侧栏收起后菜单项只有一个图标，光看图标认不出是哪个模块，所以补一条悬浮提示，
// 内容就是那一项的名称。收起有两条来路，都要算进去：一是顶栏那个折叠按钮（collapsed），
// 二是窄屏下由样式强制收起（见样式里 900px 那一档——这个数与那边是同一个断点，改要一起改）。
const narrow = ref(false)
let mq: MediaQueryList | null = null
const onNarrowChange = (e: MediaQueryListEvent) => {
  narrow.value = e.matches
}
onMounted(() => {
  mq = window.matchMedia('(max-width: 900px)')
  narrow.value = mq.matches
  mq.addEventListener('change', onNarrowChange)
})
onBeforeUnmount(() => mq?.removeEventListener('change', onNarrowChange))

const iconsOnly = computed(() => collapsed.value || narrow.value)

// 当前显示提示的那一项（菜单名，退出用 logoutKey）。空串表示都不显示。
//
// el-tooltip 传了 :visible 就是受控模式，它自带的 hover 触发全部失效（见 tooltip 的
// stopWhenControlledOrDisabled），显示时机整个由这里决定——正是要这样：
// 触屏上"悬停"是不存在的，得换成长按，两种设备的时机不是同一套。
const tipFor = ref('')
const logoutKey = '__logout'
// 侧栏重新展开（或屏幕变宽）时把它清干净。留着上一次那个名字不是"反正看不见"：
// el-tooltip 在 disabled 转回 false 的那一刻会照着 visible 把提示重新弹出来
// （见它内部对 disabled 的 watch），于是下一次收起时会凭空冒出一个，鼠标根本不在上面。
watch(iconsOnly, (on) => {
  if (!on) tipFor.value = ''
})

let pressTimer = 0
let hideTimer = 0
let tapTimer = 0
// 长按是否已经触发（提示已弹出）。每次 touchstart 归零，只在 touchend 那一刻读一次。
let longPressed = false
// 长按之后浏览器还会补一次点击，那一次不算操作——否则手指一抬就跳走了，
// 名字随页面一起消失，等于长按什么也没看到。
//
// 这个标记只在 touchend 里立起来（点击只可能跟在 touchend 后面），并由定时器按时撤掉。
// 刻意不由长按本身立起来：万一某次手势没有 touchend（被别的东西接走），
// 标记就会一直留着，把之后一次正常点击白吞掉。
let swallowTap = false
// 最近一次触摸的时刻。触屏点一下，浏览器也会合成一次 mouseenter，
// 不挡掉的话名称会闪一下再被跳转带走。
let touchedAt = 0

function showTip(name: string) {
  if (!iconsOnly.value || Date.now() - touchedAt < 800) return
  tipFor.value = name
}
function hideTip(name: string) {
  if (tipFor.value === name) tipFor.value = ''
}
function tipTouchStart(name: string) {
  touchedAt = Date.now()
  longPressed = false
  window.clearTimeout(pressTimer)
  pressTimer = window.setTimeout(() => {
    longPressed = true
    tipFor.value = name
  }, 420)
}
// 手指划动多半是在滚侧栏，不该算长按。已经显示出来的就让它按时自己收。
function tipTouchMove() {
  window.clearTimeout(pressTimer)
}
function tipTouchEnd(name: string) {
  touchedAt = Date.now()
  window.clearTimeout(pressTimer)
  if (!longPressed) return
  longPressed = false
  swallowTap = true
  window.clearTimeout(hideTimer)
  hideTimer = window.setTimeout(() => hideTip(name), 1600)
  // 补发的那一次点击在 touchend 之后约 300 毫秒才到，留够；到点就撤，
  // 不让它影响再往后的点击。
  window.clearTimeout(tapTimer)
  tapTimer = window.setTimeout(() => {
    swallowTap = false
  }, 700)
}
// 返回 true 表示这一次点击是长按带出来的，调用方应当什么都不做。
function fromLongPress() {
  if (!swallowTap) return false
  swallowTap = false
  return true
}
function onMenuClick(name: string) {
  if (fromLongPress()) return
  go(name)
}
function onLogoutClick() {
  if (fromLongPress()) return
  void doLogout()
}
// 指针移到菜单项上（或它拿到焦点）：预取那一页的代码块，顺带把名称提示带出来。
function onMenuEnter(name: string) {
  prefetchView(name)
  showTip(name)
}

// ---------- 修改账户和密码 ----------
const accountVisible = ref(false)
const accountSaving = ref(false)
const accountForm = reactive({
  username: '',
  oldPassword: '',
  newPassword: '',
  confirm: '',
})

function openAccount() {
  accountForm.username = auth.username
  accountForm.oldPassword = ''
  accountForm.newPassword = ''
  accountForm.confirm = ''
  accountVisible.value = true
}

// 切页时收起这个弹窗，与各模块页面里的弹窗一致（理由见 composables/useCloseOnLeave）。
// 这里不能用那个函数：布局本身不在 keep-alive 里，切模块时它一直挂着，onDeactivated 不会触发。
watch(
  () => route.name,
  () => {
    accountVisible.value = false
    // 跳页时把提示收掉：触屏上点一下也会合成 mouseenter，不收就留在新页面上不走了。
    tipFor.value = ''
  },
)

async function submitAccount() {
  if (!accountForm.oldPassword) {
    ElMessage.warning(t('account.needOldPassword'))
    return
  }
  const changeName = accountForm.username.trim() !== '' && accountForm.username.trim() !== auth.username
  const changePass = accountForm.newPassword !== ''
  if (!changeName && !changePass) {
    ElMessage.warning(t('account.nothingToChange'))
    return
  }
  if (changePass && accountForm.newPassword !== accountForm.confirm) {
    ElMessage.warning(t('account.passwordMismatch'))
    return
  }
  accountSaving.value = true
  try {
    const r = await auth.changeAccount({
      username: changeName ? accountForm.username.trim() : undefined,
      oldPassword: accountForm.oldPassword,
      newPassword: changePass ? accountForm.newPassword : undefined,
    })
    accountVisible.value = false
    if (r.usernameChanged) {
      // 用户名变更导致会话失效，提示并跳转登录。
      ElMessage.success(t('account.usernameChangedRelogin'))
      await auth.logout()
      router.replace({ name: 'login' })
    } else {
      ElMessage.success(t('common.saved'))
    }
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.saveFailed'))
  } finally {
    accountSaving.value = false
  }
}
</script>

<template>
  <AppBackdrop />
  <div class="layout" :class="{ collapsed }">
    <aside class="sidebar mt-glass">
      <div class="brand">
        <div class="logo">M</div>
        <span v-show="!collapsed" class="brand-name">{{ t('app.name') }}</span>
      </div>
      <nav class="menu">
        <!-- 只剩图标时才启用提示（:disabled）；展开着的侧栏本来就写着名称，再浮一个是重复。 -->
        <el-tooltip
          v-for="m in menu"
          :key="m.name"
          :content="t(m.label)"
          placement="right"
          :offset="12"
          :disabled="!iconsOnly"
          :visible="tipFor === m.name"
        >
          <button
            class="menu-item"
            :class="{ on: active === m.name }"
            @mouseenter="onMenuEnter(m.name)"
            @mouseleave="hideTip(m.name)"
            @focus="onMenuEnter(m.name)"
            @blur="hideTip(m.name)"
            @touchstart.passive="tipTouchStart(m.name)"
            @touchmove.passive="tipTouchMove()"
            @touchend.passive="tipTouchEnd(m.name)"
            @touchcancel.passive="tipTouchEnd(m.name)"
            @click="onMenuClick(m.name)"
          >
            <el-icon class="mi"><component :is="m.icon" /></el-icon>
            <span v-show="!collapsed">{{ t(m.label) }}</span>
          </button>
        </el-tooltip>
      </nav>
      <div class="side-foot">
        <el-tooltip
          :content="t('nav.logout')"
          placement="right"
          :offset="12"
          :disabled="!iconsOnly"
          :visible="tipFor === logoutKey"
        >
          <button
            class="menu-item logout"
            @mouseenter="showTip(logoutKey)"
            @mouseleave="hideTip(logoutKey)"
            @focus="showTip(logoutKey)"
            @blur="hideTip(logoutKey)"
            @touchstart.passive="tipTouchStart(logoutKey)"
            @touchmove.passive="tipTouchMove()"
            @touchend.passive="tipTouchEnd(logoutKey)"
            @touchcancel.passive="tipTouchEnd(logoutKey)"
            @click="onLogoutClick"
          >
            <el-icon class="mi"><SwitchButton /></el-icon>
            <span v-show="!collapsed">{{ t('nav.logout') }}</span>
          </button>
        </el-tooltip>
      </div>
    </aside>

    <main class="main">
      <header class="topbar mt-glass">
        <div class="topbar-left">
          <button class="collapse-btn" @click="collapsed = !collapsed">
            <el-icon><component :is="collapsed ? Expand : Fold" /></el-icon>
          </button>
        </div>

        <!-- 实时时钟：与语言切换、管理员菜单同处顶栏，水平居中。 -->
        <div class="topbar-center">
          <div class="top-clock">
            <TopClock />
          </div>
        </div>

        <div class="topbar-right">
          <LangSwitch />

          <!-- 管理员：点击弹出下拉菜单（当前账户 / 修改账户和密码 / 退出）。
               顶栏这一格只留那个带底色的首字母。用户名是能改的、长度没有上限，
               摆在这一行里就得为最长的名字留出位置，而这一行中间还要放居中的时间，
               右侧宽一像素、时间就少一像素的居中余地。名字挪到下拉里第一行显示——
               那里是纵向排布，名字多长都放得下。 -->
          <!-- placement 用 bottom-end：默认的 bottom 是以头像为中心展开，菜单比头像宽得多，
               右半边会越过顶栏卡片、被浏览器挤到贴着屏幕右沿。改成右对齐后跟着头像走。 -->
          <el-dropdown trigger="click" placement="bottom-end" @command="onAdminCommand">
            <div class="user">
              <el-avatar :size="30" class="ava">{{
                (auth.username || 'M').charAt(0).toUpperCase()
              }}</el-avatar>
              <el-icon class="caret"><ArrowDown /></el-icon>
            </div>
            <template #dropdown>
              <el-dropdown-menu>
                <!-- 一个普通 li，不是 el-dropdown-item：菜单项会参与键盘上下选中
                     与 command 派发，而这一行只是显示当前登录的是谁，点它不该有反应。 -->
                <li class="dd-user">{{ auth.username }}</li>
                <el-dropdown-item command="account" :icon="User" divided>{{
                  t('account.title')
                }}</el-dropdown-item>
                <el-dropdown-item command="logout" :icon="SwitchButton" divided>{{
                  t('nav.logout')
                }}</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </header>
      <!-- keep-alive 缓存各模块页面：切回来时 DOM 与数据直接复用（先立刻出画面，
           再由页面自身的 onActivated 静默刷新），而不是从零挂载一遍表格与表单。
           各页面的定时器 / 全局监听已相应迁到 onActivated / onDeactivated，
           否则被缓存的页面在后台仍会继续轮询。

           这里刻意**不套 <transition>**。切页动画在本布局下必然带两个可见副作用：
           一是内容区有整整一帧是空的——Vue 的 onLeave 会同步给旧页加上 leave-active
           （我们的实现即 display:none，用于避免新旧两页同帧留在流内叠成双倍高度），
           而新页在同一帧仍处于 enter-from 的 opacity:0，于是旧页已消失、新页未显形，看着就是「闪一下」；
           二是 translateY 会让整块文字在动画期间落到小数像素上被重采样而发虚，
           动画结束撤掉 transform 时又 snap 回整数像素的清晰渲染，看着就是「抖一下」。
           去掉包裹后新页在同一次 patch 里直接绘制，点了就在。 -->
      <div class="content">
        <router-view v-slot="{ Component }">
          <keep-alive>
            <component :is="Component" />
          </keep-alive>
        </router-view>
      </div>
    </main>
  </div>

  <!-- 修改账户和密码：可同时/分别改用户名与密码，均需验证当前密码。 -->
  <el-dialog
    v-model="accountVisible"
    :title="t('account.title')"
    width="min(440px, 94vw)"
    append-to-body
    :close-on-click-modal="false"
  >
    <el-form label-position="top">
      <el-form-item :label="t('account.username')">
        <el-input v-model="accountForm.username" autocomplete="off" />
      </el-form-item>
      <el-form-item :label="t('account.oldPassword')">
        <el-input
          v-model="accountForm.oldPassword"
          type="password"
          show-password
          autocomplete="off"
        />
      </el-form-item>
      <el-form-item :label="t('account.newPassword')">
        <el-input
          v-model="accountForm.newPassword"
          type="password"
          show-password
          autocomplete="off"
          :placeholder="t('account.newPasswordHint')"
        />
      </el-form-item>
      <el-form-item :label="t('account.confirmNew')">
        <el-input
          v-model="accountForm.confirm"
          type="password"
          show-password
          autocomplete="off"
        />
      </el-form-item>
    </el-form>
    <template #footer>
      <el-button @click="accountVisible = false">{{ t('common.cancel') }}</el-button>
      <el-button type="primary" :loading="accountSaving" @click="submitAccount">{{
        t('common.save')
      }}</el-button>
    </template>
  </el-dialog>
</template>

<style scoped>
.layout {
  display: flex;
  min-height: 100vh;
  padding: 14px;
  gap: 14px;
}
.sidebar {
  width: var(--mt-sidebar-w);
  flex-shrink: 0;
  padding: 16px 12px;
  display: flex;
  flex-direction: column;
  position: sticky;
  top: 14px;
  height: calc(100vh - 28px);
  transition: width 0.22s ease;
}
.collapsed .sidebar {
  width: 74px;
}
.brand {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 6px 8px 18px;
}
.logo {
  width: 40px;
  height: 40px;
  border-radius: 12px;
  display: grid;
  place-items: center;
  font-size: 21px;
  font-weight: 700;
  color: #fff;
  flex-shrink: 0;
  background: linear-gradient(135deg, var(--mt-primary), var(--mt-accent));
  box-shadow: 0 5px 15px rgba(79, 107, 237, 0.38);
}
.brand-name {
  font-size: 19px;
  font-weight: 700;
  letter-spacing: 0.4px;
}
.menu {
  display: flex;
  flex-direction: column;
  gap: 4px;
  flex: 1;
}
.menu-item {
  display: flex;
  align-items: center;
  gap: 12px;
  width: 100%;
  padding: 11px 13px;
  border: none;
  background: transparent;
  color: var(--mt-text-soft);
  font-size: calc(14px * var(--mt-font-scale));
  font-family: inherit;
  border-radius: 11px;
  cursor: pointer;
  text-align: left;
  transition: background 0.16s, color 0.16s;
  /* 只剩图标时用长按看名称（见脚本里的 tipTouchStart），别让浏览器在同一个动作上
     再叠一层自己的文本选择与长按菜单。manipulation 只关掉双击缩放，滚动照常。 */
  user-select: none;
  -webkit-touch-callout: none;
  touch-action: manipulation;
}
.menu-item:hover {
  background: rgba(127, 140, 170, 0.12);
  color: var(--mt-text);
}
.menu-item.on {
  background: linear-gradient(
    135deg,
    color-mix(in srgb, var(--mt-primary) 88%, transparent),
    color-mix(in srgb, var(--mt-accent) 78%, transparent)
  );
  color: #fff;
  box-shadow: 0 6px 16px rgba(79, 107, 237, 0.32);
}
.mi {
  font-size: 18px;
  flex-shrink: 0;
}
.logout:hover {
  color: var(--mt-danger);
}
.main {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.topbar {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 10px 16px;
  position: sticky;
  top: 14px;
  z-index: 5;
}
.topbar-left {
  flex: 1;
  display: flex;
  align-items: center;
}
.topbar-center {
  flex: 0 0 auto;
  display: flex;
  justify-content: center;
}
.topbar-right {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 14px;
}
.collapse-btn {
  border: none;
  background: transparent;
  cursor: pointer;
  font-size: 19px;
  color: var(--mt-text-soft);
  display: grid;
  place-items: center;
  padding: 4px;
}
.top-clock {
  flex-shrink: 0;
  padding: 6px 14px;
  border-radius: var(--mt-card-radius, 14px);
  background: color-mix(in srgb, var(--mt-primary) 10%, transparent);
  font-variant-numeric: tabular-nums;
}
.top-clock-time {
  font-size: 15px;
  font-weight: 660;
  letter-spacing: 0.4px;
  color: var(--mt-primary);
  font-family: 'SFMono-Regular', ui-monospace, Menlo, Consolas, monospace;
  white-space: nowrap;
}
.user {
  display: flex;
  align-items: center;
  gap: 9px;
  cursor: pointer;
  padding: 3px 6px;
  border-radius: 10px;
  transition: background 0.16s;
  outline: none;
}
.user:hover {
  background: rgba(127, 140, 170, 0.12);
}
.ava {
  background: linear-gradient(135deg, var(--mt-primary), var(--mt-accent));
  color: #fff;
  font-weight: 600;
}
/* 下拉里第一行：当前登录的是谁。
 * 用 max-width + 折行而不是省略号——挪到这里就是为了把名字完整显示出来，
 * 而这一列是纵向的，长名字多占一行就是了。 */
.dd-user {
  list-style: none;
  padding: 7px 16px 8px;
  max-width: 220px;
  font-size: 13px;
  font-weight: 600;
  line-height: 1.35;
  color: var(--mt-text-soft);
  word-break: break-all;
}
.caret {
  font-size: 12px;
  color: var(--mt-text-soft);
}
.content {
  flex: 1;
}
/* 切页不做动画（.fade-* 规则已整体移除），去掉的原因见上方 router-view 处的注释。
 *
 * 若将来要重新加回切页动画，务必记住一条：**不能用 mode="out-in"**。
 * out-in 会把新组件替换成一个注释占位节点，并把 instance.update() 挂到旧组件的 afterLeave 上
 * （见 BaseTransition 源码）——新页面的 setup() / onMounted() / onActivated() 要等离场动画整段
 * 跑完才执行，而各页面的数据请求正写在 onMounted / onActivated 里（keep-alive 下已缓存的页面
 * 同样排在 afterLeave 之后）。于是动画时长不是与请求并行，而是**串在请求前面**，等于给每一次
 * 切换白加一段固定延迟，数据越多、请求越慢越显眼。这个坑已经踩过一次。
 */

/* 窄屏外观：侧栏收成一列图标。
 *
 * 顶栏那一行的排布是「左侧折叠按钮 — 中间时间 — 右侧语言与账号」，两侧都是 flex: 1。
 * 中间那格要正好落在中线上，条件是两侧各自分到的空间都不小于较宽那一侧的内容宽度；
 * 达不到时较宽的一侧按内容宽度撑住，中间那格就整体偏向窄的一侧。
 *
 * 右侧是定值 133（语言下拉 56 + 间距 14 + 头像那块 63）——语言只显示缩写、
 * 用户名挪进了下拉，两者都不随内容变宽，所以这道算式是能算准的。
 * 时间一整串连底色 280（英文最长的 Wednesday 那一档），于是精确居中要求
 * 顶栏内部有 2 × 133 + 280 + 两道间距 28 = 574 像素。
 *
 * 带文字的侧栏宽 232，顶栏内部只有「屏宽 − 306」，要 574 就得 880 像素以上的屏宽；
 * 收成图标之后侧栏只剩 74，顶栏内部变成「屏宽 − 136」，574 只需要 710。
 * 900 取在这两个数之间，于是两侧都落在各自够宽的一边：这一档以上是带文字的侧栏、
 * 这一档以下是图标侧栏，时间在两边都精确居中。
 * 断点比算出来的数留出十几像素，是因为浏览器判定媒体查询时把纵向滚动条的宽度算在内，
 * 页面实际可用宽度比断点小约 10 像素。 */
@media (max-width: 900px) {
  .layout {
    padding: 8px;
  }
  .sidebar {
    width: 74px;
  }
  .brand-name,
  .menu-item span {
    display: none !important;
  }
}

/* 平板与横屏手机：时间仍留在这一行，只是换成上下两行的排法（那一份见 TopClock 的 730px）。
 * 两行那一份连底色宽 149~180 像素（中文 149，英文最长的 Wednesday 那档 180），
 * 按上面那道算式，精确居中要求顶栏内部有 2 × 133 + 180 + 28 = 474 像素，
 * 对应屏宽 610；而一行整串那一份要 710。730 就落在这两个数之间。 */
@media (max-width: 730px) {
  .top-clock {
    padding: 4px 12px;
  }
}

/* 手机：顶栏换成两行——上一行是折叠按钮、语言与账号，时间独占下一行。
 *
 * 断点取 530 的原则是"能装下就不换行"：时间与语言、账号同处一行、上下居中，
 * 看着才是一条完整的栏；掀到第二行会让上一行空出一大块，栏也高了一截。
 * 一行装得下的下限是折叠按钮 27 + 时间 180（英文最长的 Wednesday 那一档，
 * 上下两行的排法）+ 右侧 133 加两道间距 14，合计 368 像素的顶栏内部宽度，
 * 对应屏宽 514；530 在它上面留了十几像素，给媒体查询算进去的滚动条宽度。
 *
 * 于是 530~610 这一段是有意接受的偏差：一行里左侧只有 27、右侧有 133，
 * 两边分不到相等的空间，时间会偏左，最窄处约 45 像素。要精确居中就得换行，
 * 而那正是上面说的不好看——两者只能挑一个，这里挑了留在同一行。
 * 610 以上两侧就都够宽了，时间重新回到精确居中（算式见上一段注释）。
 *
 * 530 以下换行是没有别的选择：三格硬挤在一行时，中间那格 flex: 0 0 auto、
 * 时间又 nowrap，这一行的最小宽度被时间那一串字钉死。320 像素屏上顶栏只有
 * 180 像素可用，挤不下的部分不会换行，只会一路溢出到右边——时间那块底色跑到
 * 卡片外面，语言与账号整块被推出屏幕，整篇文档也跟着变宽，于是"要缩放才能看全"。 */
@media (max-width: 530px) {
  .topbar {
    flex-wrap: wrap;
    gap: 10px;
    padding: 8px 12px;
  }
  .topbar-left {
    flex: 0 0 auto;
  }
  /* 不给 min-width: 0：宽度实在不够时应当整块换到下一行，而不是就地压扁。 */
  .topbar-right {
    flex: 1 1 auto;
  }
  /* 100% 的基准宽度让它必然落到新的一行，order 保证那一行在下面。 */
  .topbar-center {
    order: 3;
    flex: 1 0 100%;
  }
}
</style>
