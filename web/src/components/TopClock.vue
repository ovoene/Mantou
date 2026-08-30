<script setup lang="ts">
import { computed, onActivated, onBeforeUnmount, onDeactivated, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'

// 顶栏实时时钟：中文「年-月-日 星期 时:分:秒」，英文「YYYY-MM-DD Weekday HH:MM:SS」。
//
// 单独拆成一个组件，是因为它每秒要变一次。写在 MainLayout 里时，那一下重渲染
// 覆盖的是整个外壳——侧栏十一个菜单项、顶栏、以及 <router-view> 那一层，
// 每秒一次、常年不停。渲染本身不慢，但它与鼠标移动、点击落在同一个主线程上，
// 于是"点左侧模块偶尔顿一下"这种说不清的卡顿就有了来处。拆开之后每秒重渲染的
// 只剩这一行字。
//
// 页面藏起来（切到别的标签页、最小化）时停掉：这一秒一次的定时器在后台除了
// 让浏览器不能休眠之外没有任何作用，回到前台时补渲染一次即可。
//
// 分两截存（日期 / 星期+时刻）是给窄屏用的：手机上顶栏那一行装不下整串，
// 于是改成上下两行。宽屏仍拼回原来那一整串，见下方 dateText + weekTime 的注释。

const { locale } = useI18n()

// dateText 是「年月日」，weekTime 是「星期 时:分:秒」。
// 拆在这里而不是拆到两个 tick 里，是为了让宽屏那一行仍是同一串字：
// oneLine 就是两截用一个空格拼回去，与拆分之前逐字相同。
const dateText = ref('')
const weekTime = ref('')
const oneLine = computed(() => `${dateText.value} ${weekTime.value}`)
let timer: number | null = null

const zhWeek = ['星期日', '星期一', '星期二', '星期三', '星期四', '星期五', '星期六']
const enWeek = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']

function pad2(n: number): string {
  return n < 10 ? '0' + n : String(n)
}

function tick() {
  const d = new Date()
  const zh = locale.value === 'zh-CN'
  const y = d.getFullYear()
  const m = pad2(d.getMonth() + 1)
  const day = pad2(d.getDate())
  const hm = `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`
  const w = zh ? zhWeek[d.getDay()] : enWeek[d.getDay()]
  dateText.value = zh ? `${y}年${m}月${day}日` : `${y}-${m}-${day}`
  weekTime.value = `${w} ${hm}`
}

function start() {
  tick()
  if (timer === null) timer = window.setInterval(tick, 1000)
}

function stop() {
  if (timer !== null) {
    window.clearInterval(timer)
    timer = null
  }
}

function onVisibility() {
  if (document.hidden) stop()
  else start()
}

// 切语言时立刻重排一次：不然中英文格式要等到下一秒才换，看着像没切成。
watch(locale, tick)

onMounted(() => {
  start()
  document.addEventListener('visibilitychange', onVisibility)
})
onActivated(start)
onDeactivated(stop)
onBeforeUnmount(() => {
  stop()
  document.removeEventListener('visibilitychange', onVisibility)
})
</script>

<template>
  <span class="top-clock-time">
    <!-- 两种排法各留一份文本：宽屏一行，窄屏上下两行。
         之所以不是一份文本靠 CSS 换行——CSS 折不出「日期一行、星期与时刻一行」
         这种固定断点，而放开换行则会在汉字之间随宽度乱断。
         各自一份的代价是多两个文本节点，好处是宽屏那一行一个像素都没动。 -->
    <span class="tc-line">{{ oneLine }}</span>
    <span class="tc-stack">
      <span>{{ dateText }}</span>
      <span>{{ weekTime }}</span>
    </span>
  </span>
</template>

<style scoped>
/* 宽屏只显示一行那份。断点 730 是量出来的：一整串连底色宽 280 像素（英文最长的
 * Wednesday 那一档），要让它在顶栏里正好居中，顶栏内部得有 574 像素，对应屏宽 710。
 * 再窄就换成上下两行那份——那一份连底色只有 149~180 像素，于是能一路留在顶栏那一行里
 * （和语言、账号同一行、上下居中），直到 530 以下一行实在装不下才整块换行
 * （那两道算式都在 MainLayout 的媒体查询注释里）。 */
.tc-stack {
  display: none;
}
@media (max-width: 730px) {
  .tc-line {
    display: none;
  }
  .tc-stack {
    /* inline-flex 而不是 flex：外层是个行内 span，塞进块级盒会被拆成匿名块，
     * 行高与基线都跟着变。 */
    display: inline-flex;
    flex-direction: column;
    align-items: center;
    vertical-align: middle;
    line-height: 1.32;
  }
}
</style>
