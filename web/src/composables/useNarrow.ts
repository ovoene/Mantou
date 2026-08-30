import { onMounted, onUnmounted, ref, type Ref } from 'vue'

// 窄屏判定。
//
// 这里的 640 和各组件窄屏样式里的 `@media (max-width: 640px)` 是同一个阈值，等于同一个数
// 写了两份。没有更好的办法：CSS 换不了 DOM 结构和组件属性（页头的「更多」菜单、表单的
// 标签位置都得换），而 JS 又读不到样式表里那个 @media 用的数。**改这里要一并改样式那边。**
export const NARROW_QUERY = '(max-width: 640px)'

// useNarrow 返回一个跟着窗口宽度变化的布尔值。
// 只在 onMounted 里建 matchMedia：组件可能在服务端或测试环境下被创建，那里没有 window。
export function useNarrow(): Ref<boolean> {
  const narrow = ref(false)
  let mq: MediaQueryList | null = null
  function onChange(e: MediaQueryListEvent) {
    narrow.value = e.matches
  }
  onMounted(() => {
    mq = window.matchMedia(NARROW_QUERY)
    narrow.value = mq.matches
    mq.addEventListener('change', onChange)
  })
  onUnmounted(() => mq?.removeEventListener('change', onChange))
  return narrow
}
