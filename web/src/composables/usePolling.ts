import { onBeforeUnmount, onActivated, onDeactivated, onMounted } from 'vue'

// usePolling 管一个「只在有人看着的时候才跑」的轮询定时器。
//
// 各模块页面原先各写一遍 startPolling / stopPolling，写出来的其实是**两种**不同的东西：
// Overview 那份停在两个条件上（切走页面、标签页不可见），其余四页（Wol / WebServices /
// Certs / MessageRoutes）只停在第一个。差别在后台标签页上：面板开着忘了关很常见，
// 而不可见的标签页里那个定时器照样每 2~5 秒打一次接口——白占上行带宽（远程访问家宽时
// 约 8 KB/s ≈ 30 MB/小时），还让后端持续为无人查看的页面采样。
//
// 三条行为在这里统一：
//   - 切走页面就停（keep-alive 的 onDeactivated；缓存被销毁时的 onBeforeUnmount 同理）
//   - 标签页不可见就停
//   - 重新可见立刻补一次，别让页面停在离开时的旧数据上
//
// 定时器只在「有意图 && 页面激活 && 标签页可见」三者同时成立时存在，任一条不成立即拆除。
export interface Polling {
  // start 表示「这一页现在需要轮询」。可以重复调用：已经在跑就什么也不做。
  start(): void
  // stop 表示「不需要了」。切走页面会自动 stop，因此页面在 onActivated 里要重新 start
  // （五个调用点原本都已经这么写，见各页的 onActivated）。
  stop(): void
}

export function usePolling(tick: () => unknown, intervalMs: number): Polling {
  let timer: number | undefined
  let wanted = false // start / stop 表达的意图
  let alive = true // 页面是否处于激活状态；非 keep-alive 场景下 onActivated 不触发，故默认 true

  // 跑一次 tick。
  //
  // 这里吞掉异常是刻意的，而且只吞在这一层：报错是 tick 自己的事（各页面传进来的都是
  // 静默刷新，失败时保留旧数据）。这一层要保证的是**定时器不会因为一次失败而消失**——
  // 否则一次瞬时错误就让页面永久停在旧数据上，而界面上看不出轮询已经停了。
  // 另外 run 也会被 onVisibilityChange 同步调用一次，那里抛出去会打断事件处理的后半段。
  function run(): void {
    try {
      const r = tick()
      if (r instanceof Promise) void r.catch(() => undefined)
    } catch {
      /* 交给下一轮 */
    }
  }

  function arm(): void {
    if (timer !== undefined) return
    if (!wanted || !alive || document.hidden) return
    timer = window.setInterval(run, intervalMs)
  }

  function disarm(): void {
    if (timer === undefined) return
    window.clearInterval(timer)
    timer = undefined
  }

  function onVisibilityChange(): void {
    if (document.hidden) {
      disarm()
      return
    }
    arm()
    // 补拉：只在「确实重新开跑了」之后补，否则页面早已切走、这一发请求没人要。
    if (timer !== undefined) run()
  }

  function start(): void {
    wanted = true
    arm()
  }

  function stop(): void {
    wanted = false
    disarm()
  }

  // 监听挂在 onMounted / onBeforeUnmount 上，而不是跟着 onActivated / onDeactivated 成对开合：
  // 页面被缓存期间必须**留着**这个监听，否则「离开时不可见、回来时可见」这种顺序就听不到；
  // 而缓存期间 alive 为 false，处理函数不会做任何事。非 keep-alive 组件也因此能正常工作。
  onMounted(() => document.addEventListener('visibilitychange', onVisibilityChange))

  onActivated(() => {
    alive = true
  })

  // 切走即停，并且把意图一并清掉：页面回来时会在自己的 onActivated 里重新 start，
  // 那时该拉什么、要不要接着轮询由页面现判（例如 MessageRoutes 要看还有没有试运行在跑）。
  onDeactivated(() => {
    alive = false
    stop()
  })

  onBeforeUnmount(() => {
    alive = false
    stop()
    document.removeEventListener('visibilitychange', onVisibilityChange)
  })

  return { start, stop }
}
