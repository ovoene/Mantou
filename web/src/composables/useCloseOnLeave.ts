import { onDeactivated, type Ref } from 'vue'

// 切走这一页时，把页面里的弹窗开关全部拨回 false。
//
// 各模块页面是被 keep-alive 缓存的（见 MainLayout），而 el-dialog 的实际 DOM 由 teleport
// 挂在 body 上、不在页面自己那棵子树里。页面被切走时 Vue 只把页面子树移进缓存容器，
// body 上那个弹窗留在原地——结果是弹窗浮在**新**页面上，关掉它才发现底下已经换了一页；
// 更麻烦的是弹窗里的「保存」按的仍是上一页的数据。
//
// 只能由页面自己来关：开关是页面里的 ref，外面拿不到。这个函数就是那一行样板，
// 免得每个页面各写一遍 onDeactivated、再各写一遍上面这段理由。
//
// 顺带说明为什么是「切页时关掉」而不是「切页前拦住」：这一层拦不干净。侧栏在弹窗遮罩
// 底下点不到，能触发切页的只有浏览器的返回键与手势，而那两者一旦拦下就等于让返回键失灵。
export function useCloseOnLeave(...flags: Ref<boolean>[]) {
  onDeactivated(() => {
    for (const flag of flags) flag.value = false
  })
}
