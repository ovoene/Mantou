// copyText 把一段文本放进剪贴板，返回是否成功。
//
// 两条路：先用 clipboard API，不行再退到 textarea + execCommand。
// 退路要覆盖两种"不行"：
//   - 面板跑在 http 上：clipboard API 只在安全上下文里存在；
//   - API 在，但调用被拒：权限策略、内嵌的网页视图都会让 writeText 直接抛 NotAllowedError。
//     只在"API 不存在"时才走退路的话，这种环境下复制永远失败，而老办法其实用得了。
// 两条路都失败时返回 false，由调用方提示用户手动复制——静默失败等于这个按钮不存在。
export async function copyText(text: string): Promise<boolean> {
  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text)
      return true
    } catch {
      /* 被拒：落到下面的退路 */
    }
  }
  try {
    const ta = document.createElement('textarea')
    ta.value = text
    ta.style.position = 'fixed'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.select()
    const ok = document.execCommand('copy')
    document.body.removeChild(ta)
    return ok
  } catch {
    return false
  }
}
