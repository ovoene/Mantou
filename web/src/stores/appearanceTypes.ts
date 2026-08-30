// 外观相关类型与默认值，供 store 与设置页复用。

export interface AppearanceColors {
  primary: string
  accent: string
  success: string
  warning: string
  danger: string
}
export interface AppearanceBackground {
  type: 'color' | 'gradient' | 'image'
  value: string
  blur: number
  overlayOpacity: number
  fit: string
  position: string
}
export interface AppearanceCard {
  opacity: number
  blur: number
  radius: number
  shadow: string
}
export interface AppearanceFont {
  family: string
  scale: number
  weight: number
}
export interface AppearanceLayout {
  sidebar: string
  density: string
}
export interface Appearance {
  themeMode: 'light' | 'dark' | 'auto'
  colors: AppearanceColors
  background: AppearanceBackground
  card: AppearanceCard
  font: AppearanceFont
  layout: AppearanceLayout
}

// 默认外观。
//
// 这份值必须与后端 internal/config/store.go 的 defaultAppearance() 逐项一致 —— 那边才是
// 「网站默认外观」的出处：全新安装时它被写进配置文件，登录后前端拿到的就是它。
// 这边这份只在**还没拿到服务端那份**时顶着用：没登录过的设备（外观接口要登录）、
// 接口失败、以及设置页的「恢复默认外观」。
//
// 两份值曾经不一致（主色 #4f6bed / 强调色 #f5a623 对 #4f7cff / #22c1a6，卡片透明度
// 0.98 对 0.72），于是首次访问的设备先按这边的颜色画一遍，登录后才换成服务端那套 ——
// 看上去就是"颜色跟默认的不一样，刷新一下才对"。改这里的任何一项都要同步改后端那份。
export function defaultAppearance(): Appearance {
  return {
    themeMode: 'light',
    colors: {
      primary: '#4f7cff',
      accent: '#22c1a6',
      success: '#22c55e',
      warning: '#f59e0b',
      danger: '#ef4444',
    },
    background: {
      type: 'gradient',
      value: 'linear-gradient(135deg,#e6efff 0%,#f3f0ff 100%)',
      blur: 0,
      overlayOpacity: 0.15,
      fit: 'cover',
      position: 'center',
    },
    // card.blur 已无人读取（卡片改成实底 + 细边框，见 stores/appearance.ts），
    // 这里仍留 14 只为与后端那份逐字节相同，免得"恢复默认"存回去的配置与全新安装不一样。
    card: { opacity: 0.72, blur: 14, radius: 14, shadow: 'md' },
    font: { family: 'system', scale: 1, weight: 400 },
    layout: { sidebar: 'expanded', density: 'comfortable' },
  }
}

// 深浅拷贝，避免响应式对象被直接改动。
export function cloneAppearance(a: Appearance): Appearance {
  return JSON.parse(JSON.stringify(a))
}
