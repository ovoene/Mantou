import type { GfwConfig } from '@/api/resources'

// 服务防护的状态文案：档位译名与那句"当前规则"。
//
// 抽成一个文件的理由是**同步**：这句话要出现在三处——「服务防护」模块页、Web 服务页顶部的
// 只读状态条、消息路由页顶部的只读状态条。三处各拼一份的话，改一次阈值口径就得改三处，
// 漏掉任何一处的表现是"同一份配置在两个页面上写着不同的规则"，而不会有任何报错。
//
// 后端原先下发一句拼好的中文摘要，正是为了避开这个问题；但那句话是硬编码中文，
// 英文界面上会突然冒出一行中文，而且它与模块页的表单仍是两份来源。现在统一成：
// 后端只给结构化数值，文案由这里按当前语言拼。

// Translate 只取 vue-i18n 的 t 用得到的那一种形态。
// 不直接引 ComposerTranslation：那个类型带一串泛型参数，为了一个纯函数把它拖进来
// 会让这个文件跟着 vue-i18n 的版本走。
export type Translate = (key: string, named?: Record<string, unknown>) => string

// gfwLevelLabel 档位的译名。
//
// 档位键由后端下发（config.GlobalFirewallPresets 那张表 + custom），前端不维护清单——
// 于是"后端加了一档"不需要改这里。查不到译名时原样返回键名：那样界面上会露出一个可见的
// 英文键（loose / balanced / …），比空字符串好——空字符串只会让人以为这一栏坏了。
export function gfwLevelLabel(t: Translate, level: string): string {
  if (!level) return ''
  const key = `gfw.level${level.charAt(0).toUpperCase()}${level.slice(1)}`
  const s = t(key)
  return s === key ? level : s
}

// gfwRulesText 一句话说清"现在按什么规则拦"。停用时返回空串——调用方此时该显示"已停用"，
// 再跟一串永远不会生效的阈值只会让人以为它还在拦。
//
// 自动封禁关着时刻意不念阈值：那几个数此刻不作数（见 config.GlobalFirewall.Valid 的说明），
// 念出来等于把一组不生效的数字说成当前规则。
export function gfwRulesText(t: Translate, cfg: GfwConfig | null | undefined): string {
  if (!cfg || !cfg.enabled) return ''
  const level = gfwLevelLabel(t, cfg.level)
  if (!cfg.autoBan) return t('gfw.chipAutoBanOff', { level })
  return t('gfw.chipRules', {
    level,
    ws: cfg.windowSeconds,
    wl: cfg.windowLimit,
    bs: cfg.burstSeconds,
    bl: cfg.burstLimit,
    bm: cfg.banMinutes,
  })
}

// gfwListsText 名单条数。名单是用户自己写下的明确规则，与自动封禁是两回事：
// 一个把自动封禁关掉、只靠拒绝名单挡人的用户，状态条上如果只字不提名单，
// 看起来就像服务防护什么都没在做。两张都空时返回空串，不占一行位置。
export function gfwListsText(t: Translate, cfg: GfwConfig | null | undefined): string {
  if (!cfg || !cfg.enabled) return ''
  const allow = cfg.allowIps?.length ?? 0
  const deny = cfg.denyIps?.length ?? 0
  if (allow === 0 && deny === 0) return ''
  return t('gfw.chipLists', { allow, deny })
}
