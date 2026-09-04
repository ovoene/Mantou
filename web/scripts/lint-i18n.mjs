// 语言包体检。两道检查，共同点是「错了不报错、只是界面上少点东西」，
// 因此 vue-tsc 与 vite build 都查不出来，只能在 build 前置里挡：
//
//   ① 裸 @：vue-i18n 把文案里的 @ 当成「链接到另一条文案」的起始符（@:key / @.lower:key），
//     后面接普通文字就是语法错误。代价特别不对等——vue-tsc 查不出来，dev 下只在控制台丢一条
//     tokenizer 报错，而生产构建里 t() 直接抛异常，渲染这条文案的那一整块界面（弹窗正文、
//     表单一栏）会整片空掉，页面上看不到任何错误提示。唯一正确的写法是字面量插值 {'@'}。
//
//   ② 两个语言包的键不对齐：i18n 配了 fallbackLocale: 'en-US'（见 src/i18n/index.ts），
//     所以缺键**不会**报错，只会静默降级，而且两个方向的降级都很难被发现：
//       - en-US 少一个键 → 回退到自己 → 界面上直接显示键路径本身（settings.foo.bar）
//       - zh-CN 少一个键 → 回退到 en-US → 中文界面里冒出一句英文
//     实际写代码时只会开着一种语言点一遍，另一种语言那半边没人看得到。同族问题还有两个，
//     一并在这里挡：一边是分组另一边是字符串（t() 拿到对象，渲染不出东西），以及占位符不一致
//     （{n} 只写在一个语言里 → 另一种语言的那句话默默少了个数字）。
import { readFileSync, readdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const dir = join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'i18n')
let failed = false

// 手写扫描而不是正则：要区分「字符串里的 @」和「注释里的 @」，正则做不到
// （'https://…' 里的 // 会被当成注释起点）。
function stringLiterals(src) {
  const out = []
  let line = 1
  for (let i = 0; i < src.length; i++) {
    const c = src[i]
    if (c === '\n') {
      line++
      continue
    }
    if (c === '/' && src[i + 1] === '/') {
      while (i < src.length && src[i] !== '\n') i++
      i--
      continue
    }
    if (c === '/' && src[i + 1] === '*') {
      i += 2
      while (i < src.length && !(src[i] === '*' && src[i + 1] === '/')) {
        if (src[i] === '\n') line++
        i++
      }
      i++
      continue
    }
    if (c === "'" || c === '"' || c === '`') {
      const start = line
      const quote = c
      let text = ''
      i++
      for (; i < src.length && src[i] !== quote; i++) {
        if (src[i] === '\\') {
          text += src[i + 1]
          i++
          continue
        }
        if (src[i] === '\n') line++
        text += src[i]
      }
      out.push({ text, line })
    }
  }
  return out
}

// ---------- ① 裸 @ ----------

const bad = []
for (const f of readdirSync(dir).filter((n) => n.endsWith('.ts'))) {
  const src = readFileSync(join(dir, f), 'utf8')
  for (const { text, line } of stringLiterals(src)) {
    // 先摘掉合法的 {'@'}，剩下的 @ 就是漏escape 的。
    if (text.replace(/\{'@'\}/g, '').includes('@')) bad.push(`  ${f}:${line}  ${text}`)
  }
}

if (bad.length) {
  console.error(`语言包里有 ${bad.length} 处裸 @，vue-i18n 会解析失败导致界面空白；请写成 {'@'}：`)
  console.error(bad.join('\n'))
  failed = true
}

// ---------- ② 键对齐 ----------

// 语言包是纯对象字面量（没有类型标注、没有 import、没有 as const），所以直接当 ESM 模块
// 加载即可，不必引 esbuild 转译——少一个依赖，且拿到的是真值，能顺带比占位符。
// 换成 TS 专有语法就会在这里报 SyntaxError，下面的 catch 负责把原因说清楚。
async function loadPack(file) {
  const src = readFileSync(join(dir, file), 'utf8')
  const url = 'data:text/javascript;charset=utf-8;base64,' + Buffer.from(src, 'utf8').toString('base64')
  try {
    return (await import(url)).default
  } catch (e) {
    console.error(`无法加载语言包 src/i18n/${file}：${e.message}`)
    console.error('语言包必须保持「纯对象字面量」——不要写类型标注、as const、import 或任何')
    console.error('TS 专有语法，否则这道键对齐检查读不了它（缺键就又变成静默回退了）。')
    process.exit(1)
  }
}

// 摊平成 "a.b.c" -> 值。分组（普通对象）继续往下走，其余一律当叶子。
function flatten(node, prefix, out) {
  for (const [k, v] of Object.entries(node)) {
    const key = prefix ? `${prefix}.${k}` : k
    if (v !== null && typeof v === 'object' && !Array.isArray(v)) flatten(v, key, out)
    else out.set(key, v)
  }
  return out
}

// 占位符只取名字并去重排序：英文常要写复数分支（'{n} item | {n} items'），
// 同一个名字出现几次不算差异，只有「一边有、另一边没有」才是。
function placeholders(v) {
  if (typeof v !== 'string') return ''
  // {'@'} 这类字面量插值带引号，\w 不会匹配到，不必特殊处理。
  return [...new Set([...v.matchAll(/\{(\w+)\}/g)].map((m) => m[1]))].sort().join(',')
}

const zh = flatten(await loadPack('zh-CN.ts'), '', new Map())
const en = flatten(await loadPack('en-US.ts'), '', new Map())

// 缺键分两条报，因为两个方向的表现完全不同（见文件头 ②），修的时候要知道会看到什么。
const missingEn = [...zh.keys()].filter((k) => !en.has(k))
const missingZh = [...en.keys()].filter((k) => !zh.has(k))
if (missingEn.length) {
  console.error(`en-US.ts 缺 ${missingEn.length} 个键（英文界面上会直接显示键路径本身）：`)
  console.error(missingEn.map((k) => `  ${k}`).join('\n'))
  failed = true
}
if (missingZh.length) {
  console.error(`zh-CN.ts 缺 ${missingZh.length} 个键（中文界面上会冒出英文原文）：`)
  console.error(missingZh.map((k) => `  ${k}`).join('\n'))
  failed = true
}

// 同一个键，一边是分组一边是文案：t() 会拿到对象，那个位置渲染不出东西。
const shape = [...zh.keys()].filter((k) => en.has(k) && typeof zh.get(k) !== typeof en.get(k))
if (shape.length) {
  console.error(`${shape.length} 个键在两个语言包里结构不同（一边是分组、一边是文案）：`)
  console.error(shape.map((k) => `  ${k}  zh=${typeof zh.get(k)}  en=${typeof en.get(k)}`).join('\n'))
  failed = true
}

const phDiff = []
for (const [k, v] of zh) {
  if (!en.has(k)) continue
  const a = placeholders(v)
  const b = placeholders(en.get(k))
  if (a !== b) phDiff.push(`  ${k}  zh{${a || '无'}}  en{${b || '无'}}`)
}
if (phDiff.length) {
  console.error(`${phDiff.length} 个键的占位符不一致（少占位符的那种语言会默默丢掉这个值）：`)
  console.error(phDiff.join('\n'))
  failed = true
}

if (failed) process.exit(1)
console.log(`语言包检查通过：zh-CN / en-US 各 ${zh.size} 个键，占位符一致`)


