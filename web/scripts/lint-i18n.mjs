// 语言包体检：vue-i18n 会把文案里的裸 @ 当成「链接到另一条文案」的起始符
// （@:key / @.lower:key），后面接普通文字就是语法错误。它的代价特别不对等：
// vue-tsc 查不出来，dev 下只在控制台丢一条 tokenizer 报错，而生产构建里 t()
// 直接抛异常——渲染这条文案的那一整块界面（弹窗正文、表单一栏）会整片空掉，
// 页面上看不到任何错误提示。所以放进 build 前置，写错就让构建失败。
//
// 唯一正确的写法是字面量插值 {'@'}。
import { readFileSync, readdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const dir = join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'i18n')

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
  process.exit(1)
}
