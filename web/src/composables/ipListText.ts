// 把用户粘贴进来的一大段文字拆成一条条待添加的地址（服务防护的白名单 / 黑名单添加框用）。
//
// 这里只管"拆"，不管"对不对"：哪条写法合法、哪条已在名单里、名单还放不放得下，
// 一律交给服务端的预览接口（dryRun）判断。前端再写一份 IP / CIDR / 范围校验，
// 两边迟早会出现"前端说合法、后端存的时候丢掉"的分歧，而用户看到的是前者。
//
// 拆分规则：
//   - 换行、空白、逗号、分号、顿号、竖线都算分隔符（中英文标点都认）；
//   - 一行里 # 之后的内容是这一行的备注，作用于这一行拆出来的所有地址；
//   - 「1.2.3.4 - 1.2.3.9」这种两边带空格的范围先并成一条，不会被空格拆成三段；
//   - 带端口的写法（1.2.3.4:443、[2001:db8::1]:443）去掉端口——从日志或浏览器地址栏
//     复制过来的地址常带着它，而名单只认地址；
//   - 不含任何数字的片段（"TLS""from""EOF:" 之类）直接略过并计数：整段日志贴进来时，
//     把每个英文单词都报成"无效地址"只会把真正写错的那几条淹没。

export interface IpListToken {
  ip: string
  note: string
}

export interface SplitResult {
  items: IpListToken[]
  // 略过的非地址片段个数（不含数字的词），界面上提一句即可，不逐个列出。
  ignored: number
}

const SEP = /[\s,，;；、|]+/
// 全角字符换成半角：中文输入法下敲出来的「１．２．３．４」「：」也能认。
// 按码点判断而不是写一个全角字符区间的正则：源码里不放原始的全角字符与全角空格，
// 免得一眼看上去和半角分不清、被编辑器或格式化工具悄悄换掉。
function toHalfWidth(s: string): string {
  let out = ''
  for (const ch of s) {
    const c = ch.charCodeAt(0)
    if (c >= 0xff01 && c <= 0xff5e) out += String.fromCharCode(c - 0xfee0) // 全角 ASCII 区
    else if (c === 0x3000) out += ' ' // 全角空格
    else out += ch
  }
  return out
}

// stripPort 去掉地址后面的端口；认不出的原样返回。
function stripPort(tok: string): string {
  // [v6]:port 或 [v6]
  const v6 = /^\[([0-9a-fA-F:.]+)\](?::\d{1,5})?$/.exec(tok)
  if (v6) return v6[1]
  // v4:port。只认四段点分十进制后跟一个冒号与端口，免得误伤 IPv6（它本身就满是冒号）。
  const v4 = /^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$/.exec(tok)
  if (v4) return v4[1]
  return tok
}

// trimDecor 去掉一条片段首尾的装饰：引号、括号、句号，以及日志里地址后面跟着的那个冒号
// （"from 1.2.3.4:5678: EOF" 拆出来是「1.2.3.4:5678:」）。
//
// 句末的点和冒号只在"去掉之后确实是个带端口的地址 / 四段 IPv4"时才去：IPv6 可以合法地以
// 「::」结尾（2001:db8::），一律去掉末尾冒号会把它改成另一个地址。
function trimDecor(tok: string): string {
  tok = tok.replace(/^["'`(<（]+/, '').replace(/["'`)>）。]+$/, '')
  if (tok.endsWith(':') && !tok.endsWith('::')) {
    const head = tok.slice(0, -1)
    if (stripPort(head) !== head) tok = head
  }
  if (/^\d{1,3}(?:\.\d{1,3}){3}\.$/.test(tok)) tok = tok.slice(0, -1)
  return tok
}

export function splitIpListText(text: string): SplitResult {
  const items: IpListToken[] = []
  let ignored = 0
  for (const rawLine of toHalfWidth(text || '').split(/\r?\n/)) {
    const hash = rawLine.indexOf('#')
    const body = hash >= 0 ? rawLine.slice(0, hash) : rawLine
    // 行内备注只做最基本的整理（去首尾空白）；长度由服务端校验并报错，这里不悄悄截断。
    const note = hash >= 0 ? rawLine.slice(hash + 1).trim() : ''
    // 范围两边的空格先并掉：「a - b」→「a-b」。只并"两边都像地址"的，免得把普通连字符也吃掉。
    const joined = body.replace(/([0-9a-fA-F:.\]])\s*-\s*([0-9a-fA-F:.[])/g, '$1-$2')
    for (let tok of joined.split(SEP)) {
      tok = trimDecor(tok)
      if (!tok) continue
      if (!/\d/.test(tok)) {
        ignored++
        continue
      }
      items.push({ ip: stripPort(tok), note })
    }
  }
  return { items, ignored }
}
