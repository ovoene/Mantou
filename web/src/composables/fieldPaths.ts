// 把一段样本载荷（已解析的 JSON）摊成字段树与路径清单。
//
// 这是"不写代码"的关键一环：用户把第三方系统真实推来的包贴进来，界面直接列出
// 每个字段的完整取值路径，点一下就能填进条件或模板。没有它，用户就得自己数
// body.data.items[0].名称 该怎么写，而这正是他原本要写代码的地方。

export interface FieldNode {
  path: string
  label: string
  preview: string
  // array 这一层是数组。模板里数组必须走循环，插值写法完全不同，所以要能一眼分辨；
  // children 有值时装的是**元素**的字段（路径带 [*]），不是数组自己的下一层。
  array?: boolean
  children?: FieldNode[]
}

// 深度与宽度都要有上限：载荷来自第三方，一个几千个元素的数组会让树渲染卡住，
// 而超过六层的字段在消息模板里已经没有实际可读性了。
const MAX_DEPTH = 6
const MAX_CHILDREN = 80

function preview(v: any): string {
  if (v === null || v === undefined) return 'null'
  if (Array.isArray(v)) return `[${v.length}]`
  if (typeof v === 'object') return '{…}'
  const s = String(v)
  return s.length > 48 ? s.slice(0, 48) + '…' : s
}

function build(label: string, path: string, v: any, depth: number): FieldNode {
  const node: FieldNode = { path, label, preview: preview(v) }
  if (depth >= MAX_DEPTH) return node

  if (Array.isArray(v)) {
    node.array = true
    // 数组用第一个元素推断结构，路径给 [*] 而不是 [0]：
    // 条件里 [*] 是"任一元素满足"，模板里配 {{range}} 遍历，两者都比写死下标有用。
    const first = v[0]
    if (first && typeof first === 'object' && !Array.isArray(first)) {
      node.children = Object.keys(first)
        .slice(0, MAX_CHILDREN)
        .map((k) => build(k, `${path}[*].${k}`, (first as any)[k], depth + 1))
    }
    return node
  }
  if (v && typeof v === 'object') {
    node.children = Object.keys(v)
      .slice(0, MAX_CHILDREN)
      .map((k) => build(k, path ? `${path}.${k}` : k, v[k], depth + 1))
  }
  return node
}

export function buildFieldTree(root: any): FieldNode[] {
  if (!root || typeof root !== 'object' || Array.isArray(root)) return []
  return Object.keys(root)
    .slice(0, MAX_CHILDREN)
    .map((k) => build(k, k, (root as any)[k], 0))
}

// collectPaths 摊平成路径清单，供输入框的补全用。
export function collectPaths(nodes: FieldNode[]): string[] {
  const out: string[] = []
  const walk = (list: FieldNode[]) => {
    for (const n of list) {
      out.push(n.path)
      if (n.children) walk(n.children)
    }
  }
  walk(nodes)
  return out
}

// aliasCandidates 一条「取值路径」折算成**相对载荷根**的几种写法，用来判断
// 某个字段是不是已经起过别名了。
//
// 后端取值是两步的（见 event.go）：先按信封取（body.items 这种写法），取不到再按
// 载荷取（items 这种写法）；而「取值根路径」不为空时，那一层的键还会被摊到信封根上，
// 于是 rootPath=data 时用户写的 items 实际指的是 data.items。字段树里的路径一律
// 相对载荷根，所以这里把这几种写法都折算过去，逐个比一次。
//
// 少认一种写法的后果是界面反复催用户"给数组起个别名"——而他明明已经起过了。
export function aliasCandidates(path: string, rootPath = ''): string[] {
  let p = (path || '').trim().replace(/^\.+/, '')
  if (p.startsWith('body.')) p = p.slice(5)
  if (!p || p === 'body') return []
  const root = (rootPath || '')
    .trim()
    .replace(/^\.+/, '')
    .replace(/^body\.?/, '')
  return root ? [p, `${root}.${p}`] : [p]
}

// findNode 按路径取回节点。字段树只把路径交给调用方（点一下要么复制、要么插模板），
// 而"这一层是不是数组、元素有哪些字段"要看节点本身，于是需要按路径找回来。
export function findNode(nodes: FieldNode[], path: string): FieldNode | null {
  for (const n of nodes) {
    if (n.path === path) return n
    if (n.children) {
      const hit = findNode(n.children, path)
      if (hit) return hit
    }
  }
  return null
}

// collectArrays 样本里所有"能直接遍历"的数组。
//
// 数组是这套东西里唯一需要用户额外做一件事的字段：其它字段 {{.别名}} 就取到了，
// 数组直接取到的是 Go 的切片字面量，必须走 {{range}}。所以界面上要主动把它们找出来
// 醒目标注、催用户起个别名，而不是等用户发现"那一组数据发出来是一行乱码"。
//
// 路径里带 [*] 的（数组套数组）不收：那种要嵌两层循环，而别名走 lookupOne 只拿得到
// 第一条（见后端 event.go），催用户去给它起别名是帮倒忙。数组自己的 children 装的是
// **元素**的字段，所以命中数组后不再往下走。
//
// 元素是对象的排在前面：那是一组记录，逐条列出来才有信息量；一组纯值（标签、附件名）
// 也能列，但通常不是用户想逐条摆开的那一段。
export function collectArrays(nodes: FieldNode[]): FieldNode[] {
  const out: FieldNode[] = []
  const walk = (list: FieldNode[]) => {
    for (const n of list) {
      if (n.array) {
        if (!n.path.includes('[*]')) out.push(n)
        continue
      }
      if (n.children) walk(n.children)
    }
  }
  walk(nodes)
  return out.sort((a, b) => (b.children?.length ? 1 : 0) - (a.children?.length ? 1 : 0))
}

// SampleSource 这段样本该怎么解。字段名与接收器一致，直接把接收器对象传进来即可。
export interface SampleSource {
  sourceType?: string
  pairSep?: string
  kvSep?: string
}

// trimSample 去掉首尾空白与开头的不可见字符（BOM / 零宽空格）。
//
// 必须与后端的 webhook.trimBody 一致：JS 的 trim() 认 \ufeff 但不认 \u200b，
// 少去一个字符的后果是 JSON.parse 直接抛错——样本明明是好的，界面上却标红说"解不出"，
// 而那个字节在输入框里看不见，用户完全无从下手。
export function trimSample(text: string): string {
  return (text || '').replace(/^[\s\ufeff\u200b]+|[\s\ufeff\u200b]+$/g, '')
}

// parseJSONText 是一份**完整合法**的 JSON 对象 / 数组就解出来，否则给 undefined。
// 要求以 { 或 [ 开头：裸数字、裸字符串也是合法 JSON，但没人会为它们配取值路径。
function parseJSONText(s: string): any {
  if (!s.startsWith('{') && !s.startsWith('[')) return undefined
  try {
    return JSON.parse(s)
  } catch {
    return undefined
  }
}

// MIN_KV_PAIRS 至少拆得出这么多字段才敢把一段文本当键值文本（后端 minKVPairs 同值）。
// 一个冒号的句子（"告警: 磁盘满了"）也能拆出一对，把它当字段是帮倒忙。
export const MIN_KV_PAIRS = 2

// detectSampleType 这段样本更像 json / kv / txt；空样本给空串（不表态）。
// 镜像后端的 webhook.detectSourceType——界面上「这条按什么解的」这句提示读的就是它，
// 说得和运行期不一样比不说更糟。
export function detectSampleType(text: string, pairSep = '', kvSep = ''): string {
  const s = trimSample(text)
  if (!s) return ''
  if (parseJSONText(s) !== undefined) return 'json'
  // 看着像 JSON 却解不出：判 txt，至少原文看得见。不再往 kv 上试——
  // 一段被截断的 JSON 也能按逗号+冒号拆出几个"字段"，那只会把用户带偏。
  if (s.startsWith('{') || s.startsWith('[')) return 'txt'
  return sniffKVSeps(s, pairSep, kvSep).pairs >= MIN_KV_PAIRS ? 'kv' : 'txt'
}

// parseSample 宽容地解析样本载荷：解不出字段结构就返回 null，由调用方提示。
//
// 判据与后端 decodeBody 一一对应：默认（自动识别）逐条判形态；显式选定的类型压过判定；
// **合法 JSON 永远按 JSON 解**，即便类型选的是键值文本——把 JSON 按符号硬拆会得到
// 一堆名叫 `{"biz"` 的假字段，字段树看着像解出来了，而每条取值路径都取不到值。
// 选了纯文本则一个字段都不列：运行期 body 就是一整段字符串，列出字段只会骗人。
export function parseSample(text: string, src?: SampleSource): any {
  const s = trimSample(text)
  if (!s) return null
  const asJSON = parseJSONText(s)
  switch (src?.sourceType) {
    case 'txt':
      return null
    case 'json':
      return asJSON === undefined ? null : asJSON
    case 'kv':
      return asJSON !== undefined ? asJSON : decodeKVText(s, src.pairSep || '', src.kvSep || '')
  }
  if (asJSON !== undefined) return asJSON
  return detectSampleType(s) === 'kv' ? decodeKVText(s) : null
}

// ---- 键值文本 ----
//
// 键值文本（a=1&b=2）不是 JSON，得先按分隔符拆一遍才有字段可列。
// 判据与后端 internal/modules/webhook/kv.go 同一套，但**权威永远是后端**：真实消息
// 进来时字段是后端拆的，这里只为了让用户把样本贴上就立刻看到字段树。两边若有出入，改这里。

const KV_PAIR_SEPS = ['&', '\n', ';', '|', '\t', ',']
const KV_KV_SEPS = ['=', ':']
const MAX_KV_FIELDS = 200
const MAX_KV_KEY_LEN = 64

// 只在确实出现 % 时解一次百分号编码，解不动就原样返回。
// + 绝不当空格：型号、编号里的 A+B 改掉就是实打实的数据损坏。
function kvUnescape(s: string): string {
  if (!s.includes('%')) return s
  try {
    return decodeURIComponent(s)
  } catch {
    return s
  }
}

// cutKV 只在第一个 kvSep 处切开——值里带分隔符是常态（time=12:30、url=http://a?b=1）。
// 键的形态卡得比值严：日志行 "2026-08-24 11:00:00 ERROR: disk full" 按冒号切会得到
// 一个带空格的键名，一旦当成字段，字段树里全是垃圾。JSON 的结构符号同理——
// 键名里出现它们说明拆的其实是一段结构化文本（后端 kvKeyBadChars 同一套判据）。
function cutKV(chunk: string, kvSep: string): [string, string] | null {
  let s = chunk.trim()
  if (s.startsWith('?')) s = s.slice(1) // 整段是 query 串时问号常被一起粘进来
  const i = s.indexOf(kvSep)
  if (i <= 0) return null
  const k = s.slice(0, i).trim()
  if (!k || [...k].length > MAX_KV_KEY_LEN || /[ \t\r\n"{}[\]]/.test(k)) return null
  return [kvUnescape(k), kvUnescape(s.slice(i + kvSep.length).trim())]
}

function countKV(text: string, pairSep: string, kvSep: string): number {
  let n = 0
  for (const chunk of text.split(pairSep)) if (cutKV(chunk, kvSep)) n++
  return n
}

// sniffKVSeps 在候选符号里挑出能拆出最多字段的一组，force* 非空时只试指定的那个。
// = 与 : 之间不比数量而是先认 =：值里带冒号的太多了（时间、URL），而 = 几乎只在键值场景出现。
// 界面还用它的返回值把"按什么符号拆出几个字段"写在分隔符输入框下面——
// 用户看到这句话才会相信那两栏可以留空。
export function sniffKVSeps(
  text: string,
  forcePair = '',
  forceKV = '',
): { pairSep: string; kvSep: string; pairs: number } {
  const pairCands = forcePair ? [forcePair] : KV_PAIR_SEPS
  const kvCands = forceKV ? [forceKV] : KV_KV_SEPS
  const best = { pairSep: '', kvSep: '', pairs: 0 }
  for (const k of kvCands) {
    for (const p of pairCands) {
      if (p === k) continue
      const n = countKV(text, p, k)
      if (n > best.pairs) Object.assign(best, { pairSep: p, kvSep: k, pairs: n })
    }
    if (best.pairs > 0) break // 这一层的 kvSep 已经拆得出字段，不再试更弱的候选
  }
  return best
}

// decodeKVText 拆成字段表。同名字段用 ", " 连接（与请求头、query 同口径）；
// 一个字段都拆不出来时返回 null，界面据此提示"这段不是键值文本"。
export function decodeKVText(text: string, pairSep = '', kvSep = ''): Record<string, string> | null {
  const s = (text || '').trim()
  if (!s) return null
  const hit = sniffKVSeps(s, pairSep, kvSep)
  if (!hit.pairs) return null
  const out: Record<string, string> = {}
  for (const chunk of s.split(hit.pairSep)) {
    const kv = cutKV(chunk, hit.kvSep)
    if (!kv) continue
    if (kv[0] in out) {
      out[kv[0]] += ', ' + kv[1]
      continue
    }
    if (Object.keys(out).length >= MAX_KV_FIELDS) break
    out[kv[0]] = kv[1]
  }
  return Object.keys(out).length ? out : null
}
