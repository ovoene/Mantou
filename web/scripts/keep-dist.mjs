// 构建后把 dist/.gitkeep 补回来。
//
// 后端用 `//go:embed all:dist` 内嵌前端产物，dist 不存在或为空目录都会让 go build 直接失败，
// 所以仓库里跟踪了一个空的 web/dist/.gitkeep 作为占位（.gitignore 里有 `!web/dist/.gitkeep`）。
// 而 vite 配的是 emptyOutDir: true，清 dist 时连点开头的文件一起删——本地构建完
// `git status` 就会多出一条 "deleted: web/dist/.gitkeep"，跟着改动一起提交上去，
// 别人克隆下来在没构建前端时 go build 就编不过了。
//
// 用 node 写文件而不是 touch：Windows 的 npm 是走 cmd.exe 跑脚本的，那里没有 touch。
import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const dist = join(dirname(dirname(fileURLToPath(import.meta.url))), 'dist')
mkdirSync(dist, { recursive: true })
writeFileSync(join(dist, '.gitkeep'), '')
