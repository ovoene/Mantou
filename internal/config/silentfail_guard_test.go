package config

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// 这两条断言把审计里那条反模式——「失败路径被静默吞掉，且降级方向不安全」——固化成会红的规则。
//
// 为什么放在 internal/config：A-1（randomHex 随机源失败返回空串 → 空 HMAC 密钥）与
// A-2（clone 吞掉 json.Marshal 错误 → 空配置落盘）都出在这个包，被吞的正好就是
// crypto/rand.Read 与 json.Marshal 这两个调用。clone_guard_test.go 已经用反射钉住了
// 「Config 必须可 JSON 往返」，这里钉住的是同一族问题的另一半：调用点不许把错误丢掉。
//
// 为什么用 go test 而不是 errcheck / golangci-lint：那两个都要另装一个二进制，
// 没装就静默不跑——审计要挡的偏偏就是「检查没跑而结果全绿」。go test ./... 一定会跑。

// 被盯住的调用：键是导入路径，值是函数名。选它们的共同点是**错误一旦丢掉，
// 程序会拿着一个看起来合法的零值继续走下去**（空字节串、空切片、全零随机数），
// 而不是当场停下。io.ReadAll 之类没列进来：那类调用丢掉错误通常只是让后续的解析
// 报一个位置不对的错，仍然是 fail-closed。
var watchedCalls = map[string]map[string]bool{
	"encoding/json": {"Marshal": true, "MarshalIndent": true, "Unmarshal": true},
	"crypto/rand":   {"Read": true, "Int": true, "Prime": true},
}

// TestNoSilentlyDiscardedErrors 扫描生产代码，禁止把上表里那些调用的 error 丢给 `_`。
func TestNoSilentlyDiscardedErrors(t *testing.T) {
	var bad []string
	for _, f := range productionGoFiles(t) {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, f.abs, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("解析 %s 失败: %v", f.rel, err)
		}
		imports := importNames(file)

		ast.Inspect(file, func(n ast.Node) bool {
			var lhs []ast.Expr
			var call *ast.CallExpr
			switch s := n.(type) {
			case *ast.AssignStmt:
				if len(s.Rhs) != 1 {
					return true
				}
				c, ok := s.Rhs[0].(*ast.CallExpr)
				if !ok {
					return true
				}
				lhs, call = s.Lhs, c
			case *ast.ExprStmt:
				// 返回值一个都没接：错误当然也没接。
				c, ok := s.X.(*ast.CallExpr)
				if !ok {
					return true
				}
				call = c
			default:
				return true
			}
			name, ok := watchedCallName(call, imports)
			if !ok {
				return true
			}
			// error 一律是最后一个返回值；只有最后一位是 `_` 才算丢掉。
			if len(lhs) > 0 {
				last, isIdent := lhs[len(lhs)-1].(*ast.Ident)
				if !isIdent || last.Name != "_" {
					return true
				}
			}
			pos := fset.Position(call.Pos())
			bad = append(bad, f.rel+":"+strconv.Itoa(pos.Line)+"  "+name)
			return true
		})
	}
	if len(bad) > 0 {
		t.Errorf("以下调用把 error 丢给了 `_`，失败时会带着零值继续往下走（共 %d 处）：\n  %s\n"+
			"要么把错误返回上去，要么在旁边写清楚为什么这里丢掉是安全的并从 watchedCalls 里豁免。",
			len(bad), strings.Join(bad, "\n  "))
	}
}

// TestNoMathRand 钉住审计里那条正面结论：生产代码的随机数只能来自 crypto/rand。
//
// math/rand 的输出可预测，而本项目的随机数全部用在安全语义上（会话签名密钥、
// 令牌、备份口令派生的盐）。这条以前是"审计时恰好为零"，现在是一条规则。
func TestNoMathRand(t *testing.T) {
	var bad []string
	for _, f := range productionGoFiles(t) {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, f.abs, nil, parser.ImportsOnly|parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("解析 %s 失败: %v", f.rel, err)
		}
		for _, im := range file.Imports {
			p := strings.Trim(im.Path.Value, `"`)
			if p == "math/rand" || p == "math/rand/v2" {
				bad = append(bad, f.rel+":"+strconv.Itoa(fset.Position(im.Pos()).Line)+"  "+p)
			}
		}
	}
	if len(bad) > 0 {
		t.Errorf("生产代码不许导入 math/rand（随机数一律走 crypto/rand）：\n  %s", strings.Join(bad, "\n  "))
	}
}

// ---------- 以下是两条断言共用的扫描工具 ----------

type goFile struct{ abs, rel string }

// productionGoFiles 列出仓库里所有参与构建的 .go 文件（不含测试）。
// 测试文件不在范围内：测试里丢错误最多是这条测试自己不严谨，不会进到用户的运行时。
func productionGoFiles(t *testing.T) []goFile {
	t.Helper()
	root := moduleRoot(t)
	skipDir := map[string]bool{
		".git": true, "node_modules": true, "web": true,
		"data": true, "bin": true, "dist": true, "docs": true,
	}
	var out []goFile
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && skipDir[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		out = append(out, goFile{abs: path, rel: filepath.ToSlash(rel)})
		return nil
	})
	if err != nil {
		t.Fatalf("遍历源码树失败: %v", err)
	}
	if len(out) < 50 {
		// 兜底：路径判断一旦出错（比如 moduleRoot 找错了），扫到的文件会寥寥无几，
		// 而两条断言都会因此"通过"。宁可在这里失败，也不要静默地什么都没查。
		t.Fatalf("只扫到 %d 个 .go 文件，扫描范围明显不对（root=%s）", len(out), root)
	}
	return out
}

// moduleRoot 从当前目录往上找 go.mod。测试的工作目录是包目录，不是仓库根。
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("取当前目录失败: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("向上找不到 go.mod，无法定位仓库根")
		}
		dir = parent
	}
}

// importNames 把文件里的导入映射成「本文件里用的名字 -> 导入路径」，
// 这样 json.Marshal 里的 json 到底是 encoding/json 还是别的什么包，是查出来的而不是猜的。
func importNames(file *ast.File) map[string]string {
	out := make(map[string]string, len(file.Imports))
	for _, im := range file.Imports {
		p := strings.Trim(im.Path.Value, `"`)
		name := p
		if i := strings.LastIndex(p, "/"); i >= 0 {
			name = p[i+1:]
		}
		if im.Name != nil {
			name = im.Name.Name // 别名导入，例如 crand "crypto/rand"
		}
		out[name] = p
	}
	return out
}

// watchedCallName 判断这次调用是否落在 watchedCalls 里，是则返回 "包路径.函数名"。
func watchedCallName(call *ast.CallExpr, imports map[string]string) (string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	pkgIdent, ok := sel.X.(*ast.Ident)
	if !ok {
		return "", false // 形如 json.NewEncoder(w).Encode(...)，不是本表要盯的
	}
	path, ok := imports[pkgIdent.Name]
	if !ok {
		return "", false
	}
	if !watchedCalls[path][sel.Sel.Name] {
		return "", false
	}
	return path + "." + sel.Sel.Name, true
}
