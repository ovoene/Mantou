package config

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// 这一条钉住 F-06：data 目录及其下每一层都必须是 0700。
//
// 为什么要用扫描而不是几条单点断言：这个权限位原先散在五处（data 根、配置、日志、
// 证书、上传），每处一个 os.MkdirAll(…, 0o755)。真正的风险不是这五处改不对，
// 而是**第六处**——将来谁加一个新的数据目录，照着周围的写法写下 0o755，
// 不会有任何测试变红，也不会有任何症状：面板照跑，只是那一层一直敞着。
// 所以规则定成「生产代码里创建目录一律用 fsx.DirMode」，由这条测试来守。
//
// 放在 internal/config 是因为扫描工具（productionGoFiles / importNames，见
// silentfail_guard_test.go）在这个包里，跨包用不上；它扫的是整个仓库，与本包无关。
//
// 与 os.MkdirTemp 无关：那个函数固定按 0700 建，本来就是对的。

// dirModeExempt 允许豁免的调用点（键为 "相对路径:行号"）。
//
// 现在是空的：全仓每一处建目录都该是 0700。真有例外（比如某个必须让另一个用户
// 读到的导出目录），在这里登记并在调用点旁写清理由——让豁免留下痕迹，
// 而不是把 0o755 直接写回代码里。
var dirModeExempt = map[string]bool{}

// TestDataDirsUsePrivateMode 禁止生产代码用字面量权限位创建目录。
func TestDataDirsUsePrivateMode(t *testing.T) {
	var bad []string
	for _, f := range productionGoFiles(t) {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, f.abs, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("解析 %s 失败: %v", f.rel, err)
		}
		bad = append(bad, scanDirModes(fset, file, f.rel)...)
	}
	if len(bad) > 0 {
		t.Errorf("以下建目录的调用没有用 fsx.DirMode（共 %d 处）：\n  %s\n"+
			"data 目录下的每一层都得是 0700——里面有 master.key、证书私钥、日志与上传文件，"+
			"目录一敞开，同机的其他用户不必读文件就能看清面板管着什么。\n"+
			"新建目录请改用 fsx.EnsureDir（它还会顺手收紧已存在的目录）；确有例外则登记到 dirModeExempt。",
			len(bad), strings.Join(bad, "\n  "))
	}
}

// TestDirModeGuardCatchesLiteral 这条查的是上面那条本身。
//
// 全仓当前一处不违规，于是 TestDataDirsUsePrivateMode 是"什么都没扫到"与"扫到了但都合规"
// 两种情况都会绿。前者才是真正要防的失效方式——某天 isOSMkdirCall 认包名的那一段
// 稍一改就可能永远返回假，而那条测试照样通过，直到某次审计才发现它早就不看了。
func TestDirModeGuardCatchesLiteral(t *testing.T) {
	cases := []struct {
		name     string
		src      string
		wantFlag bool
	}{
		{"字面量权限位", `package p
import "os"
func f(p string) error { return os.MkdirAll(p, 0o755) }`, true},
		{"就算已经是 0700 也要用常量", `package p
import "os"
func f(p string) error { return os.MkdirAll(p, 0o700) }`, true},
		{"os.Mkdir 同样算", `package p
import "os"
func f(p string) error { return os.Mkdir(p, 0o755) }`, true},
		{"改名导入也认得出", `package p
import stdos "os"
func f(p string) error { return stdos.MkdirAll(p, 0o755) }`, true},
		{"用 fsx.DirMode", `package p
import (
	"os"

	"mantou/internal/fsx"
)
func f(p string) error { return os.MkdirAll(p, fsx.DirMode) }`, false},
		{"fsx 包内的裸 DirMode", `package fsx
import "os"
func f(p string) error { return os.MkdirAll(p, DirMode) }`, false},
		// MkdirTemp 固定 0700，不在管辖范围内。
		{"MkdirTemp 不管", `package p
import "os"
func f(d string) (string, error) { return os.MkdirTemp(d, "stage-") }`, false},
		// 同名方法不能误伤：认的是导入路径 "os"，不是"叫 os 的那个东西"。
		{"别的包的同名方法", `package p
type fake struct{}
func (fake) MkdirAll(p string, m uint32) error { return nil }
func f(os fake, p string) error { return os.MkdirAll(p, 0o755) }`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "x.go", tc.src, parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			got := scanDirModes(fset, file, "x.go")
			if tc.wantFlag && len(got) == 0 {
				t.Fatal("这段代码该被判违规，实际没扫出来")
			}
			if !tc.wantFlag && len(got) > 0 {
				t.Fatalf("这段代码不该被判违规，实际扫出 %v", got)
			}
		})
	}
}

// scanDirModes 返回一个文件里所有"建目录却没用 fsx.DirMode"的位置。
func scanDirModes(fset *token.FileSet, file *ast.File, rel string) []string {
	imports := importNames(file)
	// fsx 包自己写的是不带包名的 DirMode。
	inFsx := file.Name.Name == "fsx"

	var bad []string
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !isOSMkdirCall(call, imports) || len(call.Args) < 2 {
			return true
		}
		where := rel + ":" + strconv.Itoa(fset.Position(call.Pos()).Line)
		if dirModeExempt[where] || isPrivateDirMode(call.Args[1], imports, inFsx) {
			return true
		}
		bad = append(bad, where+"  "+exprText(call.Args[1]))
		return true
	})
	return bad
}

// isOSMkdirCall 判断这次调用是不是 os.Mkdir / os.MkdirAll（按导入路径认，不认名字）。
func isOSMkdirCall(call *ast.CallExpr, imports map[string]string) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	if imports[pkg.Name] != "os" {
		return false
	}
	return sel.Sel.Name == "Mkdir" || sel.Sel.Name == "MkdirAll"
}

// isPrivateDirMode 判断权限参数是不是 fsx.DirMode（在 fsx 包内则是裸的 DirMode）。
func isPrivateDirMode(arg ast.Expr, imports map[string]string, inFsx bool) bool {
	switch e := arg.(type) {
	case *ast.SelectorExpr:
		pkg, ok := e.X.(*ast.Ident)
		return ok && imports[pkg.Name] == "mantou/internal/fsx" && e.Sel.Name == "DirMode"
	case *ast.Ident:
		return inFsx && e.Name == "DirMode"
	}
	return false
}

// exprText 把表达式还原成一小段可读文本，用在失败信息里指认写了什么。
func exprText(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.BasicLit:
		return v.Value
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		if pkg, ok := v.X.(*ast.Ident); ok {
			return pkg.Name + "." + v.Sel.Name
		}
		return v.Sel.Name
	}
	return "（表达式）"
}
