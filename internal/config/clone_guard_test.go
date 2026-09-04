package config

import (
	"reflect"
	"strings"
	"testing"
)

// TestConfigStaysJSONSafe 是 A-2 的护栏：Config 的类型图里不允许出现 json.Marshal 会拒绝的类型。
//
// 背景：clone() 用 JSON 往返做深拷贝，而 Update / UpdateState 会把克隆结果落盘并换进内存。
// clone 现在会把错误返回上去（那两条路遇错即放弃，不落盘不换内存），但更可靠的是让这个错误
// 根本不可能发生——只要 Config 的字段类型全部可序列化，Marshal 就不会失败。
//
// 这条断言把"当前恰好没有不可序列化字段"从一个巧合变成一条会在 CI 里报警的规则：
// 谁给 Config 加一个 any / chan / func 字段，这里就红，而不是等到某次保存设置时静默清空配置。
//
// 例外：float64 是允许的（Config 里有三个），因为 JSON 入口本身就拒绝 NaN/Inf 字面量，
// 它们只能通过 JSON 赋值进来。
func TestConfigStaysJSONSafe(t *testing.T) {
	seen := map[reflect.Type]bool{}
	var walk func(t reflect.Type, path string) []string
	walk = func(rt reflect.Type, path string) []string {
		if seen[rt] {
			return nil
		}
		seen[rt] = true
		var bad []string
		switch rt.Kind() {
		case reflect.Chan, reflect.Func, reflect.UnsafePointer,
			reflect.Complex64, reflect.Complex128, reflect.Interface:
			return []string{path + " (" + rt.Kind().String() + ")"}
		case reflect.Ptr, reflect.Slice, reflect.Array:
			bad = append(bad, walk(rt.Elem(), path+"[]")...)
		case reflect.Map:
			bad = append(bad, walk(rt.Key(), path+"{key}")...)
			bad = append(bad, walk(rt.Elem(), path+"{val}")...)
		case reflect.Struct:
			for i := 0; i < rt.NumField(); i++ {
				f := rt.Field(i)
				if !f.IsExported() {
					// 未导出字段不参与 JSON 往返，但也意味着它**不会被 clone 拷贝**。
					// Config 上不该有这种字段，顺手一起钉住。
					bad = append(bad, path+"."+f.Name+" (未导出，clone 会丢掉它)")
					continue
				}
				bad = append(bad, walk(f.Type, path+"."+f.Name)...)
			}
		}
		return bad
	}
	if bad := walk(reflect.TypeOf(Config{}), "Config"); len(bad) > 0 {
		t.Errorf("Config 含 JSON 不安全或不会被 clone 拷贝的字段：\n  %s", strings.Join(bad, "\n  "))
	}
}

// TestCloneRoundTripsFullConfig 深拷贝必须无损：出厂默认配置克隆一遍应当完全相等。
// 这条同时钉住"clone 不返回错误"这个正常路径。
func TestCloneRoundTripsFullConfig(t *testing.T) {
	src := Default()
	dst, err := src.clone()
	if err != nil {
		t.Fatalf("克隆默认配置失败: %v", err)
	}
	if !configEqual(src, dst) {
		t.Error("克隆结果与源配置不相等，深拷贝有损")
	}
	// 副本必须真的独立：改副本不应影响源。
	dst.Panel.Port = src.Panel.Port + 1
	if src.Panel.Port == dst.Panel.Port {
		t.Error("clone 返回的不是独立副本")
	}
}
