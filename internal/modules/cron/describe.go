package cron

import (
	"fmt"
	"strconv"
	"strings"
)

// Describe 将标准 5 段 cron 表达式（分 时 日 月 周）翻译为人类可读描述。
// lang 取 "en" 时返回英文，其余（含 "zh-CN"）返回中文。
// 对无法识别的复杂表达式，回退为原样返回表达式本身。
func Describe(expr, lang string) string {
	en := strings.HasPrefix(strings.ToLower(lang), "en")
	fields := strings.Fields(strings.TrimSpace(expr))
	if len(fields) != 5 {
		return expr
	}
	minute, hour, dom, month, dow := fields[0], fields[1], fields[2], fields[3], fields[4]

	// 仅当月份不限时才尝试识别常见模式。
	if month == "*" {
		// 每 N 分钟：*/N * * * *
		if strings.HasPrefix(minute, "*/") && hour == "*" && dom == "*" && dow == "*" {
			if n, err := strconv.Atoi(strings.TrimPrefix(minute, "*/")); err == nil && n > 0 {
				if en {
					return fmt.Sprintf("Every %d minute(s)", n)
				}
				return fmt.Sprintf("每 %d 分钟", n)
			}
		}
		// 每 N 小时：0 */N * * *
		if minute == "0" && strings.HasPrefix(hour, "*/") && dom == "*" && dow == "*" {
			if n, err := strconv.Atoi(strings.TrimPrefix(hour, "*/")); err == nil && n > 0 {
				if en {
					return fmt.Sprintf("Every %d hour(s)", n)
				}
				return fmt.Sprintf("每 %d 小时", n)
			}
		}
		// 每分钟：* * * * *
		if minute == "*" && hour == "*" && dom == "*" && dow == "*" {
			if en {
				return "Every minute"
			}
			return "每分钟"
		}
		// 每小时的第 M 分钟：M * * * *
		if isNum(minute) && hour == "*" && dom == "*" && dow == "*" {
			if en {
				return fmt.Sprintf("At minute %s of every hour", minute)
			}
			return fmt.Sprintf("每小时的第 %s 分钟", minute)
		}
		// 时刻类：分、时均为具体数字
		if isNum(minute) && isNum(hour) {
			hm := clock(hour, minute)
			// 每天 HH:MM
			if dom == "*" && dow == "*" {
				if en {
					return "Every day at " + hm
				}
				return "每天 " + hm
			}
			// 每周[…] HH:MM
			if dom == "*" && dow != "*" {
				days := weekdays(dow, en)
				if en {
					return fmt.Sprintf("Every %s at %s", days, hm)
				}
				return fmt.Sprintf("每周%s %s", days, hm)
			}
			// 每月 D 日 HH:MM
			if isNum(dom) && dow == "*" {
				if en {
					return fmt.Sprintf("On day %s of every month at %s", dom, hm)
				}
				return fmt.Sprintf("每月 %s 日 %s", dom, hm)
			}
		}
	}
	// 无法识别，回退为原表达式。
	return expr
}

// isNum 判断字段是否为单一非负整数。
func isNum(s string) bool {
	if s == "" {
		return false
	}
	_, err := strconv.Atoi(s)
	return err == nil
}

// clock 将 时、分 组合为零填充的 HH:MM。
func clock(hour, minute string) string {
	h, _ := strconv.Atoi(hour)
	m, _ := strconv.Atoi(minute)
	return fmt.Sprintf("%02d:%02d", h, m)
}

// weekdays 把逗号分隔的星期字段（0-6，0=周日）翻译为可读列表。
func weekdays(field string, en bool) string {
	zh := []string{"日", "一", "二", "三", "四", "五", "六"}
	enNames := []string{"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"}
	parts := strings.Split(field, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 6 {
			return field // 含范围/步进等复杂写法，原样返回
		}
		if en {
			out = append(out, enNames[n])
		} else {
			out = append(out, "周"+zh[n])
		}
	}
	if en {
		return strings.Join(out, ", ")
	}
	return strings.Join(out, "、")
}
