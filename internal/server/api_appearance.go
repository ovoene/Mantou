package server

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"mantou/internal/config"
)

// handleGetAppearance 返回当前外观配置。
func (s *Server) handleGetAppearance(c *gin.Context) {
	cfg := s.deps.Config.Snapshot()
	respondOK(c, cfg.Settings.Appearance)
}

// handleUpdateAppearance 覆盖保存外观配置（对应需求 §6.6）。
// 前端传入完整的 Appearance 对象，这里做基本范围校验后整体替换。
func (s *Server) handleUpdateAppearance(c *gin.Context) {
	var in config.Appearance
	if err := c.ShouldBindJSON(&in); err != nil {
		respondError(c, http.StatusBadRequest, "请求参数无效")
		return
	}
	sanitizeAppearance(&in)

	// 保存前快照旧的背景引用：仅当旧值为 data/uploads 物理文件引用，且与新值不同
	// （换图或改为渐变）时，才在配置落盘后回收旧文件。
	old := s.deps.Config.Snapshot().Settings.Appearance.Background

	err := s.deps.Config.Update(func(cfg *config.Config) {
		cfg.Settings.Appearance = in
	})
	if err != nil {
		respondError(c, http.StatusInternalServerError, "保存外观失败")
		return
	}

	// 关键：先确保新配置已成功落盘，再删除旧背景图文件。
	// 这样即便删文件失败，配置仍指向有效的新图；不会出现「旧图已删、新图未落盘」的孤儿/断引用。
	if s.deps.DataDir != "" &&
		strings.HasPrefix(old.Value, "/uploads/") && old.Value != in.Background.Value {
		_ = removeBackgroundFile(s.deps.DataDir, old.Value)
	}

	respondOK(c, in)
}

// sanitizeAppearance 修正越界数值，避免前端异常值破坏界面。
func sanitizeAppearance(a *config.Appearance) {
	if a.ThemeMode != "light" && a.ThemeMode != "dark" && a.ThemeMode != "auto" {
		a.ThemeMode = "auto"
	}

	a.Background.Blur = clampInt(a.Background.Blur, 0, 40)
	a.Background.OverlayOpacity = clampFloat(a.Background.OverlayOpacity, 0, 1)

	a.Card.Opacity = clampFloat(a.Card.Opacity, 0, 1)
	a.Card.Blur = clampInt(a.Card.Blur, 0, 40)
	a.Card.Radius = clampInt(a.Card.Radius, 0, 40)

	if a.Font.Scale == 0 {
		a.Font.Scale = 1
	}
	a.Font.Scale = clampFloat(a.Font.Scale, 0.8, 1.6)
	if a.Font.Weight != 0 {
		a.Font.Weight = clampInt(a.Font.Weight, 300, 700)
	}
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func clampFloat(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
