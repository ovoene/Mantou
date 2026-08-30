package server

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"mantou/internal/config"
	"mantou/internal/logx"
)

func TestHandleImportConfigRejectsPlaintext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	manager := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	if err := manager.Update(func(cfg *config.Config) {
		cfg.Auth.Initialized = true
		cfg.Auth.Username = "original"
		cfg.Auth.PasswordHash = "original-hash"
		cfg.Auth.JWTSecret = "original-secret"
	}); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "direct plaintext config", body: `{"auth":{"initialized":true,"username":"attacker","passwordHash":"known-hash","jwtSecret":"known-secret"}}`},
		{name: "wrapped plaintext config", body: `{"config":{"auth":{"initialized":true,"username":"attacker","passwordHash":"known-hash","jwtSecret":"known-secret"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requestBody bytes.Buffer
			writer := multipart.NewWriter(&requestBody)
			part, err := writer.CreateFormFile("file", "config.json")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := part.Write([]byte(tc.body)); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}

			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			ctx.Request = httptest.NewRequest(http.MethodPost, "/api/settings/import", &requestBody)
			ctx.Request.Header.Set("Content-Type", writer.FormDataContentType())
			server := &Server{deps: Deps{Config: manager, Log: logx.New(logx.Options{})}}
			server.handleImportConfig(ctx)

			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("unexpected status: %d, body: %s", recorder.Code, recorder.Body.String())
			}
			if !strings.Contains(recorder.Body.String(), "不允许导入未加密的配置文件") {
				t.Fatalf("unexpected response: %s", recorder.Body.String())
			}
			got := manager.Get()
			if got.Auth.Username != "original" || got.Auth.PasswordHash != "original-hash" || got.Auth.JWTSecret != "original-secret" {
				t.Fatalf("authentication config changed after rejected import: %+v", got.Auth)
			}
		})
	}
}
