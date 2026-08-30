import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { fileURLToPath, URL } from 'node:url'

// 前端构建产物输出到 web/dist，由 Go embed 打包进最终二进制。
// 开发时通过 proxy 将 /api 与 /uploads 转发到本地后端（默认 25666 端口）。
export default defineConfig({
  // 使用相对基址，令构建产物中的 JS/CSS 引用为相对路径，
  // 从而支持部署到任意路径前缀（basePath）下而无需重新构建。
  base: './',
  plugins: [vue()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    chunkSizeWarningLimit: 1500,
  },
  server: {
    port: 5173,
    // 不能开 changeOrigin：后端 csrfGuard 拿 Origin 和 Host 比对，改写 Host 会让
    // 开发时的每个 POST 都被判成跨站（"请求来源不被允许"），登录都进不去。
    proxy: {
      '/api': { target: 'http://127.0.0.1:25666' },
      '/uploads': { target: 'http://127.0.0.1:25666' },
    },
  },
})
