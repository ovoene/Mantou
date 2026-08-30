package server

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// 面板所有请求体的上限。
//
// 为什么必须由入口统一设定，而不是每个处理器各自判断：面板有二十多处
// c.ShouldBindJSON，其中 /auth/login 与 /init/setup 位于鉴权之前，任何人都能到达。
// 单个请求分配多少内存由对方的 Content-Length 决定，聚合量还要再乘并发数——
// 两个乘数都没有上限时，千兆链路上几条请求就能把进程打掉。而打掉的不只是面板：
// 证书续期、DDNS、端口转发、反向代理、消息路由都在同一个进程里。
//
// 登录接口自带失败计数与限流，但那是**解析完请求体之后**才生效的，对"一个请求
// 分配 2 GB"这件事没有任何作用。
//
// 逐个接口去加同样挡不住这件事：本项目二十多处绑定里一处都没加，这就是"靠纪律"
// 不成立的证据。新增接口的人不需要知道这条规则，忘了也不会有缺口。
const (
	// panelBodyLimit 默认上限。面板的常规请求都是表单级 JSON：设置整段提交
	//（含最多 60 个重启日期）、消息路由的接收器与规则、粘贴导入的证书 PEM，
	// 最大的一类是后者——1 MiB 的 PEM 相当于几百张证书串在一起，余量足够。
	panelBodyLimit = 1 << 20

	// bodyLimitSlack 上传型接口在文件本身之外的余量：multipart 的分隔串与各部分头部、
	// 以及同一份表单里的其他字段（导入备份带着口令与模块选择）。
	// 给得宽松一些，是因为算错这个数的后果是"正常上传被拦"，而拦不住的量只有 1 MiB。
	bodyLimitSlack = 1 << 20
)

// limitRequestBody 给每个请求的 Body 套上 http.MaxBytesReader。
//
// 上限按路由取：默认 panelBodyLimit，上传型路由用 registerUpload 登记过的值。
// 超限时读取方拿到 error，处理器照原路返回 400——请求体读不完整与格式不对，
// 对调用方的下一步动作是同一件事（重发一个更小的请求），不值得为它单开一条状态码分支。
func (s *Server) limitRequestBody() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Body != nil {
			limit := int64(panelBodyLimit)
			if n, ok := s.bodyLimits[c.FullPath()]; ok {
				limit = n
			}
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit)
		}
		c.Next()
	}
}

// registerUpload 注册一条上传型路由，同时登记它的请求体上限。
//
// 路径只出现一次：注册与登记在同一行完成，不会出现"路由改了名、上限还挂在旧路径上"
// 这种只在上传大文件时才暴露的漂移。g.BasePath() 已含访问路径前缀与 /api，
// 拼出来的键与 c.FullPath() 相同。
func (s *Server) registerUpload(g *gin.RouterGroup, path string, limit int64, h gin.HandlerFunc) {
	full := g.BasePath() + path
	s.bodyLimits[full] = limit
	g.POST(path, h)
}
