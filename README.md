## Dext-Server

<p align="center">
  <img src="Dext.png" alt="Dext Logo" width="120" height="120"/>
</p>

Dext-Server 是一个基于 Go 语言和 Gin 框架实现的**问卷 / 表单与项目管理后端服务**，提供用户认证、问卷管理、答卷收集、统计分析、文件与媒体管理等一站式能力，适合作为在线问卷平台或表单系统的后端。

### 功能概览

- **用户与认证**
  - 注册 / 登录 / 登出
  - JWT 认证与多端会话管理（查看、撤销、限制会话）
  - 支持邮箱验证码登录 / 重置密码
  - 支持 Google / GitHub / Microsoft 等 OAuth 登录与绑定 / 解绑
- **项目与问卷管理**
  - 项目（`/api/project/*`）的创建、更新、删除、批量删除
  - 问卷（`/api/survey/*`）的创建、更新、删除、批量删除、详情查询
  - 问卷问题管理：新增、更新、删除、排序
- **答卷与回收站**
  - 支持登录用户提交答卷 `/api/answer/submit`
  - 物理删除、逻辑删除、批量删除答卷
  - 回收站机制：查看被逻辑删除的数据、支持单条或批量恢复  
  - 定时任务自动清理超出保留期的回收站数据
- **统计与分析**
  - 单个问卷统计、全部问卷统计
  - 最近提交记录、提交历史明细
  - 提交趋势与概览 API
- **公开访问能力**
  - 公开问卷访问与提交：`/api/public/survey/:uid`
  - 可选认证模式：携带 token 时识别当前用户，否则按匿名用户处理
- **文件与媒体管理（OpenAssets 集成）**
  - 统一的文件存储服务，支持图片 / 音视频 / 文本 / PDF 等多类型文件
  - 支持按 bucket 上传、删除、列出文件，查询文件信息和用户存储占用
  - 问卷媒体管理：问卷背景图、问卷相关图片、批量上传与删除
  - 用户头像上传与管理
- **安全与基础设施**
  - RSA 私钥初始化
  - XChaCha 加密密钥对与加解密中间件
  - JWT 密钥管理与定期轮换
  - 图形验证码（base64Captcha）
  - 跨域、中间人攻击等 HTTP 安全头设置
  - 基于 Gin 的限流中间件
  - 支持 HTTP / HTTPS、HTTP->HTTPS 自动重定向

### 技术栈

- **Runtime**
  - Go `1.24.3`
- **调用库**
  - `github.com/gin-gonic/gin`
  - MySQL（`github.com/go-sql-driver/mysql`）
  - Redis（`github.com/go-redis/redis/v8`）
  - `golang.org/x/crypto`
  - 图形验证码：`github.com/mojocn/base64Captcha`
  - 定时任务：`github.com/robfig/cron/v3`
  - 邮件发送：`github.com/resend/resend-go/v2` 或 SMTP

### 目录结构（核心部分）

仅列出与核心功能相关的关键目录，实际结构可根据仓库为准：

- `main.go`：应用入口，初始化配置、数据库、Redis、定时任务、路由与 HTTP/HTTPS 服务器
- `config/`：数据库、Redis、代理、匿名 ID 配置等
- `middleware/`：CORS、限流、安全头、加解密、认证等中间件
- `model/`：用户、项目、问卷、答卷等领域模型
- `module/user`：用户注册 / 登录 / 密码与邮箱修改、Profile 等
- `module/session`：会话管理与 JWT 中间件
- `module/project`：项目增删改查
- `module/survey`：问卷增删改查、公开访问
- `module/survey/question`：问卷问题管理
- `module/answer`：答卷提交、逻辑删除、回收站管理与清理任务
- `module/analytics`：统计与分析相关 API
- `module/email`：验证码邮件 / 通知邮件发送
- `module/oauth`：第三方登录与绑定
- `module/assets` & `module/survey/media`：通用文件服务与问卷媒体
- `SQL/`：数据库初始化与升级 SQL 脚本

### 环境准备

- **必需**
  - Go `1.24.3+`
  - MySQL 实例（建议 5.7+ 或 8.x）
  - Redis 实例
- **可选 / 视需求开启**
  - 合法的域名与 SSL 证书（开启 HTTPS 时）
  - OAuth 应用：Google / GitHub / Microsoft 等
  - 邮件服务：Resend 或标准 SMTP
  - 个推（Getui）推送账号

### 配置说明（`.env`）

参考项目根目录中的 `.env.example`，复制后重命名为 `.env` 并填入实际值：

- **数据库配置**
  - `DB_USER`：数据库用户名
  - `DB_PASSWORD`：数据库密码
  - `DB_HOST`：数据库连接地址，示例：`127.0.0.1:3306`
  - `DB_NAME`：数据库名称
- **基础运行参数**
  - `PORT`：HTTP 监听端口（默认 `11222`）
  - `ENV`：运行环境，通常为 `production` 或 `development`
- **JWT / 安全**
  - `JWT_EXPIRATION`：JWT 过期时间（如：`24h`），实际由 `security` 模块读取
- **图形验证码**
  - `CAPTCHA_LEVEL`：难度级别 `1-3`
- **HTTPS 与重定向**
  - `HTTPS_ENABLED`：是否启用 HTTPS（`true` / `false`）
  - `SSL_CERT_FILE`：证书文件路径
  - `SSL_KEY_FILE`：私钥文件路径
  - `HTTPS_PORT`：HTTPS 监听端口（默认 `443`）
  - `HTTP_REDIRECT`：是否将 HTTP 重定向到 HTTPS
- **OAuth 登录**
  - `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET`
  - `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET`
  - `MICROSOFT_CLIENT_ID` / `MICROSOFT_CLIENT_SECRET`
- **推送（Getui）**
  - `GETUI_APP_ID` / `GETUI_APP_KEY` / `GETUI_APP_SECRET` / `GETUI_MASTER_SECRET`
- **邮件服务**
  - `EMAIL_PROVIDER`：`resend` 或 `smtp`
  - 当使用 SMTP 时：
    - `SMTP_HOST` / `SMTP_PORT`
    - `SMTP_USER` / `SMTP_PASS`
    - `SMTP_FROM_NAME` / `SMTP_FROM_EMAIL`
  - 当使用 Resend 时：
    - `RESEND_API_KEY`
    - `RESEND_FROM_EMAIL`（发件地址）
    - `RESEND_REPLY_TO`（回复地址）
- **匿名用户与代理配置**
  - `ANON_ID_MODE`：`off` / `normal` / `strict`
  - `ANON_INCLUDE_PORT`：严格模式下是否将端口纳入 ID 计算
  - `TRUST_PROXY`：在有反向代理时是否从 `X-Forwarded-For` 获取真实 IP
  - `ANON_ID_SALT`：可选盐值
  - `TRUSTED_PROXIES`：可信代理列表，逗号分隔
- **回收站清理任务**
  - `RECYCLE_BIN_CLEANUP_CRON`：Cron 表达式，默认 `0 0 * * *`（每天 0 点）
  - `RECYCLE_BIN_RETENTION_DAYS`：保留天数（默认 `30`）

### 数据库初始化

项目根目录的 `SQL/` 目录中包含了数据库初始化与迁移的 SQL 文件，例如：

- `database_schema.sql`：基础表结构
- 其他 `add_*`、`fix_*`、`create_*` SQL 文件：功能更新与修复

**推荐做法：**

1. 在目标 MySQL 数据库中执行 `SQL/database_schema.sql`。
2. 按时间/命名顺序执行后续的迁移脚本（如 `add_*`, `fix_*`, `create_*` 等）。

> 提示：如果你已有线上环境，建议先在测试环境完整跑一遍所有 SQL 脚本，再在生产环境按顺序执行，避免结构不一致。

### 启动项目

1. 确保已安装 Go、MySQL、Redis，并在本机或网络可访问。
2. 在项目根目录复制 `.env.example` 为 `.env`，并根据实际环境修改配置。
3. 拉取依赖（可选）：

   ```bash
   go mod tidy
   ```

4. 运行服务：

   ```bash
   go run main.go
   ```

5. 默认情况下，服务会监听 `PORT` 对应端口（如 `11222`）。  
   可以通过浏览器或 `curl` 访问健康检查接口：

   ```bash
   curl http://127.0.0.1:11222/ping
   ```

   返回：

   ```json
   {"message": "pong"}
   ```

### API 概览（部分）

- 健康检查：`GET /ping`
- 获取服务器 XChaCha 公钥：`GET /api/crypto/public-key`
- 图形验证码：
  - `POST /api/getCaptcha`
  - `POST /api/verifyCaptcha`
- 用户与认证：
  - `POST /api/auth/register`
  - `POST /api/auth/login`
  - `POST /api/auth/refresh`
  - `POST /api/auth/logout`
  - `POST /api/auth/oauth`
  - `GET  /api/auth/oauth/:provider/url`
- 会话管理（需登录）：
  - `GET    /api/sessions`
  - `DELETE /api/sessions/:session_id`
  - `POST   /api/sessions/revoke-all`
  - `POST   /api/sessions/limit`
- 问卷公开访问：
  - `GET  /api/public/survey/:uid`
  - `POST /api/public/survey/:uid/submit`

更多接口可参考各 `module/*/handler.go` 文件中的路由定义。

### 生产部署建议

- 使用反向代理（Nginx / Caddy 等）托管 HTTPS，或正确配置 `HTTPS_ENABLED` 与证书路径。
- 为 MySQL、Redis 设置强密码与访问控制，原则上只允许应用服务器访问。
- 定期备份数据库与 `assets_storage` 目录中的用户上传文件。
- 根据业务访问量调整 `RateLimitMiddleware` 与 Redis 配置，防止刷接口与滥用。
- 在生产环境使用 `ENV=production` 并开启适当日志轮转。

---