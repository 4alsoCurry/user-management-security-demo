# 安全漏洞修复报告

> **原始项目存在 16 项安全漏洞，以下逐一分析并说明修复方法。**
> 本项目演示了常见的 Web 安全风险及其防御措施，适用于信息安全课程作业。

---

## 🔴 高危漏洞

### 01. 明文密码存储

| 项目 | 内容 |
|------|------|
| **漏洞描述** | 用户密码以明文形式存储在 `USERS` 字典中，数据库文件或源码泄露即导致所有账号密码暴露 |
| **攻击方式** | 攻击者获取源码或备份文件后，可直接读取所有用户的明文密码 |
| **修复方法** | 使用 `werkzeug.security.generate_password_hash()` 对密码进行加盐哈希存储，验证时使用 `check_password_hash()` 比对 |
| **修复代码** | `app.py:194` — `u["password"] = generate_password_hash(u["password"])` |

### 02. 弱会话密钥

| 项目 | 内容 |
|------|------|
| **漏洞描述** | `secret_key` 硬编码为 `"dev-key-2025"`，攻击者可伪造任意用户的 session cookie |
| **攻击方式** | 使用 Flask session 解码工具解析 cookie，用已知密钥伪造登录态 |
| **修复方法** | 使用 `secrets.token_hex(32)` 自动生成 64 位随机十六进制密钥，支持通过环境变量覆盖 |
| **修复代码** | `app.py:43` — `app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))` |

### 03. 暴力破解 / 字典攻击

| 项目 | 内容 |
|------|------|
| **漏洞描述** | 无登录频率限制，攻击者可无限次尝试密码（Burp Suite Intruder / Hydra 等工具自动化爆破） |
| **攻击方式** | 使用字典文件，对 `/login` 接口发送大量 POST 请求，遍历常见密码 |
| **修复方法** | 实现基于 IP 的速率限制器（滑动窗口算法）：每 IP 每分钟最多 10 次登录尝试 |
| **修复代码** | `app.py:75-92` — `RateLimiter` 类，`login_limiter = RateLimiter(max_requests=10, window_seconds=60)` |

### 06. 密码泄露到前端

| 项目 | 内容 |
|------|------|
| **漏洞描述** | 登录后将用户完整信息（含密码）传递给模板并渲染到 HTML 页面，任何能查看页面的人都能看到密码 |
| **攻击方式** | 查看网页源码或通过开发者工具即可看到明文密码 |
| **修复方法** | 渲染模板前使用 `.pop("password", None)` 移除密码字段，仅传递非敏感信息 |
| **修复代码** | `app.py:233` — `user_info.pop("password", None)` |

### 07. HTML 注释泄露凭证

| 项目 | 内容 |
|------|------|
| **漏洞描述** | `login.html` 顶部 HTML 注释中写死了管理员账号密码：「调试信息 - 默认管理员账号 用户名: admin 密码: admin123」 |
| **攻击方式** | 查看网页源码即可获取管理员凭证 |
| **修复方法** | 彻底删除所有包含敏感信息的 HTML 注释 |

---

## 🟠 中危漏洞

### 04. 账户锁定机制缺失

| 项目 | 内容 |
|------|------|
| **漏洞描述** | 单用户可被无限尝试密码，攻击者可对特定账号进行定向爆破 |
| **攻击方式** | 固定用户名（如 admin），批量尝试不同密码 |
| **修复方法** | 实现 `AccountLocker` 类：5 次连续登录失败后锁定该账户 15 分钟 |
| **修复代码** | `app.py:95-124` — `AccountLocker` 类，`account_locker = AccountLocker(max_attempts=5, lockout_minutes=15)` |

### 05. 调试模式暴露

| 项目 | 内容 |
|------|------|
| **漏洞描述** | `debug=True` 开启 Werkzeug 调试器，攻击者可通过控制台执行任意 Python 代码（RCE） |
| **攻击方式** | 访问 `/console` 获取调试器 PIN，或利用调试器交互式执行系统命令 |
| **修复方法** | 默认关闭调试模式，通过环境变量 `FLASK_DEBUG=1` 控制 |
| **修复代码** | `app.py:54` — `DEBUG = os.environ.get('FLASK_DEBUG', '0') == '1'`，`app.run(debug=DEBUG, ...)` |

### 08. 用户名枚举（信息泄露）

| 项目 | 内容 |
|------|------|
| **漏洞描述** | 原代码对不同情况返回不同错误信息，攻击者可通过错误提示判断用户名是否存在 |
| **攻击方式** | 先批量尝试用户名，若返回"密码错误"说明用户存在；返回"用户不存在"则跳过 |
| **修复方法** | 统一错误提示为"用户名或密码错误"，不区分用户是否存在 |
| **修复代码** | `app.py:267` — `error = "用户名或密码错误"`（只有这一条错误信息） |

### 09. CSRF 跨站请求伪造

| 项目 | 内容 |
|------|------|
| **漏洞描述** | 登录表单无 CSRF 令牌，攻击者可构造恶意页面诱导用户提交登录请求 |
| **攻击方式** | 在第三方站点构造隐藏表单，利用用户已登录的浏览器自动提交 |
| **修复方法** | 使用 `secrets.token_hex(32)` 生成 CSRF 令牌存入 session，表单渲染时加入隐藏字段，提交时验证 |
| **修复代码** | `app.py:133-146` — `generate_csrf_token()` 和 `validate_csrf_token()` 函数 |

### 11. 输入验证缺失

| 项目 | 内容 |
|------|------|
| **漏洞描述** | 未对用户名和密码进行校验，可传入超长字符串或特殊字符（XSS / SQL 注入风险） |
| **攻击方式** | 在用户名字段写入 `<script>alert(1)</script>` 触发 XSS，或超长字符串导致 DoS |
| **修复方法** | 实现 `sanitize_input()` 函数：去除首尾空格、限制最大长度、过滤特殊字符 |
| **修复代码** | `app.py:210-216` — `sanitize_input()` 函数 |

### 12. 不安全 Cookie 设置

| 项目 | 内容 |
|------|------|
| **漏洞描述** | Session cookie 未设置 HttpOnly 和 SameSite 属性，存在 XSS 窃取 cookie 和 CSRF 风险 |
| **攻击方式** | XSS 脚本通过 `document.cookie` 读取 session cookie；跨站请求自动携带 cookie |
| **修复方法** | 设置 `SESSION_COOKIE_HTTPONLY=True`、`SESSION_COOKIE_SAMESITE='Lax'` |
| **修复代码** | `app.py:49-50` — 会话安全配置 |

### 15. 密码强度不足

| 项目 | 内容 |
|------|------|
| **漏洞描述** | 允许设置"admin123"等简单密码，易被字典攻击破解 |
| **攻击方式** | 使用常用密码字典（RockYou 等）进行爆破 |
| **修复方法** | 实现 `validate_password_strength()`：要求密码至少 8 位、包含字母和数字 |
| **修复代码** | `app.py:152-159` — `validate_password_strength()` 函数；注册页面也应用了该校验 |

---

## 🟡 低危漏洞

### 10. 会话固定攻击

| 项目 | 内容 |
|------|------|
| **漏洞描述** | 登录成功后不重新生成 session ID，攻击者可预先设置 session ID 诱导用户登录 |
| **攻击方式** | 发送带有已知 session ID 的链接给用户，用户登录后攻击者使用同一 session ID 劫持会话 |
| **修复方法** | 登录成功后调用 `session.clear()` 并重新设置 `session["username"]` |
| **修复代码** | `app.py:250-253` — `session.clear(); session.permanent = True; session["username"] = username` |

### 13. 无会话超时

| 项目 | 内容 |
|------|------|
| **漏洞描述** | Session 永不过期，用户离开后攻击者可继续使用遗留的 session cookie |
| **攻击方式** | 获取用户曾使用过的 cookie（公共电脑、网络嗅探等），直接复用 |
| **修复方法** | 设置 `PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)`，启用 `session.permanent = True` |
| **修复代码** | `app.py:51-53` — 会话超时配置 |

### 14. 审计日志缺失

| 项目 | 内容 |
|------|------|
| **漏洞描述** | 无登录成功/失败记录，安全事件发生后无法溯源 |
| **攻击方式** | 攻击者可悄无声息地尝试爆破，管理员无从知晓 |
| **修复方法** | 配置 Python logging，记录所有登录/登出/失败事件到 `security.log` 和控制台 |
| **修复代码** | `app.py:28-35` — 日志配置；各路由中的 `logger.info/warning` 调用 |

### 16. 无注册页面（功能缺失）

| 项目 | 内容 |
|------|------|
| **漏洞描述** | 原项目无注册功能，所有用户硬编码在代码中，无法扩展 |
| **攻击方式** | 非功能性漏洞，但限制了项目的可用性 |
| **修复方法** | 新增注册页面，包含用户名唯一性检查、密码强度校验、CSRF 保护、速率限制 |
| **修复代码** | `templates/register.html` + `app.py:275-316` — `register()` 路由 |

---

## 补充防护措施

### HTTP 状态码

- 频率超限返回 `429 Too Many Requests`（RFC 6585）
- 页面不存在返回 `404 Not Found`
- 服务器错误返回 `500 Internal Server Error`

### 安全响应头（未来可扩展）

建议在生产环境中添加以下响应头（可通过 Flask 中间件或 Nginx）：

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'self'
```

---

## 测试方法

可以使用以下工具验证修复效果：

```bash
# 1. Burp Suite - 测试暴力破解
#    → 发送10次以上请求，第11次应返回429

# 2. CSRF 测试
#    → 提交不含 _csrf_token 的POST请求应被拒绝

# 3. 密码哈希验证
#    → 查看 app.py 中 USERS 字典，密码为哈希值

# 4. 信息泄露测试
#    → 对不存在的用户发送登录，提示应与存在用户一致
```
