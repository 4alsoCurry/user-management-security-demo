# 用户管理系统 — 安全漏洞修复演示

> 🔴 **vulnerable/** — 存在 16 项安全漏洞的原始版本
> 🟢 **secure/** — 已全部修复的安全加固版本

## 项目结构

```
user-management-security-demo/
├── README.md                    # 本文件
├── vulnerable/                  # 🔴 漏洞版（原始代码）
│   ├── app.py                   # Flask 主应用
│   ├── templates/
│   │   ├── base.html
│   │   ├── index.html
│   │   └── login.html
│   └── static/css/
│       └── style.css
├── secure/                      # 🟢 安全版（修复后）
│   ├── app.py                   # 全部安全修复
│   ├── templates/
│   │   ├── base.html
│   │   ├── index.html
│   │   ├── login.html
│   │   └── register.html        # 新增注册页
│   ├── static/css/
│   │   └── style.css
│   ├── requirements.txt
│   ├── SECURITY_FIXES.md        # 16项漏洞详细分析
│   └── README.md                # 安全版项目说明
└── .gitignore
```

## 漏洞清单（共 16 项）

| # | 漏洞 | 严重程度 |
|---|------|---------|
| 01 | 明文密码存储 | 🔴 高危 |
| 02 | 弱会话密钥 | 🔴 高危 |
| 03 | 暴力破解 / 字典攻击 | 🔴 高危 |
| 04 | 账户锁定机制缺失 | 🟠 中危 |
| 05 | 调试模式暴露（RCE） | 🟠 中危 |
| 06 | 密码泄露到前端页面 | 🔴 高危 |
| 07 | HTML 注释泄露管理员凭证 | 🔴 高危 |
| 08 | 用户名枚举（信息泄露） | 🟠 中危 |
| 09 | CSRF 跨站请求伪造 | 🟠 中危 |
| 10 | 会话固定攻击 | 🟡 低危 |
| 11 | 输入验证缺失（XSS/注入） | 🟠 中危 |
| 12 | 不安全 Cookie 设置 | 🟠 中危 |
| 13 | 无会话超时 | 🟡 低危 |
| 14 | 审计日志缺失 | 🟡 低危 |
| 15 | 密码强度不足 | 🟠 中危 |
| 16 | 无注册功能 | 🟡 低危 |

> 详细修复报告见 [`secure/SECURITY_FIXES.md`](./secure/SECURITY_FIXES.md)

## 快速启动

```bash
# 漏洞版
cd vulnerable && pip install flask && python app.py

# 安全版
cd secure && pip install -r requirements.txt && python app.py
```

访问 http://127.0.0.1:5000

## 默认账号

| 版本 | 用户名 | 密码 |
|------|--------|------|
| 🔴 漏洞版 | admin | admin123 |
| 🟢 安全版 | admin | Admin@123456 |

## 许可

MIT
