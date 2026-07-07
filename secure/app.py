import os
import re
import secrets
import logging
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict

from flask import (
    Flask, render_template, request, redirect,
    session, url_for, flash, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash

# ============================================================
# 日志配置 / Audit Logging
# ============================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('security.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ============================================================
# Flask 应用初始化
# ============================================================
app = Flask(__name__)

# ---------- 会话密钥 ----------
app.secret_key = os.environ.get(
    'SECRET_KEY',
    secrets.token_hex(32)  # 不再硬编码弱密钥
)

# ---------- 会话安全配置 ----------
app.config['SESSION_COOKIE_HTTPONLY'] = True    # 禁止 JavaScript 读取 cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'   # 防止 CSRF 跨站发送 cookie
app.config['SESSION_COOKIE_SECURE'] = False      # 生产环境应设为 True（HTTPS）
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # 会话超时
app.config['SESSION_REFRESH_EACH_REQUEST'] = True

# ---------- 调试模式（由环境变量控制） ----------
DEBUG = os.environ.get('FLASK_DEBUG', '0') == '1'


# ============================================================
# 安全工具类
# ============================================================

class RateLimiter:
    """基于滑动窗口的 IP 级别速率限制器"""

    def __init__(self, max_requests=5, window_seconds=60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests = defaultdict(list)  # ip -> [datetime, ...]

    def is_allowed(self, ip):
        now = datetime.now()
        cutoff = now - timedelta(seconds=self.window_seconds)

        # 清理过期记录
        self._requests[ip] = [t for t in self._requests[ip] if t > cutoff]

        if len(self._requests[ip]) >= self.max_requests:
            return False

        self._requests[ip].append(now)
        return True

    def remaining(self, ip):
        cutoff = datetime.now() - timedelta(seconds=self.window_seconds)
        self._requests[ip] = [t for t in self._requests[ip] if t > cutoff]
        return max(0, self.max_requests - len(self._requests[ip]))


class AccountLocker:
    """账户锁定机制 - 记录失败次数并临时锁定"""

    def __init__(self, max_attempts=5, lockout_minutes=15):
        self.max_attempts = max_attempts
        self.lockout_minutes = lockout_minutes
        self._attempts = defaultdict(list)   # username -> [datetime, ...]
        self._locks = {}                     # username -> datetime (locked_until)

    def record_failure(self, username):
        now = datetime.now()
        self._attempts[username].append(now)

        # 清理窗口外的旧记录
        cutoff = now - timedelta(minutes=self.lockout_minutes)
        self._attempts[username] = [t for t in self._attempts[username] if t > cutoff]

        # 达到阈值 -> 锁定
        if len(self._attempts[username]) >= self.max_attempts:
            self._locks[username] = now + timedelta(minutes=self.lockout_minutes)
            logger.warning(f"账户已被锁定 | 用户名: {username} | 锁定时长: {self.lockout_minutes}分钟")

    def is_locked(self, username):
        if username not in self._locks:
            return False
        if datetime.now() > self._locks[username]:
            del self._locks[username]
            self._attempts[username] = []
            return False
        return True

    def reset(self, username):
        self._attempts[username] = []
        self._locks.pop(username, None)

    def remaining_attempts(self, username):
        cutoff = datetime.now() - timedelta(minutes=self.lockout_minutes)
        self._attempts[username] = [t for t in self._attempts[username] if t > cutoff]
        return max(0, self.max_attempts - len(self._attempts[username]))


# ============================================================
# CSRF 防护
# ============================================================

def generate_csrf_token():
    """生成并存储 CSRF 令牌到 session"""
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']

def validate_csrf_token():
    """验证 CSRF 令牌"""
    token = request.form.get('_csrf_token', '')
    stored_token = session.pop('_csrf_token', None)
    if not stored_token or not secrets.compare_digest(stored_token, token):
        logger.warning(f"CSRF 验证失败 | IP: {request.remote_addr}")
        return False
    return True


# ============================================================
# 密码强度校验
# ============================================================

def validate_password_strength(password):
    """校验密码强度，返回 (is_valid, error_message)"""
    if len(password) < 8:
        return False, "密码长度至少为 8 位"
    if not re.search(r'[A-Za-z]', password):
        return False, "密码必须包含至少一个字母"
    if not re.search(r'[0-9]', password):
        return False, "密码必须包含至少一个数字"
    return True, ""


# ============================================================
# 实例化安全组件
# ============================================================
login_limiter = RateLimiter(max_requests=10, window_seconds=60)   # 每分钟每个 IP 最多 10 次
register_limiter = RateLimiter(max_requests=3, window_seconds=300) # 每 5 分钟每个 IP 最多 3 次注册
account_locker = AccountLocker(max_attempts=5, lockout_minutes=15) # 5 次失败锁定 15 分钟


# ============================================================
# 用户数据库（密码经过哈希处理）
# ============================================================
USERS = {}

def init_users():
    """初始化用户数据，密码使用 werkzeug 哈希存储"""
    raw_users = [
        {
            "username": "admin",
            "password": "Admin@123456",
            "role": "admin",
            "email": "admin@example.com",
            "phone": "13800138000",
            "balance": 99999
        },
        {
            "username": "alice",
            "password": "Alice@2025",
            "role": "user",
            "email": "alice@example.com",
            "phone": "13900139001",
            "balance": 100
        }
    ]
    for u in raw_users:
        u["password"] = generate_password_hash(u["password"])
        USERS[u["username"]] = u

    logger.info(f"用户数据库初始化完成 | 共 {len(USERS)} 个用户")


# ============================================================
# 输入过滤工具
# ============================================================

def sanitize_input(text, max_length=50):
    """过滤用户输入：去除首尾空格、限制长度、移除危险字符"""
    if not text:
        return ""
    text = text.strip()[:max_length]
    # 仅保留字母、数字、下划线、连字符、@和点
    text = re.sub(r'[^\w@.\-]', '', text)
    return text


# ============================================================
# 路由：首页
# ============================================================

@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        # 获取用户信息（但不返回密码哈希值到模板）
        user_info = USERS[username].copy()
        user_info.pop("password", None)
    return render_template("index.html", user=user_info)


# ============================================================
# 路由：登录
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    # 已登录用户直接跳转
    if session.get("username"):
        return redirect(url_for("index"))

    error = None

    if request.method == "POST":
        # ---------- 速率限制检查 ----------
        client_ip = request.remote_addr
        if not login_limiter.is_allowed(client_ip):
            logger.warning(f"登录频率超限 | IP: {client_ip}")
            # 不暴露具体限制策略
            return render_template("login.html", error="请求过于频繁，请稍后再试"), 429

        # ---------- 输入过滤 ----------
        username = sanitize_input(request.form.get("username", ""))
        password = request.form.get("password", "")

        # ---------- 基础校验 ----------
        if not username or not password:
            error = "用户名和密码不能为空"
            return render_template("login.html", error=error)

        # ---------- 账户锁定检查 ----------
        if account_locker.is_locked(username):
            logger.warning(f"尝试登录已锁定账户 | 用户名: {username} | IP: {client_ip}")
            error = "账户已被临时锁定，请 15 分钟后再试"
            return render_template("login.html", error=error)

        # ---------- CSRF 验证 ----------
        if not validate_csrf_token():
            error = "安全验证失败，请刷新页面重试"
            return render_template("login.html", error=error)

        # ---------- 身份验证 ----------
        user = USERS.get(username)
        if user and check_password_hash(user["password"], password):
            # 登录成功
            logger.info(f"登录成功 | 用户名: {username} | IP: {client_ip}")

            # 重置锁定计数器
            account_locker.reset(username)

            # 会话固定防护：重新生成 session
            session.clear()
            session.permanent = True
            session["username"] = username
            session["login_time"] = datetime.now().isoformat()

            # 获取用户信息（不含密码哈希）
            user_info = user.copy()
            user_info.pop("password", None)
            return render_template("index.html", user=user_info)
        else:
            # 登录失败
            logger.warning(f"登录失败 | 用户名: {username} | IP: {client_ip}")
            account_locker.record_failure(username)

            # 统一错误信息，不揭示用户是否存在
            error = "用户名或密码错误"

    # 生成新的 CSRF 令牌
    csrf_token = generate_csrf_token()
    return render_template("login.html", error=error, csrf_token=csrf_token)


# ============================================================
# 路由：注册新用户
# ============================================================

@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("username"):
        return redirect(url_for("index"))

    error = None
    success = None

    if request.method == "POST":
        # ---------- 速率限制 ----------
        client_ip = request.remote_addr
        if not register_limiter.is_allowed(client_ip):
            error = "注册请求过于频繁，请稍后再试"
            return render_template("register.html", error=error)

        # ---------- CSRF 验证 ----------
        if not validate_csrf_token():
            error = "安全验证失败，请刷新页面重试"
            return render_template("register.html", error=error)

        # ---------- 获取并过滤输入 ----------
        username = sanitize_input(request.form.get("username", ""))
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        email = sanitize_input(request.form.get("email", ""), max_length=100)

        # ---------- 输入校验 ----------
        if not username or not password or not email:
            error = "所有字段均为必填项"
        elif len(username) < 3:
            error = "用户名长度至少为 3 位"
        elif not re.match(r'^[\w\-]+$', username):
            error = "用户名只能包含字母、数字、下划线和连字符"
        elif not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            error = "邮箱格式不正确"
        elif password != confirm_password:
            error = "两次输入的密码不一致"
        else:
            # ---------- 密码强度校验 ----------
            valid, msg = validate_password_strength(password)
            if not valid:
                error = msg
            elif username in USERS:
                error = "用户名已存在"
            else:
                # ---------- 创建用户 ----------
                hashed_pw = generate_password_hash(password)
                USERS[username] = {
                    "username": username,
                    "password": hashed_pw,
                    "role": "user",
                    "email": email,
                    "phone": "",
                    "balance": 0
                }
                logger.info(f"新用户注册成功 | 用户名: {username} | IP: {client_ip}")
                success = "注册成功！请登录"

    csrf_token = generate_csrf_token()
    return render_template("register.html", error=error, success=success, csrf_token=csrf_token)


# ============================================================
# 路由：登出
# ============================================================

@app.route("/logout")
def logout():
    username = session.get("username", "unknown")
    logger.info(f"用户登出 | 用户名: {username} | IP: {request.remote_addr}")
    session.clear()
    return redirect(url_for("index"))


# ============================================================
# 错误处理
# ============================================================

@app.errorhandler(404)
def not_found(e):
    return render_template("base.html", error_code=404, error_message="页面不存在"), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"服务器内部错误: {e}")
    return render_template("base.html", error_code=500, error_message="服务器内部错误"), 500

@app.errorhandler(429)
def too_many_requests(e):
    return render_template("base.html", error_code=429, error_message="请求过于频繁，请稍后重试"), 429


# ============================================================
# 启动
# ============================================================

if __name__ == "__main__":
    init_users()
    app.run(debug=DEBUG, host="0.0.0.0", port=5000)
