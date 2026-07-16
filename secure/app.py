import os
import re
import secrets
import sqlite3
import logging
import subprocess
import platform
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timedelta
from collections import defaultdict

from flask import (
    Flask, render_template, request, redirect,
    session, url_for
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
    secrets.token_hex(32)
)

# ---------- 会话安全配置 ----------
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_REFRESH_EACH_REQUEST'] = True

# ---------- 上传配置 ----------
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
UPLOAD_FOLDER = os.path.join('static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

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
        self._requests = defaultdict(list)

    def is_allowed(self, ip):
        now = datetime.now()
        cutoff = now - timedelta(seconds=self.window_seconds)
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
    """账户锁定机制"""
    def __init__(self, max_attempts=5, lockout_minutes=15):
        self.max_attempts = max_attempts
        self.lockout_minutes = lockout_minutes
        self._attempts = defaultdict(list)
        self._locks = {}

    def record_failure(self, username):
        now = datetime.now()
        self._attempts[username].append(now)
        cutoff = now - timedelta(minutes=self.lockout_minutes)
        self._attempts[username] = [t for t in self._attempts[username] if t > cutoff]
        if len(self._attempts[username]) >= self.max_attempts:
            self._locks[username] = now + timedelta(minutes=self.lockout_minutes)
            logger.warning(f"账户已被锁定 | 用户名: {username}")

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


# ============================================================
# CSRF 防护
# ============================================================

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']

def validate_csrf_token():
    token = request.form.get('_csrf_token', '')
    stored_token = session.get('_csrf_token', '')
    if not stored_token or not secrets.compare_digest(stored_token, token):
        logger.warning(f"CSRF 验证失败 | IP: {request.remote_addr}")
        return False
    return True


# ============================================================
# 密码强度校验
# ============================================================

def validate_password_strength(password):
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
login_limiter = RateLimiter(max_requests=10, window_seconds=60)
register_limiter = RateLimiter(max_requests=3, window_seconds=300)
upload_limiter = RateLimiter(max_requests=10, window_seconds=60)
recharge_limiter = RateLimiter(max_requests=5, window_seconds=60)
account_locker = AccountLocker(max_attempts=5, lockout_minutes=15)


# ============================================================
# SQLite 数据库初始化
# ============================================================

def init_db():
    """初始化 SQLite 数据库，创建 users 表并插入默认用户"""
    os.makedirs('data', exist_ok=True)
    conn = sqlite3.connect('data/users.db')
    c = conn.cursor()

    # 创建 users 表
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            balance INTEGER DEFAULT 0
        )
    ''')

    # 兼容旧表：若 balance 列不存在则添加
    try:
        c.execute("ALTER TABLE users ADD COLUMN balance INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass  # 列已存在

    # 插入默认用户（密码经过哈希处理）
    default_users = [
        ('admin', generate_password_hash('admin123'), 'admin@example.com', '13800138000', 99999),
        ('alice', generate_password_hash('alice2025'), 'alice@example.com', '13900139001', 100),
    ]
    for u in default_users:
        c.execute(
            "INSERT OR IGNORE INTO users (username, password, email, phone, balance) VALUES (?, ?, ?, ?, ?)",
            u
        )

    conn.commit()
    conn.close()
    logger.info("SQLite 数据库初始化完成 | data/users.db")


def get_db():
    """获取数据库连接"""
    return sqlite3.connect('data/users.db')


# ============================================================
# 输入过滤工具
# ============================================================

def sanitize_input(text, max_length=50):
    if not text:
        return ""
    text = text.strip()[:max_length]
    text = re.sub(r'[^\w@.\-]', '', text)
    return text


# ============================================================
# 路由：首页
# ============================================================

@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    if username:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT username, email, phone FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()
        if row:
            user_info = {
                "username": row[0],
                "email": row[1] or "",
                "phone": row[2] or "",
            }
    return render_template("index.html", user=user_info)


# ============================================================
# 路由：登录
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("username"):
        return redirect(url_for("index"))

    error = None

    if request.method == "POST":
        client_ip = request.remote_addr
        if not login_limiter.is_allowed(client_ip):
            logger.warning(f"登录频率超限 | IP: {client_ip}")
            return render_template("login.html", error="请求过于频繁，请稍后再试"), 429

        username = sanitize_input(request.form.get("username", ""))
        password = request.form.get("password", "")

        if not username or not password:
            error = "用户名和密码不能为空"
            return render_template("login.html", error=error)

        if account_locker.is_locked(username):
            logger.warning(f"尝试登录已锁定账户 | 用户名: {username}")
            error = "账户已被临时锁定，请 15 分钟后再试"
            return render_template("login.html", error=error)

        if not validate_csrf_token():
            error = "安全验证失败，请刷新页面重试"
            return render_template("login.html", error=error)

        # 从 SQLite 查询用户
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT username, password, email, phone FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()

        if row and check_password_hash(row[1], password):
            logger.info(f"登录成功 | 用户名: {username} | IP: {client_ip}")
            account_locker.reset(username)

            session.clear()
            session.permanent = True
            session["username"] = username
            session["login_time"] = datetime.now().isoformat()

            user_info = {
                "username": row[0],
                "email": row[2] or "",
                "phone": row[3] or "",
            }
            return render_template("index.html", user=user_info)
        else:
            logger.warning(f"登录失败 | 用户名: {username} | IP: {client_ip}")
            account_locker.record_failure(username)
            error = "用户名或密码错误"

    csrf_token = generate_csrf_token()
    return render_template("login.html", error=error, csrf_token=csrf_token)


# ============================================================
# 路由：注册新用户（使用参数化查询，防止 SQL 注入）
# ============================================================

@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("username"):
        return redirect(url_for("index"))

    error = None
    success = None

    if request.method == "POST":
        client_ip = request.remote_addr
        if not register_limiter.is_allowed(client_ip):
            error = "注册请求过于频繁，请稍后再试"
            return render_template("register.html", error=error)

        if not validate_csrf_token():
            error = "安全验证失败，请刷新页面重试"
            return render_template("register.html", error=error)

        # 获取用户输入并做基础校验
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        if not username or not password or not email:
            error = "用户名、密码、邮箱为必填项"
        elif len(username) < 3:
            error = "用户名长度至少为 3 位"
        elif not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            error = "邮箱格式不正确"
        else:
            hashed_pw = generate_password_hash(password)
            conn = get_db()
            c = conn.cursor()

            try:
                # 使用参数化查询，防止 SQL 注入
                c.execute(
                    "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
                    (username, hashed_pw, email, phone)
                )
                conn.commit()
                logger.info(f"新用户注册成功 | 用户名: {username} | IP: {client_ip}")
                success = "注册成功，请登录"
            except sqlite3.IntegrityError:
                error = "用户名已存在"
            except Exception as e:
                error = "注册失败，请稍后重试"
                logger.error(f"注册异常: {e}")
            finally:
                conn.close()

    csrf_token = generate_csrf_token()
    return render_template("register.html", error=error, success=success, csrf_token=csrf_token)


# ============================================================
# 路由：搜索用户（使用参数化查询，防止 SQL 注入）
# ============================================================

@app.route("/search")
def search():
    keyword = request.args.get("keyword", "")
    results = []

    if keyword:
        conn = get_db()
        c = conn.cursor()

        try:
            # 使用参数化查询，防止 SQL 注入
            # LIKE 通配符 % 放在参数中拼接（安全，仅拼接 % 字符）
            like_pattern = f"%{keyword}%"
            c.execute(
                "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?",
                (like_pattern, like_pattern)
            )
            rows = c.fetchall()
            for row in rows:
                results.append({
                    "id": row[0],
                    "username": row[1],
                    "email": row[2] or "",
                    "phone": row[3] or "",
                })
            logger.info(f"用户搜索 | 关键词: {keyword} | 结果数: {len(results)}")
        except Exception as e:
            logger.error(f"搜索异常: {e}")
        finally:
            conn.close()

    # 获取当前登录用户信息
    username = session.get("username")
    user_info = None
    if username:
        conn2 = get_db()
        c2 = conn2.cursor()
        c2.execute("SELECT username, email, phone FROM users WHERE username = ?", (username,))
        row = c2.fetchone()
        conn2.close()
        if row:
            user_info = {
                "username": row[0],
                "email": row[1] or "",
                "phone": row[2] or "",
            }

    return render_template("index.html", user=user_info,
                           search_results=results, search_keyword=keyword)


# ============================================================
# 路由：上传头像
# ============================================================

@app.route("/upload", methods=["GET", "POST"])
def upload():
    if not session.get("username"):
        return redirect(url_for("login"))

    error = None
    success = None
    file_url = None

    if request.method == "POST":
        username = session.get("username")

        # CSRF 防护
        if not validate_csrf_token():
            error = "安全验证失败，请刷新页面重试"
            csrf_token = generate_csrf_token()
            return render_template("upload.html", error=error, csrf_token=csrf_token)

        # 速率限制
        client_ip = request.remote_addr
        if not upload_limiter.is_allowed(client_ip):
            logger.warning(f"上传频率超限 | IP: {client_ip}")
            error = "请求过于频繁，请稍后再试"
            csrf_token = generate_csrf_token()
            return render_template("upload.html", error=error, csrf_token=csrf_token)

        if 'file' not in request.files:
            error = "没有选择文件"
        else:
            f = request.files['file']
            if f.filename == '':
                error = "文件名为空"
            else:
                # 仅保留文件名，去除路径防止路径遍历
                raw_name = f.filename
                safe_name = os.path.basename(raw_name)

                # 用用户名前缀防止文件覆盖
                filename = f"{username}_{safe_name}"
                save_path = os.path.join(UPLOAD_FOLDER, filename)
                f.save(save_path)
                file_url = url_for('static', filename=f'uploads/{filename}')
                logger.info(f"文件上传成功 | 用户: {username} | 文件: {filename} | IP: {client_ip}")
                success = "文件上传成功！"

    csrf_token = generate_csrf_token()
    return render_template("upload.html", error=error, success=success, file_url=file_url, csrf_token=csrf_token)


# ============================================================
# 路由：个人中心
# ============================================================

@app.route("/profile")
def profile():
    if not session.get("username"):
        return redirect(url_for("login"))

    username = session.get("username")
    user_data = None
    error = None

    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT id, username, email, phone, balance FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()
        if row:
            user_data = {
                "id": row[0],
                "username": row[1],
                "email": row[2] or "",
                "phone": row[3] or "",
                "balance": row[4] or 0,
            }
        else:
            error = "用户数据不存在"
    except Exception as e:
        error = "查询失败"
        logger.error(f"个人中心查询异常: {e}")

    return render_template("profile.html", user=user_data, error=error, csrf_token=generate_csrf_token())


# ============================================================
# 路由：充值
# ============================================================

@app.route("/recharge", methods=["POST"])
def recharge():
    if not session.get("username"):
        return redirect(url_for("login"))

    # CSRF 防护
    if not validate_csrf_token():
        logger.warning(f"充值CSRF验证失败 | IP: {request.remote_addr}")
        return redirect(url_for("profile"))

    username = session.get("username")
    amount_str = request.form.get("amount", "0")

    try:
        amount = float(amount_str)
    except ValueError:
        logger.warning(f"充值金额格式无效 | 用户: {username} | 输入: {amount_str}")
        return redirect(url_for("profile"))

    # 金额必须为正数
    if amount <= 0:
        logger.warning(f"充值金额无效 | 用户: {username} | 金额: {amount}")
        return redirect(url_for("profile"))

    # 单次充值上限（防止超大型数字导致溢出）
    if amount > 10000000:
        logger.warning(f"充值金额超出上限 | 用户: {username} | 金额: {amount}")
        return redirect(url_for("profile"))

    # 速率限制
    client_ip = request.remote_addr
    if not recharge_limiter.is_allowed(client_ip):
        logger.warning(f"充值频率超限 | 用户: {username} | IP: {client_ip}")
        return redirect(url_for("profile"))

    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("UPDATE users SET balance = balance + ? WHERE username = ?", (amount, username))
        conn.commit()
        conn.close()
        logger.info(f"充值成功 | 用户: {username} | 金额: {amount} | IP: {client_ip}")
    except Exception as e:
        logger.error(f"充值异常 | 用户: {username} | 错误: {e}")

    return redirect(url_for("profile"))


# ============================================================
# 路由：动态页面加载
# ============================================================

@app.route("/page")
def page():
    name = request.args.get("name", "")
    page_content = None
    error = None

    if not name:
        error = "请提供页面名称"
    else:
        # 直接拼接用户输入到路径中，不做任何过滤
        page_path = os.path.join("pages", name)

        # 如果有 .html 就不加，否则尝试加 .html 后缀
        if not os.path.exists(page_path):
            page_path = os.path.join("pages", name + ".html")

        if os.path.exists(page_path):
            try:
                with open(page_path, "r", encoding="utf-8") as f:
                    page_content = f.read()
            except Exception as e:
                error = f"读取页面失败"
                logger.error(f"页面读取异常: {e}")
        else:
            error = "页面不存在"

    # 获取当前用户信息
    username = session.get("username")
    user_info = None
    if username:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT username, email, phone FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()
        if row:
            user_info = {
                "username": row[0],
                "email": row[1] or "",
                "phone": row[2] or "",
            }

    return render_template("index.html", user=user_info,
                           page_content=page_content, page_error=error)


# ============================================================
# 路由：URL 抓取（含 SSRF 防护）
# ============================================================

def is_private_ip(ip_str):
    """检查 IP 是否为内网地址"""
    try:
        import ipaddress
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False

def validate_url_safe(target_url):
    """校验 URL 是否安全，防止 SSRF 攻击"""
    # 只允许 http 和 https 协议
    parsed = urllib.parse.urlparse(target_url)
    if parsed.scheme not in ("http", "https"):
        return False, f"不允许的协议: {parsed.scheme}，仅支持 http/https"

    # 解析主机名
    hostname = parsed.hostname
    if not hostname:
        return False, "无效的 URL"

    # 禁止 localhost
    if hostname in ("localhost", "0.0.0.0"):
        return False, "不允许访问本地地址"

    try:
        import socket
        # 检查是否直接使用了内网 IP
        if re.match(r'^127\.|^10\.|^172\.(1[6-9]|2\d|3[01])\.|^192\.168\.|^169\.254\.', hostname):
            return False, "不允许访问内网地址"

        # DNS 解析，检查目标是否为内网
        try:
            ip = socket.gethostbyname(hostname)
            if is_private_ip(ip):
                return False, f"目标地址 {ip} 为内网地址，已拦截"
        except socket.gaierror:
            return False, "无法解析域名"

    except Exception as e:
        return False, f"地址校验失败: {str(e)[:200]}"

    return True, ""


@app.route("/fetch-url", methods=["POST"])
def fetch_url():
    if not session.get("username"):
        return redirect(url_for("login"))

    target_url = request.form.get("url", "")
    fetch_status = None
    fetch_content = None
    fetch_error = None

    if not target_url:
        fetch_error = "请提供 URL"
    else:
        # SSRF 防护检查
        safe, msg = validate_url_safe(target_url)
        if not safe:
            fetch_error = msg
            logger.warning(f"SSRF 拦截 | 用户: {session.get('username')} | URL: {target_url} | 原因: {msg}")
        else:
            try:
                req = urllib.request.Request(target_url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=10) as response:
                    fetch_status = response.status
                    raw = response.read()
                    content = raw.decode("utf-8", errors="replace")
                    fetch_content = content[:5000]
                    logger.info(f"URL 抓取成功 | 用户: {session.get('username')} | URL: {target_url} | 状态: {fetch_status}")
            except urllib.error.HTTPError as e:
                fetch_status = e.code
                fetch_content = str(e)[:2000]
                fetch_error = f"HTTP 错误: {e.code}"
            except Exception as e:
                fetch_error = f"请求失败: {str(e)[:500]}"

    username = session.get("username")
    user_info = None
    if username:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT username, email, phone FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()
        if row:
            user_info = {
                "username": row[0],
                "email": row[1] or "",
                "phone": row[2] or "",
            }

    return render_template("index.html", user=user_info,
                           fetch_status=fetch_status, fetch_content=fetch_content,
                           fetch_error=fetch_error, fetch_url=target_url)


# ============================================================
# 路由：修改密码
# ============================================================

@app.route("/change-password", methods=["POST"])
def change_password():
    if not session.get("username"):
        return redirect(url_for("login"))

    # CSRF 验证
    if not validate_csrf_token():
        logger.warning(f"修改密码CSRF验证失败 | IP: {request.remote_addr}")
        return redirect(url_for("profile"))

    # 只能修改自己的密码（从 session 取用户名）
    session_user = session.get("username")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not new_password:
        return redirect(url_for("profile"))

    if new_password != confirm_password:
        return redirect(url_for("profile"))

    hashed_pw = generate_password_hash(new_password)
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_pw, session_user))
    conn.commit()
    conn.close()
    logger.info(f"密码修改成功 | 用户: {session_user} | IP: {request.remote_addr}")

    return redirect(url_for("profile"))


# ============================================================
# 路由：Ping 网络诊断
# ============================================================

@app.route("/ping", methods=["GET", "POST"])
def ping():
    if not session.get("username"):
        return redirect(url_for("login"))

    output = None
    ip = ""

    if request.method == "POST":
        ip = request.form.get("ip", "").strip()
        if ip:
            try:
                # 使用 f-string 拼接命令，shell=True 执行
                cmd = f"ping -c 3 {ip}"
                result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=30)
                output = result.decode("utf-8", errors="replace")
            except subprocess.CalledProcessError as e:
                output = e.output.decode("utf-8", errors="replace") if e.output else f"命令执行失败，返回码: {e.returncode}"
            except subprocess.TimeoutExpired:
                output = "ping 命令执行超时（30秒）"
            except Exception as e:
                output = f"执行错误: {str(e)}"
        else:
            output = "请输入 IP 地址"

    return render_template("ping.html", output=output, ip=ip)


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
    init_db()
    app.run(debug=DEBUG, host="0.0.0.0", port=7777)
