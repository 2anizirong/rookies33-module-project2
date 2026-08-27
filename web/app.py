"""
취약한 게시판 (Vulnerable Board) v2
- 게시글 / 이미지 업로드 기능 분리
- 보안 교육/실습용
"""
from flask import (
    Flask, request, render_template, redirect,
    session, url_for, send_from_directory, make_response
)
import sqlite3
import os
import urllib.request
import urllib.parse
import socket
import ipaddress

app = Flask(__name__)

# [취약점] 약하고 하드코딩된 시크릿 키
app.secret_key = "supersecret123"

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

DATABASE = os.path.join(os.path.dirname(__file__), "database.db")


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author TEXT NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS images (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uploader TEXT NOT NULL,
            filename TEXT NOT NULL,
            caption TEXT
        )
    """)
    try:
        c.execute("INSERT INTO users (username, password, role) VALUES ('admin', 'admin1234', 'admin')")
        c.execute("INSERT INTO users (username, password) VALUES ('guest', 'guest')")
        c.execute("INSERT INTO posts (author, title, content) VALUES ('admin', '환영합니다', '첫 번째 게시글입니다.')")
    except sqlite3.IntegrityError:
        pass
    conn.commit()
    conn.close()


# --------------------- 홈 ---------------------
@app.route("/")
def index():
    conn = get_db()
    posts = conn.execute("SELECT * FROM posts ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("index.html", posts=posts, user=session.get("username"))


# --------------------- 로그인 ---------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # [취약점] SQL Injection
        conn = get_db()
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        try:
            user = conn.execute(query).fetchone()
        except Exception as e:
            return f"<pre>DB Error: {e}\nQuery: {query}</pre>", 500
        conn.close()

        if user:
            session["username"] = user["username"]
            session["role"] = user["role"]
            return redirect(url_for("index"))
        else:
            error = f"로그인 실패. 실행된 쿼리: {query}"
    return render_template("login.html", error=error)


# --------------------- 회원가입 ---------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # [취약점] 평문 저장 + SQL Injection
        conn = get_db()
        try:
            conn.execute(
                f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')"
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return "이미 존재하는 아이디입니다. <a href='/register'>돌아가기</a>"
        conn.close()
        return redirect(url_for("login"))
    return render_template("register.html")


# --------------------- 로그아웃 ---------------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# --------------------- 글쓰기 (이미지 없음) ---------------------
@app.route("/post/new", methods=["GET", "POST"])
def new_post():
    if "username" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        title = request.form.get("title", "")
        content = request.form.get("content", "")

        # [취약점] SQL Injection
        conn = get_db()
        conn.execute(
            f"INSERT INTO posts (author, title, content) "
            f"VALUES ('{session['username']}', '{title}', '{content}')"
        )
        conn.commit()
        conn.close()
        return redirect(url_for("index"))

    return render_template("new_post.html")


# --------------------- 게시글 보기 ---------------------
@app.route("/post/<pid>")
def view_post(pid):
    # [취약점] SQL Injection
    conn = get_db()
    post = conn.execute(f"SELECT * FROM posts WHERE id={pid}").fetchone()
    conn.close()
    if not post:
        return "게시글이 존재하지 않습니다.", 404
    # [취약점] Stored XSS
    return render_template("post.html", post=post, user=session.get("username"))


# --------------------- 게시글 삭제 ---------------------
@app.route("/post/delete/<int:pid>")
def delete_post(pid):
    # [취약점] IDOR + CSRF
    if "username" not in session:
        return redirect(url_for("login"))
    conn = get_db()
    conn.execute(f"DELETE FROM posts WHERE id={pid}")
    conn.commit()
    conn.close()
    return redirect(url_for("index"))


# --------------------- 이미지 갤러리 (목록) ---------------------
@app.route("/gallery")
def gallery():
    conn = get_db()
    images = conn.execute("SELECT * FROM images ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("gallery.html", images=images, user=session.get("username"))


# --------------------- 이미지 업로드 ---------------------
@app.route("/gallery/upload", methods=["GET", "POST"])
def upload_image():
    if "username" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        caption = request.form.get("caption", "")
        file = request.files.get("image")

        if not file or not file.filename:
            return "이미지 파일을 선택해주세요. <a href='/gallery/upload'>돌아가기</a>"

        # [취약점] 확장자/MIME 검증 없음 → 임의 파일 업로드 가능
        # [취약점] 원본 파일명 그대로 사용 → Path Traversal 가능
        filename = file.filename
        save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(save_path)

        # [취약점] SQL Injection
        conn = get_db()
        conn.execute(
            f"INSERT INTO images (uploader, filename, caption) "
            f"VALUES ('{session['username']}', '{filename}', '{caption}')"
        )
        conn.commit()
        conn.close()
        return redirect(url_for("gallery"))

    return render_template("upload.html")


# --------------------- 이미지 상세 ---------------------
@app.route("/gallery/<iid>")
def view_image(iid):
    # [취약점] SQL Injection
    conn = get_db()
    image = conn.execute(f"SELECT * FROM images WHERE id={iid}").fetchone()
    conn.close()
    if not image:
        return "이미지가 존재하지 않습니다.", 404
    # [취약점] Stored XSS (caption)
    return render_template("image_detail.html", image=image, user=session.get("username"))


# --------------------- 이미지 삭제 ---------------------
@app.route("/gallery/delete/<int:iid>")
def delete_image(iid):
    # [취약점] IDOR + CSRF
    if "username" not in session:
        return redirect(url_for("login"))
    conn = get_db()
    conn.execute(f"DELETE FROM images WHERE id={iid}")
    conn.commit()
    conn.close()
    return redirect(url_for("gallery"))


# --------------------- 검색 ---------------------
@app.route("/search")
def search():
    q = request.args.get("q", "")
    conn = get_db()
    # [취약점] SQL Injection (LIKE)
    rows = conn.execute(
        f"SELECT * FROM posts WHERE title LIKE '%{q}%' OR content LIKE '%{q}%'"
    ).fetchall()
    conn.close()
    # [취약점] Reflected XSS
    html = f"<h2>'{q}' 검색 결과</h2><ul>"
    for r in rows:
        html += f"<li><a href='/post/{r['id']}'>{r['title']}</a></li>"
    html += "</ul><a href='/'>홈으로</a>"
    return html


# --------------------- 업로드 파일 서빙 ---------------------
@app.route("/files/<path:filename>")
def files(filename):
    # [취약점] Path Traversal
    full = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    if not os.path.exists(full):
        return "파일 없음", 404
    with open(full, "rb") as f:
        data = f.read()
    return make_response(data)


# --------------------- URL Preview (SSRF 방어) ---------------------
# [수정] 문자열 매칭 블랙리스트는 인코딩 우회에 취약하므로 폐기.
# 대신 decode_ip()로 정규화한 뒤 ipaddress 모듈로 "의미"를 검사한다.
# 10진수/16진수/8진수/축약형 등 어떤 표기로 들어와도 정규화 후에는
# 동일한 IPv4Address 값이 되므로 우회가 불가능하다.
BLOCKED_HOSTNAMES = {"localhost"}


def is_blocked_host(host: str) -> bool:
    """정규화된(디코딩된) 호스트가 차단 대상인지 IP 의미 기준으로 판단.

    - loopback (127.0.0.0/8, ::1)
    - private (RFC1918: 10/8, 172.16/12, 192.168/16 등)
    - link-local (169.254.0.0/16) → AWS/GCP/Azure 메타데이터 서버(169.254.169.254) 포함
    - reserved / multicast / unspecified (0.0.0.0 등)
    표기가 10진수(2852039166)든 16진수(0xa9fea9fe)든 8진수든 축약형이든
    decode_ip()가 먼저 표준 점-십진수로 바꿔주므로 여기서는 동일하게 걸린다.
    """
    if host.lower() in BLOCKED_HOSTNAMES:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False  # 일반 도메인명 (DNS 리바인딩 방어는 별도 필요)
    return (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def decode_ip(host: str) -> str:
    """
    비표준 IP 표기를 표준 점-십진수(dotted-decimal)로 변환.
    Windows Python의 urllib은 이런 표기를 자체적으로 파싱 못 하므로
    직접 변환해서 넘겨줌. 필터는 원본 문자열만 보기 때문에 우회 가능.

    지원 형식:
      - 10진수 정수:  2130706433      → 127.0.0.1
      - 16진수:       0x7f000001      → 127.0.0.1
      - 8진수(점):    0177.0.0.1      → 127.0.0.1
      - 단축 표기:    127.1           → 127.0.0.1
      - 일반 표기:    127.0.0.1       → 그대로
    """
    try:
        # 점이 없으면 → 10진수 or 16진수 정수 (int()가 0x, 0o 자동 처리)
        if "." not in host:
            return str(ipaddress.IPv4Address(int(host, 0)))

        # 점이 있으면 옥텟별로 파싱 (8진수, 16진수 혼합 가능)
        parts = host.split(".")
        if len(parts) == 2:
            # 단축 표기: A.B → A.0.0.B
            parts = [parts[0], "0", "0", parts[1]]
        if len(parts) == 3:
            # 단축 표기: A.B.C → A.B.0.C
            parts = [parts[0], parts[1], "0", parts[2]]

        def parse_octet(p):
            if p.lower().startswith("0x"):
                return int(p, 16)           # 16진수: 0x7f
            elif p.startswith("0") and len(p) > 1:
                return int(p, 8)            # 8진수: 0177
            else:
                return int(p, 10)           # 10진수: 127

        octets = [parse_octet(p) for p in parts]

        packed = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
        return str(ipaddress.IPv4Address(packed))
    except Exception:
        # 변환 실패 시 원본 그대로 (도메인명 등)
        return host


def normalize_url(url: str) -> str:
    """
    URL의 호스트 부분만 표준 IP로 변환해서 반환.
    필터는 원본 url을 검사하고, 실제 fetch는 변환된 url로 함.
    이게 바로 [취약점]: 필터가 원본만 보기 때문에 우회됨.
    """
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname  # 포트 제외한 순수 호스트
    if not host:
        return url

    decoded = decode_ip(host)

    # 포트가 있으면 다시 붙여줌
    if parsed.port:
        netloc = f"{decoded}:{parsed.port}"
    else:
        netloc = decoded

    return urllib.parse.urlunparse(parsed._replace(netloc=netloc))



@app.route("/preview", methods=["GET", "POST"])
def preview():
    """URL 미리보기 폼"""
    return render_template("preview.html", user=session.get("username"))


@app.route("/fetch")
def fetch():
    """URL Preview: 사용자가 지정한 URL을 서버가 대신 요청.

    [수정] 예전에는 필터가 원본 문자열만 검사하고 실제 요청은 정규화된
    IP로 나가서, 10진수/16진수/8진수/축약형 등으로 인코딩하면 필터를
    우회할 수 있었다 (아래는 모두 과거 우회 가능했던 예시).
    지금은 normalize_url()로 먼저 정규화한 뒤, 그 결과 호스트를
    is_blocked_host()로 검사하므로 어떤 진법/표기로 와도 동일하게 차단된다.

      /fetch?url=http://127.0.0.1:5001/           <- 차단
      /fetch?url=http://2130706433:5001/          <- 차단 (10진수)
      /fetch?url=http://0x7f000001:5001/          <- 차단 (16진수)
      /fetch?url=http://0177.0.0.1:5001/          <- 차단 (8진수)

    AWS 메타데이터 서버(169.254.169.254, link-local) 접근 시도도 마찬가지:
      /fetch?url=http://169.254.169.254/latest/meta-data/
      /fetch?url=http://2852039166/latest/meta-data/            <- 차단 (10진수)
      /fetch?url=http://0xa9fea9fe/latest/meta-data/            <- 차단 (16진수)
      /fetch?url=http://0251.0376.0251.0376/latest/meta-data/   <- 차단 (8진수)
    """
    url = request.args.get("url", "")
    if not url:
        return "url 파라미터가 필요합니다.<br><a href='/preview'>돌아가기</a>"

    # 먼저 정규화(진법 디코딩)한 뒤, 실제로 요청이 나갈 호스트를 검사한다.
    # 필터가 원본 문자열이 아니라 "실제 의미"를 보므로 인코딩 우회가 불가능하다.
    fetch_url = normalize_url(url)
    fetch_host = urllib.parse.urlparse(fetch_url).hostname or ""

    if is_blocked_host(fetch_host):
        return f"차단된 호스트입니다: {url}<br><a href='/preview'>돌아가기</a>", 403

    try:
        # [취약점] 어떤 URL이든 서버 프로세스가 대신 요청함
        #         - 내부망(사설 IP) 접근 가능
        #         - file:// 스킴으로 로컬 파일 읽기 가능
        #         - 리다이렉트 따라감
        if fetch_url.lower().startswith("file://"):
            path = fetch_url[7:]
            with open(path, "rb") as f:
                data = f.read()
        else:
            req = urllib.request.Request(fetch_url, headers={"User-Agent": "VulnBoard-Preview/1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = resp.read()
        try:
            body = data.decode("utf-8", errors="replace")
        except Exception:
            body = repr(data[:2000])
        return f"<h2>Fetch 결과 (원본 URL: {url} → 변환: {fetch_url})</h2><pre style='background:#f0f0f0;padding:15px;white-space:pre-wrap;word-break:break-all;'>{body[:5000]}</pre><a href='/preview'>돌아가기</a>"
    except Exception as e:
        return f"요청 실패: {e}<br>원본 URL: {url}<br>변환 URL: {fetch_url}<br><a href='/preview'>돌아가기</a>", 500


# --------------------- 관리자 페이지 ---------------------
@app.route("/admin")
def admin():
    # [취약점] 쿠키 role만 확인
    role = request.cookies.get("role", session.get("role", "user"))
    if role != "admin":
        return "접근 거부. (힌트: 쿠키를 확인해보세요)", 403

    conn = get_db()
    users = conn.execute("SELECT id, username, password, role FROM users").fetchall()
    conn.close()
    html = "<h1>관리자 페이지</h1><table border=1><tr><th>ID</th><th>Username</th><th>Password</th><th>Role</th></tr>"
    for u in users:
        html += f"<tr><td>{u['id']}</td><td>{u['username']}</td><td>{u['password']}</td><td>{u['role']}</td></tr>"
    html += "</table>"
    return html


# --------------------- 디버그 ---------------------
@app.route("/debug")
def debug():
    return {
        "secret_key": app.secret_key,
        "database": DATABASE,
        "upload_folder": app.config["UPLOAD_FOLDER"],
        "session": dict(session),
    }


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)
