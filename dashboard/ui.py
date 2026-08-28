"""
ui.py
URL 입력창 하나만 있는 심플 UI.
dashboard/ 폴더에 두고 실행:

    cd dashboard
    pip install flask
    python ui.py

브라우저에서 http://127.0.0.1:8000 접속.
"""

from pathlib import Path
from flask import Flask, request, jsonify, render_template_string
import subprocess
import sys

from run_pipeline import build_fetch_url, DIAGNOSIS_MAIN, ANALYZE_MAIN, OUTPUT_JSON, DIAGNOSIS_DIR, BASE_DIR

app = Flask(__name__)

PAGE = """
<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <title>Diagnosis Runner</title>
  <style>
    body { font-family: -apple-system, "Segoe UI", sans-serif; max-width: 720px;
           margin: 60px auto; padding: 0 20px; color: #eee; background: #1e1e1e; }
    h1 { font-size: 20px; margin-bottom: 24px; }
    input[type=text] { width: 100%; padding: 12px; font-size: 15px; border-radius: 6px;
                       border: 1px solid #444; background: #2a2a2a; color: #eee; box-sizing: border-box; }
    button { margin-top: 12px; padding: 10px 22px; font-size: 15px; border: 0;
             border-radius: 6px; background: #4a9eff; color: white; cursor: pointer; }
    button:disabled { background: #555; cursor: not-allowed; }
    pre { margin-top: 24px; background: #111; padding: 16px; border-radius: 6px;
          white-space: pre-wrap; word-break: break-all; font-size: 13px;
          max-height: 500px; overflow: auto; }
    .ok { color: #6dd36d; }
    .err { color: #ff6b6b; }
  </style>
</head>
<body>
  <h1>🔍 Diagnosis Pipeline</h1>
  <input id="url" type="text" placeholder="http://52.78.187.138:5000" autofocus>
  <button id="run">실행</button>
  <pre id="log">대기 중...</pre>

<script>
const btn = document.getElementById('run');
const log = document.getElementById('log');
const urlInput = document.getElementById('url');

btn.onclick = async () => {
  const url = urlInput.value.trim();
  if (!url) { alert('URL 입력해줘'); return; }

  btn.disabled = true;
  log.textContent = '실행 중... (몇 분 걸릴 수 있음)\\n';
  log.className = '';

  try {
    const res = await fetch('/run', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({url})
    });
    const data = await res.json();
    log.textContent = data.output || '(출력 없음)';
    log.className = data.ok ? 'ok' : 'err';
  } catch (e) {
    log.textContent = '요청 실패: ' + e.message;
    log.className = 'err';
  } finally {
    btn.disabled = false;
  }
};

urlInput.addEventListener('keydown', e => {
  if (e.key === 'Enter') btn.click();
});
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(PAGE)


@app.route("/run", methods=["POST"])
def run_endpoint():
    user_url = (request.json or {}).get("url", "").strip()
    if not user_url:
        return jsonify({"ok": False, "output": "URL이 비어있음"}), 400

    fetch_url = build_fetch_url(user_url)
    logs = [f"[fetch_url] {fetch_url}\n"]

    # 1) diagnosis
    logs.append(f"\n[1/2] diagnosis 실행\n$ python {DIAGNOSIS_MAIN} {fetch_url} -o {OUTPUT_JSON}\n")
    p1 = subprocess.run(
        [sys.executable, str(DIAGNOSIS_MAIN), fetch_url, "-o", str(OUTPUT_JSON)],
        cwd=str(BASE_DIR), capture_output=True, text=True,
    )
    logs.append(p1.stdout)
    if p1.stderr:
        logs.append("[stderr]\n" + p1.stderr)
    if p1.returncode != 0:
        logs.append(f"\n[!] diagnosis 실패 (exit={p1.returncode})")
        return jsonify({"ok": False, "output": "".join(logs)})

    # 2) ai/analyze
    logs.append(f"\n[2/2] ai/analyze 실행\n$ python {ANALYZE_MAIN} --input {OUTPUT_JSON.name}\n")
    p2 = subprocess.run(
        [sys.executable, str(ANALYZE_MAIN), "--input", OUTPUT_JSON.name],
        cwd=str(DIAGNOSIS_DIR), capture_output=True, text=True,
    )
    logs.append(p2.stdout)
    if p2.stderr:
        logs.append("[stderr]\n" + p2.stderr)
    if p2.returncode != 0:
        logs.append(f"\n[!] analyze 실패 (exit={p2.returncode})")
        return jsonify({"ok": False, "output": "".join(logs)})

    logs.append(f"\n[✓] 완료")
    logs.append(f"\n    - {OUTPUT_JSON}")
    logs.append(f"\n    - {DIAGNOSIS_DIR / 'ai' / 'report.md'}")
    logs.append(f"\n    - {DIAGNOSIS_DIR / 'ai' / 'report.json'}")
    return jsonify({"ok": True, "output": "".join(logs)})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=False)
