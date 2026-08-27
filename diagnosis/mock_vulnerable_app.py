"""
로컬 테스트용 SSRF 취약 웹앱 + Mock IMDS 서버.

실행:
  python mock_vulnerable_app.py
  → :5000에 취약 앱, :5001에 mock IMDS (169.254.169.254 대체)

취약점 시뮬레이션:
  - /fetch?url=... : url 파라미터를 그대로 서버에서 GET (단, localhost/. 문자열 필터)
  - 10진수 IP(예: 2130706433) 등은 필터를 우회함
  - Mock IMDS는 127.0.0.1:5001 이라, 실제로는 10진수 표현이 127.0.0.1을 가리켜야 함
    → 여기서는 "http://<대체호스트>:5001/..." 형태만 걸러내는 대신,
      필터를 문자열 기반으로만 걸어서 우회가 성공하도록 구성.
"""
from flask import Flask, request, jsonify
import requests
import re
from threading import Thread
import argparse

# ---------------- 취약 앱 (port 5000) ----------------
app = Flask("vulnerable")

# 실제로는 169.254.169.254지만, 로컬 테스트에서는 mock IMDS 주소로 매핑
MOCK_IMDS_HOSTS = {"169.254.169.254", "127.0.0.1", "localhost", "2130706433", "0x7f000001"}
MOCK_IMDS_PORT = 5001


# 로컬 테스트: 콜백 서버는 "외부 서비스" 인 척 통과시킴 (팀 발표시 이 부분 언급)
EXTERNAL_ALLOWLIST = ["127.0.0.1:9000"]


def naive_filter(url: str) -> bool:
    """일부러 취약한 필터: 문자열 기반으로 localhost/사설 IP 대역만 차단.
    → 10진수/16진수 IP 표현으로 우회 가능."""
    # 로컬 테스트 편의: 콜백 서버는 외부인 척 통과
    for allowed in EXTERNAL_ALLOWLIST:
        if allowed in url:
            return True
    lower = url.lower()
    if "localhost" in lower:
        return False
    # 사설/링크로컬 대역만 문자열로 차단
    if re.search(r"\b(127|10|169\.254|192\.168|172\.(1[6-9]|2\d|3[01]))\.", url):
        return False
    return True


def rewrite_to_mock(url: str) -> str:
    """
    169.254.169.254 이나 10진수/16진수 표현 → 로컬 mock IMDS로 리다이렉트.
    (실제 EC2에서는 이 함수 없이 그대로 요청 나감)
    """
    # 10진수: 2130706433 = 127.0.0.1
    for token in ("169.254.169.254", "2130706433", "2852039166", "0x7f000001", "0xa9fea9fe"):
        if token in url:
            return re.sub(r"http://[^/]+", f"http://127.0.0.1:{MOCK_IMDS_PORT}", url, count=1)
    return url


@app.route("/fetch", methods=["GET", "POST"])
def fetch():
    """대표 SSRF sink"""
    if request.method == "GET":
        target = request.args.get("url")
    else:
        target = (request.json or {}).get("url") or request.form.get("url")

        if not target:
        # Arjun probe 대응: 200 리턴해야 정상 동작
            return "SSRF Fetcher Service. Provide 'url' parameter.", 200

    if not naive_filter(target):
        return jsonify({"error": "blocked by filter", "url": target}), 403

    # 로컬 테스트용: mock IMDS로 리다이렉트
    fetch_url = rewrite_to_mock(target)

    try:
        r = requests.get(fetch_url, timeout=5)
        return r.text, r.status_code, {"Content-Type": r.headers.get("Content-Type", "text/plain")}
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/profile", methods=["GET"])
def profile():
    """SSRF 없는 정상 파라미터 (Arjun이 찾지만 sink는 아님)"""
    name = request.args.get("name", "guest")
    age = request.args.get("age", "??")
    return jsonify({"name": name, "age": age})


# ---------------- Mock IMDS (port 5001) ----------------
imds_app = Flask("mock_imds")

MOCK_ROLE_NAME = "module-project-role"
MOCK_CREDS = {
    "Code": "Success",
    "LastUpdated": "2026-08-27T00:00:00Z",
    "Type": "AWS-HMAC",
    "AccessKeyId": "ASIAEXAMPLEFAKEKEY01",
    "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYFAKESECRET",
    "Token": "FQoDYXdzEFAKETOKEN...",
    "Expiration": "2026-08-27T06:00:00Z",
}


@imds_app.route("/latest/meta-data/", methods=["GET"])
def imds_root():
    return "ami-id\ninstance-id\niam/\nhostname\n"


@imds_app.route("/latest/meta-data/iam/security-credentials/", methods=["GET"])
def imds_role_list():
    return MOCK_ROLE_NAME + "\n"


@imds_app.route(f"/latest/meta-data/iam/security-credentials/{MOCK_ROLE_NAME}", methods=["GET"])
def imds_creds():
    import json as _json
    return _json.dumps(MOCK_CREDS), 200, {"Content-Type": "application/json"}


# ---------------- Runner ----------------
def run_app(a, port):
    a.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--vuln-port", type=int, default=5000)
    ap.add_argument("--imds-port", type=int, default=MOCK_IMDS_PORT)
    args = ap.parse_args()

    t_imds = Thread(target=run_app, args=(imds_app, args.imds_port), daemon=True)
    t_imds.start()
    print(f"[*] Mock IMDS on http://127.0.0.1:{args.imds_port}")
    print(f"[*] Vulnerable app on http://0.0.0.0:{args.vuln_port}")
    print(f"[*] Try:  curl 'http://127.0.0.1:{args.vuln_port}/fetch?url=http://2130706433/latest/meta-data/'")
    run_app(app, args.vuln_port)
