"""
web/app.py
SSRF 취약 웹 서비스 (Flask)

- /fetch?url=<대상 URL> 요청을 받아서 서버가 대신 해당 URL로 요청을 보내는
  전형적인 SSRF 취약 엔드포인트입니다.
- 필터는 일부러 허술하게 구현합니다 (localhost, 점(.) 포함 여부만 체크).
  -> 이 허술함을 진단 도구팀이 우회하는 것이 이번 프로젝트의 핵심 시나리오입니다.
"""

from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

# TODO: 로컬 mock IMDS 서버 주소 (mock_imds 실행 후 여기에 연결)
MOCK_IMDS_URL = "http://127.0.0.1:5001"


def is_blocked_by_filter(target_url: str) -> bool:
    """
    일부러 허술하게 구현한 SSRF 필터입니다.
    - 'localhost' 문자열이 포함되어 있으면 차단
    - IP 형식에 점(.)이 포함되어 있으면 (예: 127.0.0.1) 차단
    => 10진수 IP(2130706433)처럼 점이 없는 표현은 그대로 통과되는 게 취약점 포인트입니다.
    """
    lowered = target_url.lower()
    if "localhost" in lowered:
        return True
    # 아주 단순하게 '127.0.0.1' 같은 점 포함 IP만 체크 (허점 있음)
    if "127.0.0.1" in lowered:
        return True
    return False


@app.route("/fetch", methods=["GET"])
def fetch_url():
    """
    사용자가 준 url 파라미터로 서버가 대신 요청을 보내는 취약 엔드포인트.
    예시: /fetch?url=http://2130706433/ (127.0.0.1 을 10진수로 우회)
    """
    target_url = request.args.get("url", "")

    if not target_url:
        return jsonify({"error": "url 파라미터가 필요합니다."}), 400

    if is_blocked_by_filter(target_url):
        return jsonify({"error": "차단된 요청입니다.", "blocked": True}), 403

    try:
        # TODO: 타임아웃, 리다이렉트 허용 여부 등 진단 시나리오에 맞게 조정
        response = requests.get(target_url, timeout=3, allow_redirects=True)
        return jsonify({
            "status_code": response.status_code,
            "body": response.text[:2000],  # 너무 길면 잘라서 반환
            "blocked": False
        })
    except requests.exceptions.RequestException as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    """진단 도구팀이 서버 살아있는지 확인용으로 쓸 수 있는 헬스체크 엔드포인트."""
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    # TODO: AWS EC2 배포 시 host="0.0.0.0" 으로 변경
    app.run(host="127.0.0.1", port=5000, debug=True)