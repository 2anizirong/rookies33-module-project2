"""
Sink Discovery용 OOB 콜백 서버.
Stage 2에서 이 서버로 /probe/<token> 요청이 오는지 확인해서 SSRF sink 판정.

실행: python callback_server.py
기본 포트: 9000
"""
from flask import Flask, jsonify, request
from threading import Lock
import argparse

app = Flask(__name__)
_hits = {}
_lock = Lock()


@app.route("/probe/<token>", methods=["GET", "POST"])
def probe(token):
    """SSRF로 서버가 요청 보낼 엔드포인트"""
    with _lock:
        _hits[token] = {
            "hit": True,
            "remote_addr": request.remote_addr,
            "method": request.method,
            "user_agent": request.headers.get("User-Agent", ""),
        }
    return "OK", 200


@app.route("/hits/<token>", methods=["GET"])
def check_hit(token):
    """Stage 2에서 hit 여부 조회"""
    with _lock:
        info = _hits.get(token)
    if info:
        return jsonify(info)
    return jsonify({"hit": False})


@app.route("/hits", methods=["GET"])
def list_hits():
    """전체 hit 로그 (디버깅용)"""
    with _lock:
        return jsonify(_hits)


@app.route("/reset", methods=["POST"])
def reset():
    with _lock:
        _hits.clear()
    return "reset", 200


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=9000)
    args = ap.parse_args()
    print(f"[*] Callback server listening on http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False)
