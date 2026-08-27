"""
스모크 테스트: 서버 3개 띄우고 파이프라인 각 stage 순차 검증.
"""
import subprocess
import time
import sys
import os
import signal
import json

os.chdir(os.path.dirname(os.path.abspath(__file__)))

procs = []


def start(name, cmd):
    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    procs.append((name, p))
    print(f"  started {name} (pid={p.pid})")


def cleanup():
    for name, p in procs:
        try:
            p.terminate()
            p.wait(timeout=3)
        except Exception:
            p.kill()


try:
    print("[1/5] 서버 기동")
    start("mock_app", [sys.executable, "mock_vulnerable_app.py"])
    start("callback", [sys.executable, "callback_server.py"])
    time.sleep(3)

    print("\n[2/5] Stage 2 (Sink Discovery) 검증")
    from stage2_sink_discovery import run_sink_discovery
    p1 = {
        "target": "http://127.0.0.1:5000/fetch",
        "parameters": [
            {"name": "url", "method": "GET", "location": "query"},
            {"name": "name", "method": "GET", "location": "query"},
        ],
    }
    p2 = run_sink_discovery(p1, "http://127.0.0.1:9000", include_negatives=True)
    print(json.dumps(p2, indent=2, ensure_ascii=False))

    print("\n[3/5] Stage 3 (Bypass Diagnosis) 검증")
    from stage3_bypass_diagnosis import run_bypass_diagnosis
    # sink 판정된 것만으로 좁힘
    p2_filtered = {
        "target": p2["target"],
        "ssrf_candidates": [c for c in p2["ssrf_candidates"] if c["server_request_detected"]],
    }
    p3 = run_bypass_diagnosis(p2_filtered)
    print(json.dumps(p3, indent=2, ensure_ascii=False))

    print("\n[4/5] Stage 4 (IMDS / Credential Exposure) 검증")
    from stage4_imds_exposure import run_imds_exposure, strip_raw_credentials
    p4 = run_imds_exposure(p3)
    print(json.dumps(strip_raw_credentials(p4), indent=2, ensure_ascii=False))

    print("\n[5/5] Stage 6 (AI Risk Analysis) 검증 - 규칙기반 폴백")
    from stage6_ai_analysis import run_ai_analysis
    pipeline = {
        "parameter_discovery": p1,
        "sink_discovery": p2_filtered,
        "bypass_diagnosis": p3,
        "imds_exposure": strip_raw_credentials(p4),
        "cloud_impact": {"principal": {"type": "IAMRole", "name": "module-project-role"},
                         "cloud_impact": [], "overall_impact": "none"},
    }
    # API 키 없이 → 규칙기반 폴백
    os.environ.pop("OPENAI_API_KEY", None)
    p6 = run_ai_analysis(pipeline, offline_fallback=True)
    print(json.dumps(p6, indent=2, ensure_ascii=False))

    print("\n[✓] 전체 파이프라인 스모크 테스트 완료")

finally:
    cleanup()
