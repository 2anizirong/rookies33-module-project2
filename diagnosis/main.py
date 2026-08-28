"""
전체 파이프라인 실행 오케스트레이터.

사용법:
    python main.py http://localhost:5000/fetch
    python main.py http://localhost:5000/fetch --callback http://127.0.0.1:9000
"""
import argparse
import json
import sys
from datetime import datetime

from src.stage1_parameter_discovery import run_parameter_discovery
from src.stage2_sink_discovery import run_sink_discovery
from src.stage3_bypass_diagnosis import run_bypass_diagnosis
from src.stage4_imds_exposure import run_imds_exposure, strip_raw_credentials
from src.stage5_cloud_impact import run_cloud_impact
from src.stage8_os_command_injection import run_os_command_injection


def diagnose(target_url: str, method: str, callback_server: str, region: str,
             extra_params: dict = None, skip_sink: bool = False) -> dict:
    extra_params = extra_params or {}

    print(f"[*] Stage 1: Parameter Discovery — {target_url}", file=sys.stderr)
    p1 = run_parameter_discovery(target_url, method=method)
    print(f"    발견된 파라미터: {len(p1.get('parameters', []))}개", file=sys.stderr)

    if skip_sink:
        print(f"[*] Stage 2: Sink Discovery — SKIPPED (모든 파라미터를 candidate로 간주)",
              file=sys.stderr)
        p2 = {
            "target": p1["target"],
            "ssrf_candidates": [
                {**p, "server_request_detected": None}
                for p in p1.get("parameters", [])
            ],
        }
    else:
        print(f"[*] Stage 2: Sink Discovery — callback={callback_server}", file=sys.stderr)
        p2 = run_sink_discovery(p1, callback_server=callback_server)
    print(f"    SSRF candidates: {len(p2.get('ssrf_candidates', []))}개", file=sys.stderr)

    print(f"[*] Stage 3: Bypass Diagnosis (extra={extra_params})", file=sys.stderr)
    p3 = run_bypass_diagnosis(p2, extra_params=extra_params)
    vuln_cnt = sum(1 for r in p3 if r["result"] == "vulnerable")
    print(f"    vulnerable: {vuln_cnt} / {len(p3)}", file=sys.stderr)

    print(f"[*] Stage 4: IMDS Exposure", file=sys.stderr)
    p4 = run_imds_exposure(p3)
    print(f"    IMDS reachable: {p4['imds']['reachable']}, "
          f"creds exposed: {p4['temporary_credentials'].get('exposed', False)}",
          file=sys.stderr)

    print(f"[*] Stage 5: Cloud Impact — region={region}", file=sys.stderr)
    p5 = run_cloud_impact(p4, region=region)
    print(f"    overall_impact: {p5.get('overall_impact')}", file=sys.stderr)

    print("[*] Stage 8: OS Command Injection", file=sys.stderr)
    p8 = run_os_command_injection(p1, extra_params=extra_params)
    print(
        f"    vulnerable: "
        f"{p8['summary']['vulnerable_count']} / "
        f"{p8['summary']['tested_parameter_count']}",
        file=sys.stderr
    )



    pipeline_result = {
        "parameter_discovery": p1,
        "sink_discovery": p2,
        "bypass_diagnosis": p3,
        "imds_exposure": strip_raw_credentials(p4),   # 자격증명 제거
        "cloud_impact": p5,
        "os_command_injection": p8,
    }

    return {
        "meta": {
            "target": target_url,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        },
        "stages": pipeline_result,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", help="진단 대상 URL (예: http://localhost:5000/fetch)")
    ap.add_argument("--method", default="GET", choices=["GET", "POST"])
    ap.add_argument("--callback", default="http://127.0.0.1:9000",
                    help="OOB 콜백 서버 주소 (callback_server.py 실행 후 지정)")
    ap.add_argument("--region", default="ap-northeast-2", help="AWS 리전")
    ap.add_argument("--output", "-o", help="결과 JSON 저장 경로 (미지정시 stdout)")
    ap.add_argument("--extra", action="append", default=[],
                    help="추가 파라미터 (예: --extra level=1). 팀 서버 필터 레벨 지정.")
    ap.add_argument("--skip-sink", action="store_true",
                    help="Stage 2(Sink Discovery) 건너뜀. EC2 대상 등 콜백서버 접근 불가시 사용.")
    args = ap.parse_args()

    # --extra level=1 --extra foo=bar 같은 형식 파싱
    extra_params = {}
    for e in args.extra:
        if "=" in e:
            k, v = e.split("=", 1)
            extra_params[k.strip()] = v.strip()

    result = diagnose(args.target, args.method, args.callback, args.region,
                      extra_params=extra_params, skip_sink=args.skip_sink)
    out = json.dumps(result, indent=2, ensure_ascii=False)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"[+] 저장: {args.output}", file=sys.stderr)
    else:
        print(out)


if __name__ == "__main__":
    main()