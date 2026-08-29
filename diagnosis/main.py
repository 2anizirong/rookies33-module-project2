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
from src.stage6_sqli_diagnosis import run_sqli_diagnosis
from src.stage7_stored_xss import run_stored_xss_diagnosis
from src.stage8_os_command_injection import run_os_command_injection
from src.stage9_login_limit import diagnose_login_limit, DEFAULT_TEST_USERNAME


def diagnose(target_url: str, method: str, callback_server: str, region: str,
             extra_params: dict = None, skip_sink: bool = False,
             base_url: str = None, xss_username: str = "", xss_password: str = "",
             login_limit_username: str = DEFAULT_TEST_USERNAME,
             login_limit_attempts: int = 10) -> dict:
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

    # Stage 6: SQL Injection Diagnosis
    # (Stage 7과 마찬가지로 --base-url 필요. 단일 sink 엔드포인트가 아니라
    #  /login, /register, /post/<pid> 등 여러 엔드포인트를 대상으로 하기 때문)
    print(f"[*] Stage 6: SQL Injection Diagnosis", file=sys.stderr)
    if base_url:
        try:
            p6 = run_sqli_diagnosis(base_url)
            vuln_cnt6 = sum(1 for r in p6 if r["result"] == "vulnerable")
            print(f"    vulnerable: {vuln_cnt6} / {len(p6)}", file=sys.stderr)
        except Exception as e:
            # 대상 서버에 SQLi 후보 엔드포인트가 없는 배포 환경도 있을 수 있으니
            # 실패해도 전체 파이프라인은 계속 진행되게 방어.
            print(f"    [!] SQLi 진단 실패 (건너뜀): {e}", file=sys.stderr)
            p6 = {"skipped": True, "reason": str(e)}
    else:
        p6 = {"skipped": True, "reason": "--base-url 미지정"}

    # Stage 7: Stored XSS Diagnosis (Stage 6과 마찬가지로 --base-url 필요)
    print(f"[*] Stage 7: Stored XSS Diagnosis", file=sys.stderr)
    if base_url:
        p7 = run_stored_xss_diagnosis(base_url, username=xss_username, password=xss_password)
        print(f"    vulnerable: {p7['summary']['vulnerable_count']} / {p7['summary']['total_tested']}", file=sys.stderr)
    else:
        p7 = {"skipped": True, "reason": "--base-url 미지정"}

    # Stage 8: OS Command Injection (Stage 1에서 찾은 파라미터를 그대로 재사용, --base-url 불필요)
    print("[*] Stage 8: OS Command Injection", file=sys.stderr)
    p8 = run_os_command_injection(p1, extra_params=extra_params)
    print(
        f"    vulnerable: "
        f"{p8['summary']['vulnerable_count']} / "
        f"{p8['summary']['tested_parameter_count']}",
        file=sys.stderr
    )

    # Stage 9: 로그인 자동화 방어(Rate Limiting) 진단
    # (Stage 6/7과 마찬가지로 사이트 URL이 필요. 전용 테스트 계정으로
    #  동일한 잘못된 비밀번호를 반복 전송해 429/차단/CAPTCHA 신호를 확인한다.
    #  비밀번호를 직접 추측하는 게 아니라 "방어 장치 자체가 있는지"만 확인함.)
    print(f"[*] Stage 9: Login Rate-Limit Diagnosis", file=sys.stderr)
    if base_url:
        try:
            p9_raw = diagnose_login_limit(
                base_url,
                username=login_limit_username,
                password="Stage9-Intentionally-Wrong-Password!",
                attempts=login_limit_attempts,
            )
            p9 = p9_raw["stages"]["stage9_login_limit"]
            print(f"    verdict: {p9['summary']['verdict']}", file=sys.stderr)
        except Exception as e:
            # 대상 서버가 다운되었거나 /login 경로가 다른 배포 환경일 수 있으니
            # 실패해도 전체 파이프라인은 계속 진행되게 방어.
            print(f"    [!] 로그인 속도제한 진단 실패 (건너뜀): {e}", file=sys.stderr)
            p9 = {"skipped": True, "reason": str(e)}
    else:
        p9 = {"skipped": True, "reason": "--base-url 미지정"}

    pipeline_result = {
        "parameter_discovery": p1,
        "sink_discovery": p2,
        "bypass_diagnosis": p3,
        "imds_exposure": strip_raw_credentials(p4),   # 자격증명 제거
        "cloud_impact": p5,
        "sqli_diagnosis": p6,       # Stage 6: SQL Injection
        "stored_xss": p7,          # Stage 7: Stored XSS
        "os_command_injection": p8, # Stage 8: OS Command Injection
        "login_rate_limit": p9,     # Stage 9: 로그인 자동화 방어(Rate Limiting)
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
    ap.add_argument("--base-url", help="Stored XSS 진단을 위한 기본 URL")
    ap.add_argument("--xss-username", default="admin", help="Stored XSS 진단을 위한 사용자 이름")
    ap.add_argument("--xss-password", default="admin1234", help="Stored XSS 진단을 위한 비밀번호")
    ap.add_argument("--login-limit-username", default=DEFAULT_TEST_USERNAME,
                    help="로그인 속도제한 진단에 사용할 전용 테스트 계정명 (실제 admin/guest 계정 사용 금지)")
    ap.add_argument("--login-limit-attempts", type=int, default=10,
                    help="로그인 속도제한 진단 시도 횟수 (1~20)")
    args = ap.parse_args()

    # --extra level=1 --extra foo=bar 같은 형식 파싱
    extra_params = {}
    for e in args.extra:
        if "=" in e:
            k, v = e.split("=", 1)
            extra_params[k.strip()] = v.strip()

    result = diagnose(args.target, args.method, args.callback, args.region,
                      extra_params=extra_params, skip_sink=args.skip_sink,
                      base_url=args.base_url, xss_username=args.xss_username, xss_password=args.xss_password,
                      login_limit_username=args.login_limit_username,
                      login_limit_attempts=args.login_limit_attempts)
    out = json.dumps(result, indent=2, ensure_ascii=False)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"[+] 저장: {args.output}", file=sys.stderr)
    else:
        print(out)


if __name__ == "__main__":
    main()
