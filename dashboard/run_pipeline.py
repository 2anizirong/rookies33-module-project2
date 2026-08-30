"""
run_pipeline.py
dashboard.py가 사용하는 3단계 진단 파이프라인 실행 로직.

Target URL 하나(base_url / fetch_url)를 받아 순서대로 실행한다:
  1) diagnosis/main.py                (1~9단계 진단 -> scan_result.json)          (cwd = dashboard/)
  2) diagnosis/ai/analyze.py          (SSRF 전용 AI 리포트 -> report.md / ai_report.json)   (cwd = diagnosis/)
  3) diagnosis/ai_etc/analyze_etc.py  (SQLi / XSS / OS-CMD / Brute Force AI 리포트
                                        -> report_etc_*.md / ai_report_etc.json)   (cwd = diagnosis/)

UI(Streamlit)에는 의존하지 않는다. 진행 상황은 선택적 콜백으로 호출자에게 넘기며,
대시보드는 이 콜백을 Streamlit 위젯에 연결한다. 
CLI 로도 실행 가능 : python dashboard/run_pipeline.py http://52.78.187.138:5000
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from report_parser import report_json_to_markdown


# ---- 경로 상수 ----
PROJECT_ROOT = Path(__file__).resolve().parent          # dashboard/
DIAGNOSIS_DIR = PROJECT_ROOT.parent / "diagnosis"

# 1단계: diagnosis/main.py <fetch_url> -o scan_result.json --base-url <base_url>  (cwd = dashboard/)
DIAGNOSIS_MAIN = DIAGNOSIS_DIR / "main.py"
SCAN_RESULT_JSON = DIAGNOSIS_DIR / "scan_result.json"

# 2단계: diagnosis/ai/analyze.py --input scan_result.json   (SSRF 전용, cwd = diagnosis/)
ANALYZE_MAIN = DIAGNOSIS_DIR / "ai" / "analyze.py"
AI_REPORT_JSON = DIAGNOSIS_DIR / "ai_report.json"
REPORT_MD = DIAGNOSIS_DIR / "report.md"

# 3단계: diagnosis/ai_etc/analyze_etc.py --input scan_result.json   (SQLi/XSS/OS-CMD/BF, cwd = diagnosis/)
ANALYZE_ETC_MAIN = DIAGNOSIS_DIR / "ai_etc" / "analyze_etc.py"
AI_REPORT_ETC_JSON = DIAGNOSIS_DIR / "ai_report_etc.json"

VULN_TYPES = ["sqli", "stored_xss", "os_command_injection", "login_rate_limit"]
REPORT_ETC_MD_PATHS = {vt: DIAGNOSIS_DIR / f"report_etc_{vt}.md" for vt in VULN_TYPES}


# 자식 프로세스 stdout 의 마커 -> (진행률 0.0~1.0, 표시 문구)
STAGE_PROGRESS = {
    "Stage 1:": (0.05, "[1/8] Parameter Discovery 실행 중"),
    "Stage 2:": (0.10, "[2/8] SSRF Sink Discovery 실행 중"),
    "Stage 3:": (0.16, "[3/8] SSRF Bypass Diagnosis 실행 중"),
    "Stage 4:": (0.22, "[4/8] IMDS Exposure 확인 중"),
    "Stage 5:": (0.28, "[5/8] Cloud Impact 확인 중"),
    "Stage 6:": (0.36, "[6/8] SQL Injection 진단 실행 중"),
    "Stage 7:": (0.44, "[7/8] Stored XSS 진단 실행 중"),
    "Stage 8:": (0.50, "[8/9] OS Command Injection 진단 실행 중"),
    "Stage 9:": (0.53, "[9/9] Login Rate-Limit 진단 실행 중"),
    "[+] 저장:": (0.55, "scan_result.json 저장 완료"),
    "[AI 0/2]": (0.60, "SSRF 리포트 — 진단 증거 정리 중"),
    "[AI 1/2]": (0.68, "SSRF 리포트 — 웹 리서치 중"),
    "[AI 2/2]": (0.76, "SSRF 리포트 — AI 종합 생성 중"),
    "[AI-ETC 0/2]": (0.82, "SQLi/XSS/OS-CMD/BF 리포트 — 진단 증거 정리 중"),
    "[AI-ETC 1/2]": (0.88, "SQLi/XSS/OS-CMD/BF 리포트 — 웹 리서치 중"),
    "[AI-ETC 2/2]": (0.95, "SQLi/XSS/OS-CMD/BF 리포트 — AI 종합 생성 중"),
    "[DONE]": (1.00, "리포트 저장 완료"),
}


# 진행 상황 통지용 콜백 타입 (전부 선택적)
ProgressFn = Callable[[float, str], None]   # (진행률, 문구)
StatusFn = Callable[[str], None]            # (현재 단계 캡션)
LogFn = Callable[[list[str]], None]         # (지금까지의 로그 리스트)


def split_target(value: str) -> tuple[str, str]:
    """사용자가 입력한 URL 하나를 base_url(사이트 루트)과 fetch_url(SSRF/OS-Cmd 대상)로 분리한다."""
    base = value.strip().rstrip("/")
    if base.lower().endswith("/fetch"):
        base = base[: -len("/fetch")].rstrip("/")
    return base, base + "/fetch"


def run_full_pipeline(
    base_url: str,
    fetch_url: str,
    *,
    on_log: LogFn | None = None,
    on_progress: ProgressFn | None = None,
    on_status: StatusFn | None = None,
) -> dict[str, Any]:
    """3단계 진단 파이프라인을 실행하고 결과 dict를 반환한다.

    진행 상황은 콜백으로 통지한다(모두 선택):
      - on_progress(value, text): 0.0~1.0 진행률과 문구
      - on_status(text): 현재 단계 캡션
      - on_log(logs): 지금까지의 로그 리스트 (호출자가 최근 N줄만 렌더하면 됨)
    """

    def _progress(value: float, text: str) -> None:
        if on_progress:
            on_progress(value, text)

    def _status(text: str) -> None:
        if on_status:
            on_status(text)

    def _emit_logs(logs: list[str]) -> None:
        if on_log:
            on_log(logs)

    if not DIAGNOSIS_MAIN.exists():
        raise FileNotFoundError(f"main.py를 찾을 수 없습니다: {DIAGNOSIS_MAIN}")
    if not ANALYZE_MAIN.exists():
        raise FileNotFoundError(f"ai/analyze.py를 찾을 수 없습니다: {ANALYZE_MAIN}")
    if not ANALYZE_ETC_MAIN.exists():
        raise FileNotFoundError(f"ai_etc/analyze_etc.py를 찾을 수 없습니다: {ANALYZE_ETC_MAIN}")

    # 이전 실행 결과가 이번 실행 결과처럼 보이는 것을 방지 (스킵된 취약점의 리포트가 안 지워지고 남는 문제)
    for stale in [SCAN_RESULT_JSON, AI_REPORT_JSON, REPORT_MD, AI_REPORT_ETC_JSON, *REPORT_ETC_MD_PATHS.values()]:
        stale.unlink(missing_ok=True)

    _progress(0.0, "진단 준비 중")
    logs: list[str] = []

    child_env = os.environ.copy()
    child_env["PYTHONIOENCODING"] = "utf-8"
    child_env["PYTHONUTF8"] = "1"

    def stream(command: list[str], cwd: Path, label: str) -> int:
        logs.append(f"\n[$] cd {cwd.name} && {' '.join(command)}")
        _emit_logs(logs)

        process = subprocess.Popen(
            command,
            cwd=str(cwd),
            env=child_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        assert process.stdout is not None

        for raw_line in process.stdout:
            line = raw_line.rstrip()
            if not line:
                continue
            logs.append(line)
            _emit_logs(logs)

            matched = False
            for marker, (value, stage_label) in STAGE_PROGRESS.items():
                if marker in line:
                    _progress(value, stage_label)
                    _status(stage_label)
                    matched = True
                    break
            if not matched:
                _status(label)

        return process.wait()

    # 1단계: diagnosis/main.py  <fetch_url> -o scan_result.json --base-url <base_url>  (cwd = dashboard/)
    # --base-url이 있어야 Stage 6(SQLi)/7(Stored XSS)이 /login,/register,/search,/post/new,/gallery/upload
    # 등 실제 후보 엔드포인트를 대상으로 진단한다. (없으면 두 단계 모두 스킵됨)
    _status("1~8단계 취약점 진단 실행 중 (수 분 소요될 수 있음)")
    code1 = stream(
        [sys.executable, "-u", str(DIAGNOSIS_MAIN), fetch_url,
         "-o", str(SCAN_RESULT_JSON), "--base-url", base_url],
        cwd=PROJECT_ROOT,
        label="1~8단계 진단 실행 중",
    )
    if code1 != 0:
        _progress(0.0, "진단 실패")
        raise RuntimeError("diagnosis/main.py 실행 중 오류가 발생했습니다. 위 실행 로그를 확인하세요.")
    if not SCAN_RESULT_JSON.exists():
        raise FileNotFoundError(f"진단은 종료됐지만 결과 JSON을 찾을 수 없습니다: {SCAN_RESULT_JSON}")

    # 2단계: diagnosis/ai/analyze.py --input scan_result.json   (SSRF 전용, cwd = diagnosis/)
    _status("SSRF AI Security Report 생성 중 (수 분 소요될 수 있음)")
    code2 = stream(
        [sys.executable, "-u", str(ANALYZE_MAIN), "--input", SCAN_RESULT_JSON.name],
        cwd=DIAGNOSIS_DIR,
        label="SSRF AI Security Report 생성 중",
    )
    if code2 != 0:
        _progress(0.55, "SSRF AI 리포트 생성 실패")
        raise RuntimeError("ai/analyze.py 실행 중 오류가 발생했습니다. 위 실행 로그를 확인하세요.")

    # 3단계: diagnosis/ai_etc/analyze_etc.py --input scan_result.json   (SQLi/XSS/OS-CMD/BF, cwd = diagnosis/)
    _status("SQLi / Stored XSS / OS Command Injection AI Report / Brute Force 생성 중 (수 분 소요될 수 있음)")
    code3 = stream(
        [sys.executable, "-u", str(ANALYZE_ETC_MAIN), "--input", SCAN_RESULT_JSON.name],
        cwd=DIAGNOSIS_DIR,
        label="SQLi / XSS / OS-CMD / Brute Force AI Report 생성 중",
    )
    if code3 != 0:
        _progress(0.80, "SQLi/XSS/OS-CMD/Brute-Force AI 리포트 생성 실패")
        raise RuntimeError("ai_etc/analyze_etc.py 실행 중 오류가 발생했습니다. 위 실행 로그를 확인하세요.")

    # ---- 결과 수집 ----
    with SCAN_RESULT_JSON.open("r", encoding="utf-8") as f:
        raw_scan = json.load(f)

    ssrf_md = REPORT_MD.read_text(encoding="utf-8") if REPORT_MD.exists() else None
    ssrf_ai_meta: dict[str, Any] = {}
    if AI_REPORT_JSON.exists():
        try:
            ssrf_ai_meta = json.loads(AI_REPORT_JSON.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            ssrf_ai_meta = {}
    if ssrf_md is None and ssrf_ai_meta:
        # report.md가 없으면 ai_report.json의 "report" 필드를 마크다운으로 변환 (dashboard.py와 동일한 폴백)
        ssrf_md = report_json_to_markdown(ssrf_ai_meta.get("report", ssrf_ai_meta))

    etc_reports: dict[str, str | None] = {}
    for vt in VULN_TYPES:
        p = REPORT_ETC_MD_PATHS[vt]
        etc_reports[vt] = p.read_text(encoding="utf-8") if p.exists() else None

    if ssrf_md is None and all(v is None for v in etc_reports.values()):
        raise RuntimeError(
            "진단은 완료됐지만 SSRF / SQLi / Stored XSS / OS Command Injection 리포트가 "
            "하나도 생성되지 않았습니다. OPENAI_API_KEY 설정을 확인하세요."
        )

    n_ok = (1 if ssrf_md else 0) + sum(1 for v in etc_reports.values() if v)
    _progress(1.0, "진단 완료")

    return {
        "raw": raw_scan,
        "ssrf": {"markdown": ssrf_md, "ai_meta": ssrf_ai_meta},
        "etc_reports": etc_reports,
        "target": {"base_url": base_url, "fetch_url": fetch_url},
        "report_count": n_ok,
        "_dashboard_timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="3단계 진단 파이프라인 실행 (SSRF + SQLi/XSS/OS-CMD/Brute Force)"
    )
    parser.add_argument("url", help="타겟 URL (예: http://52.78.187.138:5000)")
    args = parser.parse_args()

    base_url, fetch_url = split_target(args.url)

    try:
        # CLI에서는 자식 프로세스의 최신 로그 줄을 그대로 흘려보낸다.
        result = run_full_pipeline(
            base_url,
            fetch_url,
            on_log=lambda logs: print(logs[-1], flush=True),
        )
    except Exception as exc:  # noqa: BLE001 - CLI 최상단에서 사용자에게 사유만 전달
        print(f"\n[!] 실패: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"\n[✓] 완료 ({result['report_count']}개 리포트 생성)")
    print(f"    - scan_result : {SCAN_RESULT_JSON}")
    print(f"    - SSRF report : {REPORT_MD}")
    for vt in VULN_TYPES:
        print(f"    - {vt:22s}: {REPORT_ETC_MD_PATHS[vt]}")


if __name__ == "__main__":
    main()
