"""
side_dashboard.py
SSRF + SQL Injection + Stored XSS + OS Command Injection 통합 진단 대시보드.

Target URL 하나를 입력하고 '진단 시작'을 누르면 순서대로:
  1) diagnosis/main.py                    (1~8단계 진단, scan_result.json 생성)
  2) diagnosis/ai/analyze.py              (SSRF 전용 AI 리포트 -> report.md / ai_report.json)
  3) diagnosis/ai_etc/analyze_etc.py      (SQLi / Stored XSS / OS Command Injection AI 리포트
                                            -> report_etc_sqli.md / report_etc_stored_xss.md /
                                               report_etc_os_command_injection.md)
가 실행된다. 처음에는 SSRF 리포트가 표시되고, 왼쪽 사이드바의 SSRF / SQL Injection /
Stored XSS / OS Command Injection 버튼을 눌러 4개 리포트를 오가며 볼 수 있다.
UI/스타일은 dashboard.py(SSRF 전용 대시보드)와 동일한 톤을 공유한다.

실행:
    streamlit run dashboard/side_dashboard.py
"""

from __future__ import annotations

import copy
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import plotly.graph_objects as go
import streamlit as st

from src.report_parser import (
    count_subheadings,
    extract_evidence_list,
    extract_meta,
    extract_numbered_list,
    extract_recommendation_list,
    extract_subsection,
    find_section,
    get_report_title,
    parse_sections,
    report_json_to_markdown,
    strip_meta_bullets,
)


PROJECT_ROOT = Path(__file__).resolve().parent          # dashboard/
DIAGNOSIS_DIR = PROJECT_ROOT.parent / "diagnosis"

# 1단계: diagnosis/main.py <fetch_url> -o scan_result.json --base-url <base_url>  (cwd = dashboard/)
DIAGNOSIS_MAIN = DIAGNOSIS_DIR / "main.py"
SCAN_RESULT_JSON = DIAGNOSIS_DIR / "scan_result.json"

# 2단계: diagnosis/ai/analyze.py --input scan_result.json   (SSRF 전용, cwd = diagnosis/)
ANALYZE_MAIN = DIAGNOSIS_DIR / "ai" / "analyze.py"
AI_REPORT_JSON = DIAGNOSIS_DIR / "ai_report.json"
REPORT_MD = DIAGNOSIS_DIR / "report.md"

# 3단계: diagnosis/ai_etc/analyze_etc.py --input scan_result.json   (SQLi/XSS/OS-CMD, cwd = diagnosis/)
ANALYZE_ETC_MAIN = DIAGNOSIS_DIR / "ai_etc" / "analyze_etc.py"
AI_REPORT_ETC_JSON = DIAGNOSIS_DIR / "ai_report_etc.json"

VULN_TYPES = ["sqli", "stored_xss", "os_command_injection", "login_rate_limit"]
REPORT_ETC_MD_PATHS = {vt: DIAGNOSIS_DIR / f"report_etc_{vt}.md" for vt in VULN_TYPES}

TABS = ["ssrf", *VULN_TYPES]
TAB_LABELS = {
    "ssrf": "SSRF · Cloud Impact",
    "sqli": "SQL Injection",
    "stored_xss": "Stored / Reflected XSS",
    "os_command_injection": "OS Command Injection",
    "login_rate_limit": "Login Rate Limiting",
}


def normalize_scan_result(raw: dict[str, Any]) -> dict[str, Any]:
    """diagnosis/main.py가 만드는 scan_result.json(meta/stages.*)을
    SSRF 탭 렌더링이 기대하는 평평한(top-level) 스키마로 변환한다."""
    stages = raw.get("stages", {}) or {}
    meta_block = raw.get("meta", {}) or {}

    imds_exposure = stages.get("imds_exposure") or {}

    raw_cloud = stages.get("cloud_impact") or {}
    normalized_impacts = []
    for item in raw_cloud.get("cloud_impact", []) or []:
        permissions = item.get("permissions") or []
        normalized_impacts.append(
            {
                **item,
                "accessible": True,
                "action": item.get("resource", "-"),
                "assets": permissions,
                "asset_count": len(permissions),
            }
        )

    return {
        "target": {"endpoint": meta_block.get("target", "-")},
        "timestamp": meta_block.get("timestamp"),
        "parameter_discovery": stages.get("parameter_discovery", {}) or {},
        "ssrf_sink_discovery": stages.get("sink_discovery", {}) or {},
        "ssrf_bypass_diagnosis": {"bypass_results": stages.get("bypass_diagnosis", []) or []},
        "imds_credential_exposure": {
            "assessments": [imds_exposure] if imds_exposure else [],
        },
        "cloud_impact_assessment": {
            "principal": raw_cloud.get("principal", {}) or {},
            "cloud_impact": normalized_impacts,
            "overall_impact": raw_cloud.get("overall_impact", "unknown"),
            "region": raw_cloud.get("region", "-"),
        },
    }


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
    "[AI-ETC 0/2]": (0.82, "SQLi/XSS/OS-CMD 리포트 — 진단 증거 정리 중"),
    "[AI-ETC 1/2]": (0.88, "SQLi/XSS/OS-CMD 리포트 — 웹 리서치 중"),
    "[AI-ETC 2/2]": (0.95, "SQLi/XSS/OS-CMD 리포트 — AI 종합 생성 중"),
    "[DONE]": (1.00, "리포트 저장 완료"),
}

SEVERITY_COLORS = {
    "critical": "#ff3b5c",
    "high": "#ff6b45",
    "medium": "#ffb020",
    "low": "#20c997",
    "unknown": "#58a6ff",
}

SQLI_TECHNIQUE_LABELS = {
    "auth_bypass": "인증 우회",
    "error_based": "에러 기반",
    "boolean_based": "불리언 기반",
    "boolean_based_search": "불리언 기반(검색)",
}


st.set_page_config(
    page_title="Vuln Sentinel · SSRF/SQLi/XSS/OS-CMD 진단 대시보드",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Noto+Sans+KR:wght@400;500;600;700&display=swap');

:root { --ink:#e8edf6; --muted:#8b97aa; --panel:#111722; --line:#252f40; --cyan:#4de2c5; --orange:#ff6b45; }
.stApp { background: radial-gradient(circle at 85% -10%, #162c3b 0%, #0a0e15 34%, #080b11 70%); color:var(--ink); }
html, body, [class*="css"] { font-family:'Noto Sans KR',sans-serif; }
[data-testid="stSidebar"] { background:#0c1119; border-right:1px solid #1f2938; }
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p { color:#aeb8c8; }
[data-testid="stHeader"] { background:transparent; }
.block-container { padding:2rem 2.6rem 4rem; max-width:1500px; }

.brand { font-family:'IBM Plex Mono'; font-size:.78rem; letter-spacing:.17em; color:#4de2c5; margin-bottom:.4rem; }
.hero-title { font-size:2.15rem; font-weight:700; letter-spacing:-.045em; margin:0; color:#f7f9fc; }
.hero-sub { color:#8793a6; margin-top:.55rem; font-size:.94rem; }
.status-pill { display:inline-flex; align-items:center; gap:.5rem; padding:.45rem .72rem; border-radius:999px; background:rgba(255,107,69,.1); border:1px solid rgba(255,107,69,.28); color:#ff8a6c; font-family:'IBM Plex Mono'; font-size:.72rem; letter-spacing:.07em; }
.status-pill.ok { background:rgba(77,226,197,.1); border-color:rgba(77,226,197,.28); color:#4de2c5; }
.pulse { width:7px; height:7px; background:#ff6b45; border-radius:50%; box-shadow:0 0 0 4px rgba(255,107,69,.12); }
.status-pill.ok .pulse { background:#4de2c5; box-shadow:0 0 0 4px rgba(77,226,197,.12); }

.metric-card { background:linear-gradient(145deg,rgba(20,28,41,.96),rgba(13,18,27,.96)); border:1px solid #242e3d; border-radius:14px; padding:1.05rem 1.15rem; min-height:118px; box-shadow:0 12px 35px rgba(0,0,0,.16); }
.metric-label { color:#78869a; font-size:.72rem; letter-spacing:.08em; text-transform:uppercase; margin-bottom:.65rem; }
.metric-value { color:#f0f4fa; font-family:'IBM Plex Mono'; font-size:1.65rem; font-weight:600; line-height:1.05; }
.metric-foot { color:#6f7d91; font-size:.72rem; margin-top:.65rem; }
.accent-high { color:#ff6b45; }
.accent-green { color:#4de2c5; }

.section-kicker { font-family:'IBM Plex Mono'; font-size:.68rem; color:#4de2c5; letter-spacing:.16em; margin:2rem 0 .35rem; }
.section-title { font-size:1.12rem; font-weight:650; margin:0 0 1rem; }
.panel { background:rgba(15,21,31,.9); border:1px solid #222c3b; border-radius:14px; padding:1.15rem; }
.flow { display:grid; grid-template-columns:repeat(auto-fit, minmax(150px, 1fr)); gap:.55rem; align-items:stretch; }
.flow-node { position:relative; padding:.9rem .75rem; background:#111925; border:1px solid #283447; border-radius:11px; min-height:70px; }
.flow-node:not(:last-child):after { content:'›'; position:absolute; right:-.52rem; top:32%; color:#53627a; z-index:3; font-size:1.25rem; }
.flow-num { font-family:'IBM Plex Mono'; color:#4de2c5; font-size:.65rem; }
.flow-name { font-weight:600; font-size:.82rem; margin:.35rem 0; color:#e8edf5; }
.flow-state { font-size:.7rem; color:#8b98aa; }
.flow-alert { border-color:rgba(255,107,69,.42); background:linear-gradient(145deg,#1b1a20,#151820); }

.test-row { display:grid; grid-template-columns:1.25fr .8fr .8fr 1fr; gap:.6rem; align-items:center; padding:.73rem .85rem; border-bottom:1px solid #222b39; font-size:.79rem; }
.test-row:last-child { border-bottom:0; }
.test-head { color:#718095; font-size:.67rem; text-transform:uppercase; letter-spacing:.08em; }
.mono { font-family:'IBM Plex Mono'; }
.badge { display:inline-block; border-radius:6px; padding:.25rem .48rem; font-size:.66rem; font-weight:600; }
.badge-ok { color:#53e2c6; background:rgba(77,226,197,.1); border:1px solid rgba(77,226,197,.24); }
.badge-bad { color:#ff8d71; background:rgba(255,107,69,.1); border:1px solid rgba(255,107,69,.24); }

.impact-card { padding:.9rem; border:1px solid #263143; border-radius:11px; background:#101722; margin-bottom:.65rem; }
.impact-top { display:flex; justify-content:space-between; gap:1rem; }
.service { font-family:'IBM Plex Mono'; color:#f0f4fa; font-weight:600; }
.resource { color:#7f8ca0; font-size:.72rem; margin:.25rem 0 .55rem; }
.perm { display:inline-block; padding:.18rem .42rem; margin:.12rem; border-radius:5px; background:#172335; color:#9fb3cc; font:500 .64rem 'IBM Plex Mono'; }
.evidence { display:flex; gap:.75rem; padding:.65rem 0; border-bottom:1px solid #212a37; color:#aeb9c8; font-size:.78rem; }
.evidence:last-child { border:0; }
.evidence-mark { color:#4de2c5; font-family:'IBM Plex Mono'; }
.recommend { display:flex; gap:.7rem; padding:.72rem .8rem; margin-bottom:.5rem; background:#101722; border-left:2px solid #4de2c5; border-radius:0 8px 8px 0; color:#b8c2d1; font-size:.78rem; }
.summary-box { padding:1rem 1.1rem; background:rgba(255,107,69,.07); border:1px solid rgba(255,107,69,.25); border-radius:11px; color:#d6dce6; line-height:1.65; font-size:.82rem; }
.footer-note { color:#566377; font:400 .68rem 'IBM Plex Mono'; text-align:right; margin-top:2rem; }
.intro-panel { padding:1.4rem 1.5rem; }
div[data-testid="stDownloadButton"] button { width:100%; background:#172236; color:#dbe5f2; border:1px solid #2b3a50; }
div[data-testid="stDownloadButton"] button:hover { border-color:#4de2c5; color:#4de2c5; }
@media(max-width:900px){ .flow-node:not(:last-child):after{display:none;} .block-container{padding:1.2rem;} }
</style>
""",
    unsafe_allow_html=True,
)


def e(value: Any) -> str:
    return escape(str(value))


def format_time(raw: str) -> str:
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00")).strftime("%Y.%m.%d  %H:%M UTC")
    except (ValueError, AttributeError, TypeError):
        return raw or "-"


def split_target(value: str) -> tuple[str, str]:
    """사용자가 입력한 URL 하나를 base_url(사이트 루트)과 fetch_url(SSRF/OS-Cmd 대상)로 분리한다."""
    base = value.strip().rstrip("/")
    if base.lower().endswith("/fetch"):
        base = base[: -len("/fetch")].rstrip("/")
    return base, base + "/fetch"


def validate_target(value: str) -> tuple[bool, str]:
    value = value.strip()

    if not value:
        return False, "Target URL을 입력하세요."

    try:
        parsed = urlparse(value)
    except Exception:
        return False, "올바른 URL 형식이 아닙니다."

    if parsed.scheme not in {"http", "https"}:
        return False, "http:// 또는 https:// 로 시작하는 URL을 입력하세요."

    if not parsed.hostname:
        return False, "호스트가 포함된 URL을 입력하세요."

    if parsed.hostname == "169.254.169.254":
        return False, "Target에는 IMDS 주소가 아니라 진단할 웹 애플리케이션 루트 URL을 입력하세요."

    return True, ""


def mask_identifier(value: Any, visible: int = 4) -> Any:
    if not isinstance(value, str) or len(value) <= visible:
        return value
    return value[:visible] + "****REDACTED"


def sanitize_raw_scan_result(raw: dict[str, Any]) -> dict[str, Any]:
    """scan_result.json 다운로드용 — cloud_impact.principal(AWS 계정/ARN 등)만 마스킹한다."""
    safe = copy.deepcopy(raw)
    stages = safe.get("stages")
    principal = stages.get("cloud_impact", {}).get("principal") if isinstance(stages, dict) else None
    if isinstance(principal, dict):
        if principal.get("account"):
            principal["account"] = mask_identifier(principal["account"], 3)
        if principal.get("arn"):
            principal["arn"] = "REDACTED"
        if principal.get("user_id"):
            principal["user_id"] = "REDACTED"
    return safe


def run_full_pipeline(base_url: str, fetch_url: str) -> dict[str, Any]:
    if not DIAGNOSIS_MAIN.exists():
        raise FileNotFoundError(f"main.py를 찾을 수 없습니다: {DIAGNOSIS_MAIN}")
    if not ANALYZE_MAIN.exists():
        raise FileNotFoundError(f"ai/analyze.py를 찾을 수 없습니다: {ANALYZE_MAIN}")
    if not ANALYZE_ETC_MAIN.exists():
        raise FileNotFoundError(f"ai_etc/analyze_etc.py를 찾을 수 없습니다: {ANALYZE_ETC_MAIN}")

    # 이전 실행 결과가 이번 실행 결과처럼 보이는 것을 방지 (스킵된 취약점의 리포트가 안 지워지고 남는 문제)
    for stale in [SCAN_RESULT_JSON, AI_REPORT_JSON, REPORT_MD, AI_REPORT_ETC_JSON, *REPORT_ETC_MD_PATHS.values()]:
        stale.unlink(missing_ok=True)

    progress = st.progress(0.0, text="진단 준비 중")
    status_text = st.empty()
    log_box = st.empty()
    logs: list[str] = []

    child_env = os.environ.copy()
    child_env["PYTHONIOENCODING"] = "utf-8"
    child_env["PYTHONUTF8"] = "1"

    def stream(command: list[str], cwd: Path, label: str) -> int:
        logs.append(f"\n[$] cd {cwd.name} && {' '.join(command)}")
        log_box.code("\n".join(logs[-16:]), language="text")

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
            log_box.code("\n".join(logs[-16:]), language="text")

            matched = False
            for marker, (value, stage_label) in STAGE_PROGRESS.items():
                if marker in line:
                    progress.progress(value, text=stage_label)
                    status_text.caption(stage_label)
                    matched = True
                    break
            if not matched:
                status_text.caption(label)

        return process.wait()

    # 1단계: diagnosis/main.py  <fetch_url> -o scan_result.json --base-url <base_url>  (cwd = dashboard/)
    # --base-url이 있어야 Stage 6(SQLi)/7(Stored XSS)이 /login,/register,/search,/post/new,/gallery/upload
    # 등 실제 후보 엔드포인트를 대상으로 진단한다. (없으면 두 단계 모두 스킵됨)
    status_text.caption("1~8단계 취약점 진단 실행 중 (수 분 소요될 수 있음)")
    code1 = stream(
        [sys.executable, "-u", str(DIAGNOSIS_MAIN), fetch_url,
         "-o", str(SCAN_RESULT_JSON), "--base-url", base_url],
        cwd=PROJECT_ROOT,
        label="1~8단계 진단 실행 중",
    )
    if code1 != 0:
        progress.progress(0.0, text="진단 실패")
        raise RuntimeError("diagnosis/main.py 실행 중 오류가 발생했습니다. 위 실행 로그를 확인하세요.")
    if not SCAN_RESULT_JSON.exists():
        raise FileNotFoundError(f"진단은 종료됐지만 결과 JSON을 찾을 수 없습니다: {SCAN_RESULT_JSON}")

    # 2단계: diagnosis/ai/analyze.py --input scan_result.json   (SSRF 전용, cwd = diagnosis/)
    status_text.caption("SSRF AI Security Report 생성 중 (수 분 소요될 수 있음)")
    code2 = stream(
        [sys.executable, "-u", str(ANALYZE_MAIN), "--input", SCAN_RESULT_JSON.name],
        cwd=DIAGNOSIS_DIR,
        label="SSRF AI Security Report 생성 중",
    )
    if code2 != 0:
        progress.progress(0.55, text="SSRF AI 리포트 생성 실패")
        raise RuntimeError("ai/analyze.py 실행 중 오류가 발생했습니다. 위 실행 로그를 확인하세요.")

    # 3단계: diagnosis/ai_etc/analyze_etc.py --input scan_result.json   (SQLi/XSS/OS-CMD, cwd = diagnosis/)
    status_text.caption("SQLi / Stored XSS / OS Command Injection AI Report 생성 중 (수 분 소요될 수 있음)")
    code3 = stream(
        [sys.executable, "-u", str(ANALYZE_ETC_MAIN), "--input", SCAN_RESULT_JSON.name],
        cwd=DIAGNOSIS_DIR,
        label="SQLi / XSS / OS-CMD AI Report 생성 중",
    )
    if code3 != 0:
        progress.progress(0.80, text="SQLi/XSS/OS-CMD AI 리포트 생성 실패")
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
    progress.progress(1.0, text="진단 완료")
    status_text.success(f"전체 파이프라인이 완료되었습니다. ({n_ok}/4개 리포트 생성됨)")

    return {
        "raw": raw_scan,
        "ssrf": {"markdown": ssrf_md, "ai_meta": ssrf_ai_meta},
        "etc_reports": etc_reports,
        "target": {"base_url": base_url, "fetch_url": fetch_url},
        "_dashboard_timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def risk_gauge(score: float, color: str):
    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score,
            number={"font": {"size": 34, "color": "#f0f4fa", "family": "IBM Plex Mono"}, "suffix": "/10"},
            gauge={
                "axis": {"range": [0, 10], "tickwidth": 0, "tickfont": {"color": "#657287", "size": 10}},
                "bar": {"color": color, "thickness": 0.28},
                "bgcolor": "#151d29",
                "borderwidth": 0,
                "steps": [
                    {"range": [0, 3], "color": "#15231f"},
                    {"range": [3, 6], "color": "#282318"},
                    {"range": [6, 8], "color": "#2b1d18"},
                    {"range": [8, 10], "color": "#2a171d"},
                ],
            },
        )
    )
    fig.update_layout(height=210, margin=dict(l=22, r=22, t=28, b=10), paper_bgcolor="rgba(0,0,0,0)", font={"color": "#8390a3"})
    return fig


def extract_verdict(markdown_text: str) -> tuple[str, bool]:
    """report_etc_*.md 상단의 '**진단 결과: ...**' 배지 줄을 읽어 (표시 텍스트, 취약 여부)를 반환한다."""
    m = re.search(r"\*\*진단 결과:\s*(.+?)\*\*", markdown_text)
    label = m.group(1).strip() if m else "결과 미상"
    is_vulnerable = "VULNERABLE" in label.upper()
    return label, is_vulnerable


def sqli_rows(stages: dict[str, Any]) -> list[tuple[str, str, str, str]]:
    items = stages.get("sqli_diagnosis")
    rows: list[tuple[str, str, str, str]] = []
    if not isinstance(items, list):
        return rows
    for item in items:
        if not isinstance(item, dict):
            continue
        param = item.get("parameter") or {}
        techniques = ", ".join(
            SQLI_TECHNIQUE_LABELS.get(t.get("technique"), str(t.get("technique")))
            for t in (item.get("tests") or []) if isinstance(t, dict)
        ) or "-"
        rows.append((
            str(item.get("endpoint", "-")),
            f"{param.get('name', '-')} · {param.get('method', '-')}/{param.get('location', '-')}",
            techniques,
            str(item.get("result", "unknown")),
        ))
    return rows


def xss_rows(stages: dict[str, Any]) -> list[tuple[str, str, str, str]]:
    block = stages.get("stored_xss")
    rows: list[tuple[str, str, str, str]] = []
    if not isinstance(block, dict):
        return rows
    for item in block.get("injection_points") or []:
        if not isinstance(item, dict):
            continue
        rows.append((
            str(item.get("endpoint", "-")),
            f"{item.get('parameter', '-')} · {item.get('method', '-')}",
            str(item.get("payload", "-")),
            "vulnerable" if item.get("vulnerable") else "safe",
        ))
    return rows


def cmd_rows(stages: dict[str, Any]) -> list[tuple[str, str, str, str]]:
    block = stages.get("os_command_injection")
    rows: list[tuple[str, str, str, str]] = []
    if not isinstance(block, dict):
        return rows
    for item in block.get("results") or []:
        if not isinstance(item, dict):
            continue
        rows.append((
            str(item.get("parameter", "-")),
            f"{item.get('method', '-')} · {item.get('location', '-')}",
            str(item.get("detection") or "-"),
            str(item.get("result", "unknown")),
        ))
    return rows


def login_limit_rows(stages: dict[str, Any]) -> list[tuple[str, str, str, str]]:
    block = stages.get("login_rate_limit")
    if not isinstance(block, dict):
        return []
    if block.get("skipped"):
        return []
    summary = block.get("summary") or {}

    def yn(v: Any) -> str:
        return "예" if v else "아니오"

    return [
        ("Rate limit 감지", yn(summary.get("rate_limit_detected")), "연속 로그인 시도 제한 장치",
         "감지" if summary.get("rate_limit_detected") else "미감지"),
        ("차단(blocking) 감지", yn(summary.get("blocking_detected")), "IP/계정 차단 장치",
         "감지" if summary.get("blocking_detected") else "미감지"),
        ("CAPTCHA 감지", yn(summary.get("captcha_detected")), "자동화 방지 장치",
         "감지" if summary.get("captcha_detected") else "미감지"),
        ("완료 시도", f"{block.get('completed_attempts', '-')}/{block.get('configured_attempts', '-')}",
         "무차별 대입 시뮬레이션(비파괴)", str(block.get("stopped_reason") or "-")),
    ]


DETAIL_ROWS_FN: dict[str, tuple[list[str], Any]] = {
    "sqli": (["ENDPOINT", "PARAMETER", "TECHNIQUE", "RESULT"], sqli_rows),
    "stored_xss": (["ENDPOINT", "PARAMETER", "PAYLOAD", "RESULT"], xss_rows),
    "os_command_injection": (["PARAMETER", "METHOD / LOCATION", "DETECTION", "RESULT"], cmd_rows),
    "login_rate_limit": (["점검 항목", "관측값", "비고", "결과"], login_limit_rows),
}


def render_detail_grid(headers: list[str], rows: list[tuple[str, str, str, str]]) -> None:
    head_html = "".join(f"<div class='test-head'>{e(h)}</div>" for h in headers)
    body_html = []
    for c1, c2, c3, result in rows:
        normalized = str(result).lower()
        vulnerable = normalized in {"vulnerable", "true"}
        safe = normalized in {"safe", "false"}
        badge_cls = "badge-bad" if vulnerable else "badge-ok"
        badge_txt = "VULNERABLE" if vulnerable else ("SAFE" if safe else str(result).upper())
        body_html.append(
            "<div class='test-row'>"
            f"<div>{e(c1)}</div>"
            f"<div class='mono'>{e(c2)}</div>"
            f"<div class='mono'>{e(c3)}</div>"
            f"<div><span class='badge {badge_cls}'>{e(badge_txt)}</span></div>"
            "</div>"
        )
    st.markdown(
        "<div class='panel' style='padding:0'>"
        f"<div class='test-row'>{head_html}</div>"
        f"{''.join(body_html)}"
        "</div>",
        unsafe_allow_html=True,
    )


def render_ssrf_tab(result: dict[str, Any]) -> None:
    markdown_text = result["ssrf"]["markdown"] or ""
    raw = result.get("raw", {}) or {}
    json_result = normalize_scan_result(raw)

    sections = parse_sections(markdown_text)
    meta = extract_meta(markdown_text)
    report_title = get_report_title(sections)

    severity = meta["severity"].lower()
    score = meta["score"]
    color = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["unknown"])

    target_endpoint = meta["target"] or json_result.get("target", {}).get("endpoint", "-")
    generated_at = meta["generated_at"] or format_time(result.get("_dashboard_timestamp", ""))

    section_risk = find_section(sections, "종합 위험도")
    section_vuln = find_section(sections, "취약점 분류")
    section_evidence = find_section(sections, "자동 진단 증거")
    section_cve = find_section(sections, "관련 CVE")
    section_breach = find_section(sections, "실제 침해")
    section_official = find_section(sections, "공식 보안 권고")
    section_analysis = find_section(sections, "종합 분석")
    section_recs = find_section(sections, "대응방안")

    evidence_list = extract_evidence_list(section_evidence["body"]) if section_evidence else []
    recommendation_list = extract_recommendation_list(section_recs["body"]) if section_recs else []
    cve_count = count_subheadings(section_cve["body"]) if section_cve else 0

    attack_chain_text = extract_subsection(section_vuln["body"], "공격 체인") if section_vuln else ""
    attack_chain_steps = extract_numbered_list(attack_chain_text)

    reasoning = ""
    if section_risk:
        m = re.search(r"판단 근거:\s*(.+)", section_risk["body"])
        reasoning = m.group(1).strip() if m else strip_meta_bullets(section_risk["body"])

    ai_report_meta = result["ssrf"].get("ai_meta", {}) or {}

    assessments = json_result.get("imds_credential_exposure", {}).get("assessments", [])
    first_assessment = assessments[0] if assessments else {}
    imds_info = first_assessment.get("imds", {})
    role = first_assessment.get("iam_role", {})
    credentials = first_assessment.get("temporary_credentials", {})
    cloud = json_result.get("cloud_impact_assessment", {})
    impacts = cloud.get("cloud_impact", [])
    accessible_impacts = [
        item for item in impacts
        if item.get("accessible") is True and str(item.get("service", "")).upper() in {"S3", "LAMBDA"}
    ]

    head_left, head_right = st.columns([4, 1], vertical_alignment="center")
    with head_left:
        st.markdown("<div class='brand'>SECURITY ASSESSMENT / RESULT</div>", unsafe_allow_html=True)
        st.markdown(f"<h1 class='hero-title'>{e(report_title)}</h1>", unsafe_allow_html=True)
        st.markdown(
            f"<div class='hero-sub'><span class='mono'>{e(target_endpoint)}</span> · {e(generated_at)}</div>",
            unsafe_allow_html=True,
        )
    with head_right:
        pill_class = "ok" if severity in {"low", "unknown"} else ""
        st.markdown(
            f"<div style='text-align:right'><span class='status-pill {pill_class}'><span class='pulse'></span>{e(severity.upper())} RISK</span></div>",
            unsafe_allow_html=True,
        )

    st.markdown("<div style='height:1.15rem'></div>", unsafe_allow_html=True)
    m1, m2, m3, m4 = st.columns(4)
    cards = [
        (m1, "RISK SCORE", f"{score:.1f}", "10점 기준 종합 위험도", "accent-high" if score >= 6 else "accent-green"),
        (m2, "핵심 근거", str(len(evidence_list)), "자동 진단 증거 항목", ""),
        (m3, "관련 CVE", str(cve_count), "유사 공격 패턴 참고", "accent-high" if cve_count else "accent-green"),
        (m4, "권고 조치", str(len(recommendation_list)), "우선순위별 대응방안", ""),
    ]
    for col, label, value, foot, cls in cards:
        col.markdown(
            f"<div class='metric-card'><div class='metric-label'>{e(label)}</div><div class='metric-value {cls}'>{e(value)}</div><div class='metric-foot'>{e(foot)}</div></div>",
            unsafe_allow_html=True,
        )

    st.markdown("<div class='section-kicker'>ATTACK PATH</div><div class='section-title'>공격 체인</div>", unsafe_allow_html=True)
    if attack_chain_steps:
        flow_html = "".join(
            f"<div class='flow-node'><div class='flow-num'>{idx:02d}</div><div class='flow-name'>{e(step)}</div></div>"
            for idx, step in enumerate(attack_chain_steps, 1)
        )
        st.markdown(f"<div class='panel'><div class='flow'>{flow_html}</div></div>", unsafe_allow_html=True)
    else:
        st.markdown("<div class='panel'>공격 체인 정보를 찾지 못했습니다.</div>", unsafe_allow_html=True)

    left, right = st.columns([1.55, 1])
    with left:
        st.markdown("<div class='section-kicker'>EVIDENCE</div><div class='section-title'>자동 진단 증거</div>", unsafe_allow_html=True)
        evidence_html = "".join(
            f"<div class='evidence'><span class='evidence-mark'>[{idx:02d}]</span><span>{e(item)}</span></div>"
            for idx, item in enumerate(evidence_list, 1)
        ) or "<div class='evidence'>탐지 근거가 없습니다.</div>"
        st.markdown(f"<div class='panel'>{evidence_html}</div>", unsafe_allow_html=True)

        if section_vuln:
            vuln_body = extract_subsection(section_vuln["body"], "공격 체인")
            vuln_intro = section_vuln["body"]
            if vuln_body:
                vuln_intro = section_vuln["body"].split("### ", 1)[0].strip()
            st.markdown("<div class='section-kicker'>CLASSIFICATION</div><div class='section-title'>취약점 분류</div>", unsafe_allow_html=True)
            with st.container(border=True):
                st.markdown(vuln_intro or "_내용 없음_")

    with right:
        st.markdown("<div class='section-kicker'>RISK</div><div class='section-title'>종합 위험도</div>", unsafe_allow_html=True)
        st.markdown("<div class='panel'>", unsafe_allow_html=True)
        st.plotly_chart(risk_gauge(score, color), width="stretch", config={"displayModeBar": False})
        st.markdown(f"<div class='summary-box'>{e(reasoning or '요약 정보가 없습니다.')}</div>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

        st.markdown("<div class='section-kicker'>EXPOSURE</div><div class='section-title'>IMDS 및 자격증명</div>", unsafe_allow_html=True)
        exposure_rows = [
            ("IMDS 연결", "REACHABLE" if imds_info.get("reachable") else "NOT FOUND"),
            ("검증 버전", imds_info.get("version_tested", "-")),
            ("IAM Role", role.get("role_name", "-") if role.get("detected") else "미탐지"),
            ("임시 자격증명", "EXPOSED · MASKED" if credentials.get("exposed") else "SAFE"),
        ]
        exposure_html = "".join(
            f"<div class='test-row' style='grid-template-columns:1fr 1.4fr'><div style='color:#78869a'>{e(k)}</div><div class='mono' style='font-size:.72rem;color:{'#ff8d71' if ('REACHABLE' in str(v) or 'EXPOSED' in str(v)) else '#d7deea'}'>{e(v)}</div></div>"
            for k, v in exposure_rows
        )
        st.markdown(f"<div class='panel' style='padding:.35rem .7rem'>{exposure_html}</div>", unsafe_allow_html=True)

    st.markdown("<div class='section-kicker'>CLOUD BLAST RADIUS</div><div class='section-title'>클라우드 영향 범위</div>", unsafe_allow_html=True)
    if accessible_impacts:
        impact_cols = st.columns(max(1, min(3, len(accessible_impacts))))
        for idx, impact in enumerate(accessible_impacts):
            assets = impact.get("assets") or []
            asset_count = impact.get("asset_count", len(assets))
            permissions = "".join(f"<span class='perm'>{e(a)}</span>" for a in assets[:8])
            if len(assets) > 8:
                permissions += f"<span class='perm'>+{len(assets) - 8}</span>"
            impact_cols[idx % len(impact_cols)].markdown(
                "<div class='impact-card'>"
                "<div class='impact-top'>"
                f"<span class='service'>{e(impact.get('service', '-'))}</span>"
                f"<span class='badge badge-bad'>{e(str(impact.get('impact', '-')).upper())}</span>"
                "</div>"
                f"<div class='resource'>{e(impact.get('action', '-'))} · {e(asset_count)}개 권한 확인</div>"
                f"<div>{permissions}</div>"
                "</div>",
                unsafe_allow_html=True,
            )
    else:
        st.info("확인된 클라우드 영향이 없습니다.")

    st.markdown("<div class='section-kicker'>REMEDIATION</div><div class='section-title'>권고 조치</div>", unsafe_allow_html=True)
    if recommendation_list:
        rec_cols = st.columns(2)
        for idx, rec in enumerate(recommendation_list):
            rec_cols[idx % 2].markdown(
                f"<div class='recommend'><span class='mono'>{idx + 1:02d}</span><span>{e(rec)}</span></div>",
                unsafe_allow_html=True,
            )
    else:
        st.info("권고 조치 정보가 없습니다.")

    if ai_report_meta.get("fallback_reason"):
        st.caption(f"※ AI 분석 대신 규칙 기반 리포트가 사용되었습니다: {ai_report_meta['fallback_reason']}")

    st.divider()
    st.subheader("심층 리포트")
    narrative_sections = [
        ("CVE INTEL", "관련 CVE", section_cve),
        ("BREACH INTEL", "실제 침해 / 공개 사례", section_breach),
        ("OFFICIAL GUIDANCE", "공식 보안 권고", section_official),
        ("DEEP DIVE", "종합 분석", section_analysis),
    ]
    for kicker, label, section in narrative_sections:
        st.markdown(f"<div class='section-kicker'>{e(kicker)}</div><div class='section-title'>{e(label)}</div>", unsafe_allow_html=True)
        with st.container(border=True):
            st.markdown((section["body"] if section else "") or "_내용을 찾지 못했습니다._")

    st.markdown(f"<div class='footer-note'>SSRF SENTINEL · TARGET {e(target_endpoint.upper())}</div>", unsafe_allow_html=True)


def render_vuln_tab(vuln_type: str, markdown_text: str, raw: dict[str, Any]) -> None:
    sections = parse_sections(markdown_text)
    meta = extract_meta(markdown_text)
    report_title = get_report_title(sections)
    verdict_label, is_vulnerable = extract_verdict(markdown_text)

    severity = meta["severity"].lower()
    score = meta["score"]
    color = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["unknown"])

    target_endpoint = meta["target"] or (raw.get("meta", {}) or {}).get("target", "-")
    generated_at = meta["generated_at"] or format_time((raw.get("meta", {}) or {}).get("timestamp", ""))

    section_risk = find_section(sections, "위험도")
    section_vuln = find_section(sections, "취약점 분류")
    section_evidence = find_section(sections, "자동 진단 증거")
    section_cve = find_section(sections, "관련 CVE")
    section_breach = find_section(sections, "실제 침해")
    section_official = find_section(sections, "공식 보안 권고")
    section_analysis = find_section(sections, "종합 분석")
    section_recs = find_section(sections, "대응방안")
    section_sources = find_section(sections, "검색 출처")

    evidence_list = extract_evidence_list(section_evidence["body"]) if section_evidence else []
    recommendation_list = extract_recommendation_list(section_recs["body"]) if section_recs else []
    cve_count = count_subheadings(section_cve["body"]) if section_cve else 0

    attack_chain_text = extract_subsection(section_vuln["body"], "공격 체인") if section_vuln else ""
    attack_chain_steps = extract_numbered_list(attack_chain_text)

    reasoning = ""
    if section_risk:
        m = re.search(r"판단 근거:\s*(.+)", section_risk["body"])
        reasoning = m.group(1).strip() if m else strip_meta_bullets(section_risk["body"])

    stages = raw.get("stages", {}) or {}
    grid = DETAIL_ROWS_FN.get(vuln_type)
    if grid:
        headers, rows_fn = grid
        detail_rows = rows_fn(stages if isinstance(stages, dict) else {})
    else:
        headers, detail_rows = [], []

    head_left, head_right = st.columns([4, 1], vertical_alignment="center")
    with head_left:
        st.markdown(f"<div class='brand'>{e(TAB_LABELS[vuln_type].upper())} / RESULT</div>", unsafe_allow_html=True)
        st.markdown(f"<h1 class='hero-title'>{e(report_title)}</h1>", unsafe_allow_html=True)
        st.markdown(
            f"<div class='hero-sub'><span class='mono'>{e(target_endpoint)}</span> · {e(generated_at)}</div>",
            unsafe_allow_html=True,
        )
    with head_right:
        pill_class = "" if is_vulnerable else "ok"
        st.markdown(
            f"<div style='text-align:right'><span class='status-pill {pill_class}'><span class='pulse'></span>{e(verdict_label)}</span></div>",
            unsafe_allow_html=True,
        )

    st.markdown("<div style='height:1.15rem'></div>", unsafe_allow_html=True)
    m1, m2, m3, m4 = st.columns(4)
    cards = [
        (m1, "RISK SCORE", f"{score:.1f}", "10점 기준 위험도", "accent-high" if score >= 6 else "accent-green"),
        (m2, "핵심 근거", str(len(evidence_list)), "자동 진단 증거 항목", ""),
        (m3, "관련 CVE", str(cve_count), "유사 공격 패턴 참고", "accent-high" if cve_count else "accent-green"),
        (m4, "권고 조치", str(len(recommendation_list)), "우선순위별 대응방안", ""),
    ]
    for col, label, value, foot, cls in cards:
        col.markdown(
            f"<div class='metric-card'><div class='metric-label'>{e(label)}</div><div class='metric-value {cls}'>{e(value)}</div><div class='metric-foot'>{e(foot)}</div></div>",
            unsafe_allow_html=True,
        )

    st.markdown("<div class='section-kicker'>ATTACK PATH</div><div class='section-title'>공격 체인</div>", unsafe_allow_html=True)
    if attack_chain_steps:
        flow_html = "".join(
            f"<div class='flow-node'><div class='flow-num'>{idx:02d}</div><div class='flow-name'>{e(step)}</div></div>"
            for idx, step in enumerate(attack_chain_steps, 1)
        )
        st.markdown(f"<div class='panel'><div class='flow'>{flow_html}</div></div>", unsafe_allow_html=True)
    else:
        st.markdown("<div class='panel'>공격 체인 정보를 찾지 못했습니다.</div>", unsafe_allow_html=True)

    left, right = st.columns([1.55, 1])
    with left:
        st.markdown("<div class='section-kicker'>EVIDENCE</div><div class='section-title'>자동 진단 증거</div>", unsafe_allow_html=True)
        evidence_html = "".join(
            f"<div class='evidence'><span class='evidence-mark'>[{idx:02d}]</span><span>{e(item)}</span></div>"
            for idx, item in enumerate(evidence_list, 1)
        ) or "<div class='evidence'>탐지 근거가 없습니다.</div>"
        st.markdown(f"<div class='panel'>{evidence_html}</div>", unsafe_allow_html=True)

        if section_vuln:
            vuln_body = extract_subsection(section_vuln["body"], "공격 체인")
            vuln_intro = section_vuln["body"]
            if vuln_body:
                vuln_intro = section_vuln["body"].split("### ", 1)[0].strip()
            st.markdown("<div class='section-kicker'>CLASSIFICATION</div><div class='section-title'>취약점 분류</div>", unsafe_allow_html=True)
            with st.container(border=True):
                st.markdown(vuln_intro or "_내용 없음_")

    with right:
        st.markdown("<div class='section-kicker'>RISK</div><div class='section-title'>위험도</div>", unsafe_allow_html=True)
        st.markdown("<div class='panel'>", unsafe_allow_html=True)
        st.plotly_chart(risk_gauge(score, color), width="stretch", config={"displayModeBar": False})
        st.markdown(f"<div class='summary-box'>{e(reasoning or '요약 정보가 없습니다.')}</div>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown(
        f"<div class='section-kicker'>RAW DATA</div><div class='section-title'>자동 진단 상세 ({len(detail_rows)}건)</div>",
        unsafe_allow_html=True,
    )
    if detail_rows:
        render_detail_grid(headers, detail_rows)
    else:
        st.info("원본 진단 상세 데이터가 없습니다.")

    st.markdown("<div class='section-kicker'>REMEDIATION</div><div class='section-title'>대응방안</div>", unsafe_allow_html=True)
    if recommendation_list:
        rec_cols = st.columns(2)
        for idx, rec in enumerate(recommendation_list):
            rec_cols[idx % 2].markdown(
                f"<div class='recommend'><span class='mono'>{idx + 1:02d}</span><span>{e(rec)}</span></div>",
                unsafe_allow_html=True,
            )
    else:
        st.info("대응방안 정보가 없습니다.")

    st.divider()
    st.subheader("심층 리포트")
    narrative_sections = [
        ("CVE INTEL", "관련 CVE", section_cve),
        ("BREACH INTEL", "실제 침해 / 공개 사례", section_breach),
        ("OFFICIAL GUIDANCE", "공식 보안 권고", section_official),
        ("DEEP DIVE", "종합 분석", section_analysis),
        ("WEB SOURCES", "검색 출처 (Web)", section_sources),
    ]
    for kicker, label, section in narrative_sections:
        st.markdown(f"<div class='section-kicker'>{e(kicker)}</div><div class='section-title'>{e(label)}</div>", unsafe_allow_html=True)
        with st.container(border=True):
            st.markdown((section["body"] if section else "") or "_내용을 찾지 못했습니다._")

    st.markdown(f"<div class='footer-note'>{e(TAB_LABELS[vuln_type].upper())} · TARGET {e(target_endpoint.upper())}</div>", unsafe_allow_html=True)


def render_missing(tab: str) -> None:
    label = TAB_LABELS[tab]
    reasons = {
        "ssrf": "- diagnosis/ai/analyze.py 실행이 실패했거나 report.md / ai_report.json이 생성되지 않았습니다.",
        "sqli": (
            "- --base-url로 지정한 대상에 /login, /register 등 SQLi 진단 후보 엔드포인트가 없거나 접근할 수 없었을 수 있습니다.\n"
            "- 또는 AI 리포트 생성(ai_etc/analyze_etc.py)이 실패했을 수 있습니다."
        ),
        "stored_xss": (
            "- --base-url로 지정한 대상에 /post/new, /gallery/upload 등 진단 후보 엔드포인트가 없거나 접근할 수 없었을 수 있습니다.\n"
            "- 또는 AI 리포트 생성(ai_etc/analyze_etc.py)이 실패했을 수 있습니다."
        ),
        "os_command_injection": (
            "- Stage 1(Parameter Discovery)에서 발견된 파라미터가 없었을 수 있습니다.\n"
            "- 또는 AI 리포트 생성(ai_etc/analyze_etc.py)이 실패했을 수 있습니다."
        ),
        "login_rate_limit": (
            "- --base-url로 지정한 대상에 /login 엔드포인트가 없거나 접근할 수 없었을 수 있습니다.\n"
            "- 또는 AI 리포트 생성(ai_etc/analyze_etc.py)이 실패했을 수 있습니다."
        ),
    }
    st.markdown(
        f"<div class='section-kicker'>NO REPORT</div><div class='section-title'>{e(label)} 결과 없음</div>",
        unsafe_allow_html=True,
    )
    st.warning(
        f"**{label}** 진단 리포트가 아직 없습니다. 아래 원인 중 하나일 수 있습니다.\n\n"
        f"{reasons.get(tab, '- 원인을 알 수 없습니다.')}\n\n"
        "OPENAI_API_KEY 설정, Target URL 접근 가능 여부, 위쪽 실행 로그를 확인한 뒤 "
        "'진단 시작'을 다시 눌러 재시도해보세요."
    )


# ── 사이드바 ──────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("<div class='brand'>VULN SENTINEL</div>", unsafe_allow_html=True)

    if "pipeline_result" not in st.session_state:
        st.markdown("### 진단 콘솔")
        st.caption(
            "Target URL을 입력하고 진단을 시작하면 SSRF / SQL Injection / Stored XSS / "
            "OS Command Injection 리포트가 아래 버튼으로 표시됩니다."
        )
    else:
        pipeline_result = st.session_state["pipeline_result"]
        st.markdown("### 취약점 리포트")
        st.caption("현재 진단 대상")
        st.code(pipeline_result["target"]["base_url"], language=None)

        active_tab = st.session_state.get("active_tab", "ssrf")

        def _has_report(tab: str) -> bool:
            if tab == "ssrf":
                return bool(pipeline_result["ssrf"]["markdown"])
            return bool(pipeline_result["etc_reports"].get(tab))

        for tab in TABS:
            available = _has_report(tab)
            btn_type = "primary" if active_tab == tab else "secondary"
            if st.button(TAB_LABELS[tab], key=f"tab_btn_{tab}", type=btn_type, use_container_width=True):
                # 탭이 바뀌면 즉시 rerun 해서 모든 버튼의 하이라이트(primary/secondary)가
                # 새 active_tab 기준으로 다시 그려지게 한다. rerun이 없으면 이번 렌더에서
                # 이미 그려진 버튼들은 이전 active_tab 색을 그대로 유지해 한 박자 늦게 표시됨.
                if st.session_state.get("active_tab") != tab:
                    st.session_state["active_tab"] = tab
                    st.rerun()
            if not available:
                st.caption("결과 없음 · 클릭 시 안내 표시")

        st.markdown("---")

        active_md = (
            pipeline_result["ssrf"]["markdown"] if active_tab == "ssrf"
            else pipeline_result["etc_reports"].get(active_tab)
        )
        if active_md:
            file_name = "report.md" if active_tab == "ssrf" else f"report_etc_{active_tab}.md"
            st.download_button(
                f"{TAB_LABELS[active_tab]} 리포트 다운로드 (Markdown)",
                data=active_md,
                file_name=file_name,
                mime="text/markdown",
            )
        st.download_button(
            "전체 진단 결과 JSON 다운로드 (마스킹)",
            data=json.dumps(sanitize_raw_scan_result(pipeline_result["raw"]), ensure_ascii=False, indent=2),
            file_name="scan_result_sanitized.json",
            mime="application/json",
        )
        st.markdown("---")
        st.caption("Credential values are masked and never rendered in full.")


# ── 메인 화면 ──────────────────────────────────────────────────────
st.markdown("<div class='brand'>VULN SENTINEL / CONSOLE</div>", unsafe_allow_html=True)
st.markdown(
    "<h1 class='hero-title'>SSRF · SQL Injection · Stored XSS · OS Command Injection 통합 진단</h1>",
    unsafe_allow_html=True,
)
st.markdown(
    "<div class='hero-sub'>Target URL 하나로 diagnosis/main.py(1~8단계) → ai/analyze.py(SSRF) + "
    "ai_etc/analyze_etc.py(SQLi/Stored XSS/OS Command Injection)를 함께 실행하고, "
    "왼쪽 사이드바 버튼으로 4개 리포트를 오가며 봅니다.</div>",
    unsafe_allow_html=True,
)
st.markdown("<div style='height:1rem'></div>", unsafe_allow_html=True)

with st.container(border=True):
    target = st.text_input(
        "Target URL",
        value="http://52.78.187.138:5000",
        placeholder="http://<EC2_PUBLIC_IP>:5000",
        help=(
            "팀의 허가된 취약 웹 애플리케이션 루트 URL을 입력하세요. "
            "/fetch(SSRF · OS Command Injection), /login, /register, /search, /post/new, "
            "/gallery/upload(SQLi · Stored XSS) 엔드포인트를 자동으로 진단합니다."
        ),
    )

    authorized = st.checkbox(
        "이 대상이 팀이 소유하거나 명시적으로 진단 허가를 받은 실습 환경임을 확인합니다."
    )

    run_button = st.button(
        "진단 시작",
        type="primary",
        use_container_width=True,
        disabled=not authorized,
    )

if run_button:
    valid, error = validate_target(target)

    if not valid:
        st.error(error)
    else:
        st.session_state.pop("pipeline_result", None)
        st.session_state.pop("active_tab", None)

        base_url, fetch_url = split_target(target)
        try:
            pipeline_result = run_full_pipeline(base_url, fetch_url)
            st.session_state["pipeline_result"] = pipeline_result
            st.session_state["active_tab"] = "ssrf"
        except Exception as exc:
            st.error(str(exc))
        else:
            # 진단이 성공하면 곧바로 rerun 해서 사이드바(맨 위에서 먼저 렌더됨)가
            # 방금 저장된 pipeline_result를 보고 SSRF/SQLi/XSS/OSC/Login-RateLimit 버튼을
            # 즉시 그리게 한다. (rerun 없으면 다음 상호작용 전까지 버튼이 안 보임)
            st.rerun()

if "pipeline_result" in st.session_state:
    pipeline_result = st.session_state["pipeline_result"]
    active_tab = st.session_state.get("active_tab", "ssrf")

    if active_tab == "ssrf":
        if pipeline_result["ssrf"]["markdown"]:
            render_ssrf_tab(pipeline_result)
        else:
            render_missing("ssrf")
    else:
        active_md = pipeline_result["etc_reports"].get(active_tab)
        if active_md:
            render_vuln_tab(active_tab, active_md, pipeline_result["raw"])
        else:
            render_missing(active_tab)
else:
    st.info(
        "Target URL을 입력하고 '진단 시작'을 누르면 SSRF / SQL Injection / Stored XSS / "
        "OS Command Injection 결과가 여기에 표시됩니다."
    )
