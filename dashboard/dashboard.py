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


# from src.remediation_guide import PDF_DIR, fetch_guided_recommendations
# from src.report_pdf import build_pdf_report
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

# 1단계: diagnosis/main.py  <fetch_url> -o <AAA.json>   (cwd = dashboard/)
DIAGNOSIS_MAIN = DIAGNOSIS_DIR / "main.py"
AAA_JSON = DIAGNOSIS_DIR / "AAA.json"

# 2단계: diagnosis/ai/analyze.py --input AAA.json        (cwd = diagnosis/)
ANALYZE_MAIN = DIAGNOSIS_DIR / "ai" / "analyze.py"

# analyze.py가 report.md / report.json을 diagnosis/ai/ 에 쓰는지 diagnosis/ 에 쓰는지
# 팀 코드에 따라 다를 수 있어 두 위치를 모두 후보로 두고, 존재하는 쪽을 사용한다.
REPORT_MD_CANDIDATES = [DIAGNOSIS_DIR / "ai" / "report.md", DIAGNOSIS_DIR / "report.md"]
REPORT_JSON_CANDIDATES = [DIAGNOSIS_DIR / "ai" / "report.json", DIAGNOSIS_DIR / "report.json"]


def _first_existing(paths: list[Path]) -> Path | None:
    for p in paths:
        if p.exists():
            return p
    return None


def normalize_scan_result(raw: dict[str, Any]) -> dict[str, Any]:
    """
    diagnosis/main.py가 실제로 내놓는 AAA.json 스키마
    (meta / stages.parameter_discovery / stages.sink_discovery /
     stages.bypass_diagnosis / stages.imds_exposure / stages.cloud_impact)
    를 render_dashboard()가 기대하는 평평한(top-level) 스키마로 변환한다.

    실제 AAA.json 예시:
        {
          "meta": {"target": "...", "timestamp": "..."},
          "stages": {
            "parameter_discovery": {"parameters": [...]},
            "sink_discovery": {"ssrf_candidates": [...]},
            "bypass_diagnosis": [{"parameter": {...}, "tests": [...], "result": "vulnerable"}],
            "imds_exposure": {"imds": {...}, "iam_role": {...}, "temporary_credentials": {...}},
            "cloud_impact": {"principal": {...}, "cloud_impact": [...], "overall_impact": "high"}
          }
        }
    """
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
                # 리스트에 올라와 있다는 것 자체가 이미 접근이 확인됐다는 뜻
                "accessible": True,
                # 렌더링 쪽 표시용 alias (기존 코드가 "action"/"assets" 필드명을 기대함)
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
    "[1/6]": (0.08, "Parameter Discovery 실행 중"),
    "[2/6]": (0.24, "SSRF Sink Discovery 실행 중"),
    "[3/6]": (0.40, "SSRF / IMDS Diagnosis 실행 중"),
    "[4/6]": (0.58, "IMDS / Credential Exposure 실행 중"),
    "[5/6]": (0.76, "Cloud Impact Assessment 실행 중"),
    "[6/6]": (0.90, "AI Security Report 생성 중"),
    "[DONE]": (1.00, "진단 완료"),
}

SEVERITY_COLORS = {
    "critical": "#ff3b5c",
    "high": "#ff6b45",
    "medium": "#ffb020",
    "low": "#20c997",
    "unknown": "#58a6ff",
}

TECHNIQUE_LABELS = {
    "direct": "직접 접근",
    "decimal_ip": "10진수 IP",
    "hex_ip": "16진수 IP",
    "octal_ip": "8진수 IP",
}


st.set_page_config(
    page_title="SSRF Sentinel · 진단 대시보드",
    page_icon="◈",
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
        return False, "Target에는 IMDS 주소가 아니라 진단할 웹 엔드포인트를 입력하세요."

    return True, ""


def run_scan(target: str) -> dict[str, Any]:
    if not DIAGNOSIS_MAIN.exists():
        raise FileNotFoundError(f"main.py를 찾을 수 없습니다: {DIAGNOSIS_MAIN}")

    if not ANALYZE_MAIN.exists():
        raise FileNotFoundError(f"analyze.py를 찾을 수 없습니다: {ANALYZE_MAIN}")

    fetch_url = target.strip().rstrip("/")
    if not fetch_url.endswith("/fetch"):
        fetch_url = fetch_url + "/fetch"

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

    # 1단계: diagnosis/main.py  <fetch_url> -o AAA.json   (stage 1~5, cwd = dashboard/)
    status_text.caption("1~5단계 진단 실행 중 (수 분 소요될 수 있음)")
    code1 = stream(
        [sys.executable, "-u", str(DIAGNOSIS_MAIN), fetch_url, "-o", str(AAA_JSON)],
        cwd=PROJECT_ROOT,
        label="1~5단계 진단 실행 중",
    )
    if code1 != 0:
        progress.progress(0.0, text="진단 실패")
        raise RuntimeError(
            "diagnosis/main.py 실행 중 오류가 발생했습니다. 위 실행 로그를 확인하세요."
        )
    if not AAA_JSON.exists():
        raise FileNotFoundError(f"진단은 종료됐지만 결과 JSON을 찾을 수 없습니다: {AAA_JSON}")

    # 2단계: diagnosis/ai/analyze.py --input AAA.json   (stage 6, cwd = diagnosis/)
    progress.progress(0.80, text="AI Security Report 생성 중")
    status_text.caption("AI Security Report 생성 중 (수 분 소요될 수 있음)")
    code2 = stream(
        [sys.executable, "-u", str(ANALYZE_MAIN), "--input", AAA_JSON.name],
        cwd=DIAGNOSIS_DIR,
        label="AI Security Report 생성 중",
    )
    if code2 != 0:
        progress.progress(0.80, text="AI 리포트 생성 실패")
        raise RuntimeError(
            "ai/analyze.py 실행 중 오류가 발생했습니다. 위 실행 로그를 확인하세요."
        )

    # 리포트 파일이 실제로 나왔는지 확인 (analyze.py가 diagnosis/ai/ 또는 diagnosis/ 에 씀)
    report_md_path = _first_existing(REPORT_MD_CANDIDATES)
    report_json_path = _first_existing(REPORT_JSON_CANDIDATES)
    if report_md_path is None and report_json_path is None:
        checked = ", ".join(str(p) for p in REPORT_MD_CANDIDATES + REPORT_JSON_CANDIDATES)
        raise FileNotFoundError(
            f"analyze.py는 종료됐지만 report.md / report.json을 찾을 수 없습니다. 확인한 경로: {checked}"
        )

    with AAA_JSON.open("r", encoding="utf-8") as f:
        raw_scan = json.load(f)
    json_result = normalize_scan_result(raw_scan)

    ai_report_data: dict[str, Any] = {}
    if report_json_path is not None:
        ai_report_data = json.loads(report_json_path.read_text(encoding="utf-8"))

    if report_md_path is not None:
        markdown_text = report_md_path.read_text(encoding="utf-8")
    else:
        # report.md가 없으면 report.json의 "report" 필드를 마크다운으로 변환
        markdown_text = report_json_to_markdown(ai_report_data.get("report", ai_report_data))

    # ai_report 메타(provider, fallback_reason 등)를 json_result 안에 병합해
    # 아래 render_dashboard()가 이전과 동일하게 json_result.get("ai_report", {}) 로 읽을 수 있게 함
    json_result["ai_report"] = ai_report_data.get("ai_report", ai_report_data)

    progress.progress(1.0, text="진단 완료")
    status_text.success("전체 파이프라인(1~6단계)이 완료되었습니다.")

    return {
        "markdown": markdown_text,
        "json": json_result,
        "_dashboard_timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def mask_identifier(value: Any, visible: int = 4) -> Any:
    if not isinstance(value, str) or len(value) <= visible:
        return value
    return value[:visible] + "****REDACTED"


def sanitized_result(result: dict[str, Any]) -> dict[str, Any]:
    safe = copy.deepcopy(result)

    principal = safe.get("cloud_impact_assessment", {}).get("principal")
    if isinstance(principal, dict):
        if principal.get("account"):
            principal["account"] = mask_identifier(principal["account"], 3)
        if principal.get("arn"):
            principal["arn"] = "REDACTED"
        if principal.get("user_id"):
            principal["user_id"] = "REDACTED"

    return safe


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


def render_dashboard(result: dict[str, Any]) -> None:
    markdown_text = result.get("markdown", "") or ""
    json_result = result.get("json", {}) or {}

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
    section_internal = find_section(sections, "내부 보안 가이드")
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

    ai_report_meta = json_result.get("ai_report", {}) or {}

    # steps 1~5 원본 데이터 (상세 탭 / PDF / 가이드 RAG 용도)
    params = json_result.get("parameter_discovery", {}).get("parameters", [])
    candidates = json_result.get("ssrf_sink_discovery", {}).get("ssrf_candidates", [])
    bypass_results = json_result.get("ssrf_bypass_diagnosis", {}).get("bypass_results", [])
    tests = [t for item in bypass_results for t in item.get("tests", [])]
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
    overall_impact = str(cloud.get("overall_impact", "unknown"))

    with st.sidebar:
        st.markdown("<div class='brand'>SSRF SENTINEL</div>", unsafe_allow_html=True)
        st.markdown("### 진단 리포트")
        st.caption("현재 진단 대상")
        st.code(target_endpoint, language=None)
        st.download_button(
            "리포트 다운로드 (Markdown)",
            data=markdown_text,
            file_name="report.md",
            mime="text/markdown",
        )
        if json_result:
            st.download_button(
                "마스킹 결과 JSON 다운로드",
                data=json.dumps(sanitized_result(json_result), ensure_ascii=False, indent=2),
                file_name="scan_result_sanitized.json",
                mime="application/json",
            )
        st.markdown("---")
        st.caption("Credential values are masked and never rendered in full.")

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
        ("INTERNAL GUIDE", "내부 보안 가이드 연계", section_internal),
        ("DEEP DIVE", "종합 분석", section_analysis),
    ]
    for kicker, label, section in narrative_sections:
        st.markdown(f"<div class='section-kicker'>{e(kicker)}</div><div class='section-title'>{e(label)}</div>", unsafe_allow_html=True)
        with st.container(border=True):
            st.markdown((section["body"] if section else "") or "_내용을 찾지 못했습니다._")

    st.markdown(f"<div class='footer-note'>SSRF SENTINEL · TARGET {e(target_endpoint.upper())}</div>", unsafe_allow_html=True)


with st.sidebar:
    if "scan_result" not in st.session_state:
        st.markdown("<div class='brand'>SSRF SENTINEL</div>", unsafe_allow_html=True)
        st.markdown("### 진단 콘솔")
        st.caption("Target endpoint를 입력하고 진단을 시작하면 결과 리포트가 여기에 표시됩니다.")

st.markdown("<div class='brand'>SSRF SENTINEL / CONSOLE</div>", unsafe_allow_html=True)
st.markdown("<h1 class='hero-title'>SSRF → AWS Cloud Impact 자동 진단</h1>", unsafe_allow_html=True)
st.markdown(
    "<div class='hero-sub'>Parameter Discovery → SSRF Sink → IMDS → Credential Exposure → "
    "Cloud Impact → AI Security Intelligence Report</div>",
    unsafe_allow_html=True,
)
st.markdown("<div style='height:1rem'></div>", unsafe_allow_html=True)

with st.container(border=True):
    target = st.text_input(
        "Target endpoint",
        value="http://52.78.187.138:5000/fetch",
        placeholder="http://<EC2_PUBLIC_IP>:5000/fetch",
        help="IMDS 주소가 아니라 팀의 허가된 취약 웹 애플리케이션 엔드포인트를 입력하세요.",
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
        st.session_state.pop("scan_result", None)

        try:
            result = run_scan(target.strip())
            st.session_state["scan_result"] = result
        except Exception as exc:
            st.error(str(exc))

if "scan_result" in st.session_state:
    render_dashboard(st.session_state["scan_result"])
else:
    st.info("Target endpoint를 입력하고 '진단 시작'을 누르면 결과가 여기에 표시됩니다.")