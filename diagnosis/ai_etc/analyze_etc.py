"""
scan_result.json 후처리 AI 파이프라인 — SQL Injection / Stored XSS / OS Command Injection /
Login Rate Limit 전용.

ai/analyze.py(SSRF 전용)와 완전히 독립. main.py, ai/ 폴더는 전혀 건드리지 않음.
파일 서치(file_research)는 팀 결정으로 이 파이프라인에서 제외함.

흐름:
scan_result.json
→ evidence_extractor_etc.build_safe_evidence_etc()  (안전한 증거 추출)
→ web_research_etc.run()                            (웹서치)
→ report_generator_etc.generate_etc()                (OpenAI 종합 → vulnerabilities 배열)
→ ai_report_etc.json (통합 1개) + report_etc_{vuln_type}.md (취약점 타입별로 분리 저장)

사용법:
    cd diagnosis
    python ai_etc/analyze_etc.py --input scan_result.json
    python ai_etc/analyze_etc.py --input scan_result.json --evidence-only   # API 호출 없이 증거만 확인
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

AI_ETC_ROOT = Path(__file__).resolve().parent
DIAGNOSIS_ROOT = AI_ETC_ROOT.parent
PROJECT_ROOT = DIAGNOSIS_ROOT.parent

load_dotenv(PROJECT_ROOT / ".env")

# diagnosis/를 Python import 경로에 먼저 추가해야 아래 "ai_etc.xxx" 형태의 import가 동작함.
# (이 스크립트를 `python ai_etc/analyze_etc.py` 처럼 직접 실행하면 sys.path에
#  diagnosis/ 자체가 자동으로 들어가지 않기 때문 — 반드시 import보다 먼저 실행되어야 함)
if str(DIAGNOSIS_ROOT) not in sys.path:
    sys.path.insert(0, str(DIAGNOSIS_ROOT))

from ai_etc.evidence_extractor_etc import build_safe_evidence_etc  # noqa: E402

DEFAULT_MODEL = os.getenv("OPENAI_MODEL", "gpt-5")


def analyze_etc(scan_result: dict[str, Any], model: str = DEFAULT_MODEL) -> dict[str, Any]:
    # OpenAI 의존 모듈은 실제 AI 실행 시점에만 불러온다 (--evidence-only일 때 불필요한 import 방지).
    from ai_etc import report_generator_etc, web_research_etc

    evidence = build_safe_evidence_etc(scan_result)

    print("[AI-ETC 0/2] Evidence Extraction", file=sys.stderr)
    summary = evidence.get("confirmed_summary", {})
    print(
        "         "
        f"sqli_vulnerable={summary.get('sqli_vulnerable_count', 0)}/{summary.get('sqli_endpoint_count', 0)}, "
        f"xss_vulnerable={summary.get('xss_vulnerable_count', 0)}/{summary.get('xss_tested_count', 0)}, "
        f"cmd_vulnerable={summary.get('cmd_injection_vulnerable_count', 0)}/{summary.get('cmd_injection_tested_count', 0)}",
        file=sys.stderr,
    )

    print("[AI-ETC 1/2] Web Research", file=sys.stderr)
    web_result = web_research_etc.run(evidence=evidence, model=model)
    print(
        f"         status={web_result.get('status')}, "
        f"tool_used={web_result.get('web_search_used', False)}, "
        f"sources={len(web_result.get('sources', []))}",
        file=sys.stderr,
    )

    print("[AI-ETC 2/2] Final Synthesis", file=sys.stderr)
    report = report_generator_etc.generate_etc(
        evidence=evidence,
        web_result=web_result,
        model=model,
    )
    vuln_count = len(report.get("vulnerabilities", []))
    print(f"         status={report.get('status')}, vulnerabilities={vuln_count}", file=sys.stderr)

    return {
        "provider": "openai",
        "analysis_type": "security_intelligence_etc",
        "model": model,
        # 안전하게 정규화된 실제 진단 사실 — Dashboard/발표에서 AI 판단의 입력 근거 확인용
        "safe_evidence": evidence,
        "research_status": {
            "web_search": web_result.get("status", "unknown"),
            "web_search_used": web_result.get("web_search_used", False),
        },
        "status": report.get("status"),
        "vulnerabilities": report.get("vulnerabilities", []),
        "sources": {
            "web": web_result.get("sources", []),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default="scan_result.json")
    parser.add_argument("--output", default="ai_report_etc.json")
    parser.add_argument(
        "--report-dir",
        default=None,
        help="report_etc_{vuln_type}.md 파일들을 저장할 디렉터리 (기본: diagnosis/ 바로 밑)",
    )
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument(
        "--evidence-only",
        action="store_true",
        help="API 호출 없이 현재 scan_result에서 추출되는 안전한 Evidence만 출력",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        input_path = DIAGNOSIS_ROOT / args.input
    if not input_path.exists():
        parser.error(f"입력 파일을 찾을 수 없음: {args.input}")

    try:
        scan_result = json.loads(input_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        parser.error(f"입력 JSON 파싱 실패: {exc}")

    if args.evidence_only:
        evidence = build_safe_evidence_etc(scan_result)
        print(json.dumps(evidence, ensure_ascii=False, indent=2))
        return

    result = analyze_etc(scan_result=scan_result, model=args.model)

    output_path = Path(args.output)
    if not output_path.is_absolute():
        output_path = DIAGNOSIS_ROOT / output_path
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    from ai_etc import report_generator_etc

    report_dir = Path(args.report_dir) if args.report_dir else DIAGNOSIS_ROOT
    written = report_generator_etc.save_markdown_reports_etc(result, report_dir)

    print(f"[DONE] {output_path}")
    if written:
        for p in written:
            print(f"[DONE] {p}")
    else:
        print("[!] vulnerabilities가 비어 있어 저장된 .md 파일이 없음 "
              "(모든 취약점이 safe였거나 AI 분석 실패)")


if __name__ == "__main__":
    main()
