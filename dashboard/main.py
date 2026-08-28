## 진단 파이프라인 순서대로 실행하는 오케스트레이터
## Parameter Discovery -> SSRF Sink Discovery -> SSRF Bypass Diagnosis
## -> IMDS / Credential Exposure -> Cloud Impact Assessment -> AI Security Report 생성 (markdown)
from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path

from src.common import load_json, save_json, require_authorized_lab
from src.parameter_discovery import parameter_discovery
from src.ssrf_sink_discovery import ssrf_sink_discovery
from src.ssrf_bypass_diagnosis import ssrf_bypass_diagnosis
from src.imds_credential_exposure import imds_credential_exposure
from src.cloud_impact_assessment import cloud_impact_assessment
from src.report_markdown import generate_markdown_report

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--target",
        required = True,
        help = "diganosis web endpoint -> ex. http://127.0.0.1:5000/fetch"
    )
    parser.add_argument("--config", default="config.json")
    parser.add_argument("--output", default="scan_result.json")
    parser.add_argument("--report", default="report.md", help="AI Security Intelligence Report(Markdown) 저장 경로")
    args = parser.parse_args()
    target_endpoint = args.target

    config = load_json(args.config)
    require_authorized_lab(config)

    timeout = int(config.get("request_timeout", 5))

    # 모든 단계 결과를 이 JSON 하나에 누적
    scan_result = {
        "schema_version": "1.0",
        "scope": "authorized_lab_only",
        "target": {
            "endpoint": target_endpoint,
        },
    }

    print("[1/6] Parameter Discovery 실행 중")
    step1 = parameter_discovery(
        target_endpoint=target_endpoint,
        methods=config.get("arjun_methods", ["GET", "POST", "JSON"]),
    )
    scan_result["parameter_discovery"] = step1
    save_json(args.output, scan_result)

    print("[2/6] SSRF Sink Discovery 실행 중")
    step2 = ssrf_sink_discovery(
        parameter_discovery_result=step1,
        probe_url=config["sink_probe_url"],
        probe_marker=config["sink_probe_marker"],
        timeout=timeout,
    )
    scan_result["ssrf_sink_discovery"] = step2
    save_json(args.output, scan_result)

    print("[3/6] SSRF Bypass Diagnosis 실행 중")
    step3 = ssrf_bypass_diagnosis(
        sink_result=step2,
        metadata_path=config.get("imds_metadata_path", "/latest/meta-data/"),
        timeout=timeout,
    )
    scan_result["ssrf_bypass_diagnosis"] = step3
    save_json(args.output, scan_result)

    print("[4/6] IMDS / Credential Exposure 실행 중")
    step4, runtime_credentials = imds_credential_exposure(
        bypass_result=step3,
        timeout=timeout,
    )
    scan_result["imds_credential_exposure"] = step4
    save_json(args.output, scan_result)

    print("[5/6] Cloud Impact Assessment 실행 중")
    step5 = cloud_impact_assessment(
        runtime_credentials=runtime_credentials,
    )
    scan_result["cloud_impact_assessment"] = step5
    save_json(args.output, scan_result)

    # 실제 Temporary Credential은 파일에 저장하지 않고 메모리에서 제거
    runtime_credentials.clear()
    del runtime_credentials

    print("[6/6] AI Security Report 생성 중")
    report = generate_markdown_report(
        scan_result=scan_result,
        model=config.get("openai_model", "gpt-4o-mini"),
    )
    scan_result["ai_report"] = {
        "provider": report["provider"],
        "fallback_reason": report["fallback_reason"],
        "path": args.report,
    }

    with open(args.report, "w", encoding="utf-8") as f:
        f.write(report["markdown"])

    save_json(args.output, scan_result)
    print(f"[DONE] {args.report}")


if __name__ == "__main__":
    main()
