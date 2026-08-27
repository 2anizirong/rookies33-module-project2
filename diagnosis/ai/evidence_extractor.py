"""
현재 main.py가 생성하는 scan_result.json에서 AI 분석용 안전한 증거만 추출한다.

현재 진단 결과 스키마:
{
  "meta": {...},
  "stages": {
    "parameter_discovery": {...},
    "sink_discovery": {...},
    "bypass_diagnosis": [...],
    "imds_exposure": {...},
    "cloud_impact": {...}
  }
}

보안 원칙:
- AWS Access Key / Secret / Session Token은 전달하지 않는다.
- IAM Role 이름, Account ID, ARN, Bucket/Lambda 실제 리소스명도 전달하지 않는다.
- Stage 3의 body_snippet은 메타데이터가 포함될 수 있으므로 전달하지 않는다.
"""

from __future__ import annotations

from typing import Any


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _stage_root(scan_result: dict[str, Any]) -> dict[str, Any]:
    """현재 stages 스키마를 우선 사용하고, 이전 flat 스키마도 최소 호환한다."""
    stages = scan_result.get("stages")
    return stages if isinstance(stages, dict) else scan_result


def _normalize_bypass_results(raw: Any) -> list[dict[str, Any]]:
    # 현재 스키마: bypass_diagnosis 자체가 list
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]

    # 이전 스키마 호환: {"bypass_results": [...]}
    if isinstance(raw, dict):
        items = raw.get("bypass_results", [])
        return [item for item in _as_list(items) if isinstance(item, dict)]

    return []


def _normalize_imds_results(raw: Any) -> list[dict[str, Any]]:
    # 현재 스키마: imds_exposure가 단일 assessment 객체
    if isinstance(raw, dict) and any(
        key in raw for key in ("imds", "iam_role", "temporary_credentials")
    ):
        return [raw]

    # 이전 스키마 호환: {"assessments": [...]}
    if isinstance(raw, dict):
        return [
            item
            for item in _as_list(raw.get("assessments", []))
            if isinstance(item, dict)
        ]

    return []


def build_safe_evidence(scan_result: dict[str, Any]) -> dict[str, Any]:
    stages = _stage_root(scan_result)

    parameter_result = _as_dict(stages.get("parameter_discovery"))
    sink_result = _as_dict(
        stages.get("sink_discovery")
        or stages.get("ssrf_sink_discovery")
    )

    raw_bypass = (
        stages.get("bypass_diagnosis")
        if "bypass_diagnosis" in stages
        else stages.get("ssrf_bypass_diagnosis")
    )
    bypass_results = _normalize_bypass_results(raw_bypass)

    raw_imds = (
        stages.get("imds_exposure")
        if "imds_exposure" in stages
        else stages.get("imds_credential_exposure")
    )
    imds_results = _normalize_imds_results(raw_imds)

    cloud_result = _as_dict(
        stages.get("cloud_impact")
        or stages.get("cloud_impact_assessment")
    )

    # ---------------------------------------------------------
    # Stage 1: Parameter Discovery
    # ---------------------------------------------------------
    parameters: list[dict[str, Any]] = []
    for item in _as_list(parameter_result.get("parameters", [])):
        if not isinstance(item, dict):
            continue
        parameters.append(
            {
                "name": item.get("name"),
                "method": item.get("method"),
                "location": item.get("location"),
            }
        )

    # ---------------------------------------------------------
    # Stage 2: Sink Discovery
    # ---------------------------------------------------------
    candidates: list[dict[str, Any]] = []
    for item in _as_list(sink_result.get("ssrf_candidates", [])):
        if not isinstance(item, dict):
            continue
        candidates.append(
            {
                "parameter": item.get("name") or item.get("parameter"),
                "method": item.get("method"),
                "location": item.get("location"),
                "server_request_detected": item.get("server_request_detected"),
            }
        )

    # ---------------------------------------------------------
    # Stage 3: Bypass / IMDS Diagnosis
    # body_snippet은 절대 AI에 전달하지 않는다.
    # ---------------------------------------------------------
    bypasses: list[dict[str, Any]] = []
    for item in bypass_results:
        tests: list[dict[str, Any]] = []

        for test in _as_list(item.get("tests", [])):
            if not isinstance(test, dict):
                continue

            # 현재 스키마는 bypassed, 이전 스키마는 success를 사용할 수 있음.
            bypassed = test.get("bypassed")
            if bypassed is None:
                bypassed = test.get("success")

            tests.append(
                {
                    "technique": test.get("technique"),
                    "bypassed": bypassed,
                    "verdict": test.get("verdict"),
                    "status_code": test.get("status_code"),
                }
            )

        result = item.get("result")
        technique = item.get("bypass_technique") or item.get("successful_technique")

        bypasses.append(
            {
                "result": result,
                "successful_technique": technique,
                "imds_access_confirmed": result == "vulnerable",
                "imds_v2_protected": result == "imds_v2_protected",
                "tests": tests,
            }
        )

    # ---------------------------------------------------------
    # Stage 4: IMDS / Credential Exposure
    # 이름 및 Credential 값은 제외하고 boolean 사실만 전달한다.
    # ---------------------------------------------------------
    imds_assessments: list[dict[str, Any]] = []
    for item in imds_results:
        imds = _as_dict(item.get("imds"))
        role = _as_dict(item.get("iam_role"))
        creds = _as_dict(item.get("temporary_credentials"))

        imds_assessments.append(
            {
                "imds_reachable": imds.get("reachable"),
                "data_extracted": imds.get("data_extracted"),
                "version_tested": imds.get("version_tested"),
                "v2_enforced": imds.get("v2_enforced"),
                "iam_role_detected": role.get("detected"),
                "temporary_credentials_exposed": creds.get("exposed"),
            }
        )

    # ---------------------------------------------------------
    # Stage 5: Cloud Impact
    # resource/principal의 실제 이름은 제외한다.
    # ---------------------------------------------------------
    cloud_services: list[dict[str, Any]] = []
    for item in _as_list(cloud_result.get("cloud_impact", [])):
        if not isinstance(item, dict):
            continue

        permissions = item.get("permissions", [])
        if isinstance(permissions, str):
            permissions = [permissions]
        elif not isinstance(permissions, list):
            permissions = []

        cloud_services.append(
            {
                "service": item.get("service"),
                "permissions": [str(p) for p in permissions],
                "impact": item.get("impact"),
            }
        )

    principal = _as_dict(cloud_result.get("principal"))

    # ---------------------------------------------------------
    # AI가 검색/종합 단계에서 기본 사실을 헷갈리지 않도록
    # 핵심 chain 상태를 코드에서 명시적으로 계산한다.
    # ---------------------------------------------------------
    vulnerable_count = sum(
        1 for item in bypasses if item.get("result") == "vulnerable"
    )
    imds_reachable = any(
        item.get("imds_reachable") is True for item in imds_assessments
    )
    credentials_exposed = any(
        item.get("temporary_credentials_exposed") is True
        for item in imds_assessments
    )
    cloud_access_confirmed = bool(cloud_services)

    return {
        "schema": "diagnosis-safe-evidence-v2",
        "confirmed_summary": {
            "parameter_count": len(parameters),
            "ssrf_candidate_count": len(candidates),
            "vulnerable_candidate_count": vulnerable_count,
            "imds_reachable": imds_reachable,
            "temporary_credentials_exposed": credentials_exposed,
            "cloud_api_access_confirmed": cloud_access_confirmed,
            "overall_cloud_impact": cloud_result.get("overall_impact"),
        },
        "stage1_parameter_discovery": {
            "parameter_count": len(parameters),
            "parameters": parameters,
        },
        "stage2_sink_discovery": {
            "candidate_count": len(candidates),
            "candidates": candidates,
        },
        "stage3_bypass_diagnosis": {
            "results": bypasses,
        },
        "stage4_imds_exposure": {
            "assessments": imds_assessments,
        },
        "stage5_cloud_impact": {
            "principal_type": principal.get("type"),
            "overall_impact": cloud_result.get("overall_impact"),
            "services": cloud_services,
        },
    }
