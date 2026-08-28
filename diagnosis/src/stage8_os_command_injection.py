"""
Stage 8: OS Command Injection Diagnosis

Stage 1에서 발견한 파라미터에 비파괴적인 산술 명령을 삽입하고,
연산 결과가 HTTP 응답에 나타나는지 확인하여
OS Command Injection 가능 여부를 진단한다.
"""

import random
import requests


def run_os_command_injection(
    parameter_json: dict,
    extra_params: dict = None,
    timeout: int = 10,
) -> dict:

    target = parameter_json.get("target")
    parameters = parameter_json.get("parameters", [])
    extra_params = extra_params or {}

    results = []

    for param in parameters:
        name = param.get("name")
        method = param.get("method", "GET").upper()
        location = param.get("location", "query")

        if not name:
            continue

        result = _test_parameter(
            target,
            name,
            method,
            location,
            extra_params,
            timeout,
        )

        results.append(result)

    vulnerable_count = sum(
        1 for r in results
        if r["result"] == "vulnerable"
    )

    return {
        "target": target,
        "summary": {
            "tested_parameter_count": len(results),
            "vulnerable_count": vulnerable_count,
        },
        "results": results,
    }


def _test_parameter(
    target,
    name,
    method,
    location,
    extra_params,
    timeout,
):

    # 랜덤한 산술식 생성
    a = random.randint(1000, 5000)
    b = random.randint(5000, 9000)

    expected = str(a * b)

    # Linux / Unix 계열
    payload = f";printf %s $(({a}*{b}))"

    params = dict(extra_params)
    params[name] = payload

    try:
        if location == "query":
            response = requests.request(
                method,
                target,
                params=params,
                timeout=timeout,
            )

        elif location == "json":
            response = requests.request(
                method,
                target,
                json=params,
                timeout=timeout,
            )

        else:
            response = requests.request(
                method,
                target,
                data=params,
                timeout=timeout,
            )

    except requests.RequestException as e:
        return {
            "parameter": name,
            "method": method,
            "location": location,
            "result": "unknown",
            "error": str(e),
        }

    vulnerable = expected in response.text

    return {
        "parameter": name,
        "method": method,
        "location": location,
        "result": "vulnerable" if vulnerable else "safe",
        "detection": "arithmetic_response" if vulnerable else None,
        "status_code": response.status_code,
    }