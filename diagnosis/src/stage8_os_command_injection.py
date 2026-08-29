"""
Stage 8: OS Command Injection Diagnosis

Stage 1에서 발견한 파라미터에 비파괴적인 산술 명령을 삽입하고,
연산 결과가 HTTP 응답에 나타나는지 확인하여
OS Command Injection 가능 여부를 진단한다.

진단 흐름:
1. Stage 1에서 발견한 파라미터를 하나씩 가져옴
2. 랜덤한 두 숫자를 생성하고 곱셈 결과를 미리 계산
3. 파라미터에 ";printf %s $((a*b))" 형태의 Payload 삽입
4. 서버에 GET / POST 요청 전송
5. HTTP 응답에 예상한 산술 결과가 포함되어 있는지 확인
6. 결과가 포함되어 있으면 → vulnerable
   포함되어 있지 않으면 → safe

예시:
Payload  : ;printf %s $((245*123))
Expected : 30135

서버가 해당 문자열을 단순 입력값이 아니라
Shell 명령어로 실행했다면 응답에서 30135가 확인될 수 있다.
"""

import random
import requests


# Stage 8 전체 OS Command Injection 진단 실행

# Stage 1의 Parameter Discovery 결과(parameter_json)를 받아서
# 발견된 모든 파라미터를 하나씩 _test_parameter()로 전달한다.

# 예:
# parameters = [
#     {
#         "name": "url",
#         "method": "GET",
#         "location": "query"
#     }
# ]

# 최종적으로:
# - 몇 개의 파라미터를 테스트했는지
# - 몇 개가 취약했는지
# - 각 파라미터별 상세 결과
# 를 dict 형태로 반환한다.
def run_os_command_injection(
    parameter_json: dict,
    extra_params: dict = None,
    timeout: int = 10,
) -> dict:

    # Stage 1에서 전달받은 진단 대상 URL
    target = parameter_json.get("target")

    # Stage 1에서 발견한 파라미터 목록
    parameters = parameter_json.get("parameters", [])

    # 요청 시 함께 전달해야 하는 추가 파라미터
    # 값이 없으면 빈 dict 사용
    extra_params = extra_params or {}

    # 각 파라미터별 진단 결과 저장
    results = []

    # Stage 1에서 발견한 파라미터를 하나씩 테스트
    for param in parameters:

        # 파라미터 이름
        # 예: url, host, target 등
        name = param.get("name")

        # HTTP Method
        # 값이 없으면 GET을 기본값으로 사용
        method = param.get("method", "GET").upper()

        # 파라미터 전달 위치
        
        # query → URL Query String
        # json  → JSON Body
        # 그 외 → 일반 Form Body
        location = param.get("location", "query")

        # 이름이 없는 파라미터는 테스트 불가능하므로 건너뜀
        if not name:
            continue

        # 실제 OS Command Injection 테스트 수행
        result = _test_parameter(
            target,
            name,
            method,
            location,
            extra_params,
            timeout,
        )

        results.append(result)

    # 전체 결과 중 vulnerable 판정 개수 계산
    vulnerable_count = sum(
        1 for r in results
        if r["result"] == "vulnerable"
    )

    # 최종 Stage 8 결과 반환
    return {
        "target": target,
        "summary": {
            "tested_parameter_count": len(results),
            "vulnerable_count": vulnerable_count,
        },
        "results": results,
    }


# 개별 파라미터 OS Command Injection 테스트

# 하나의 파라미터에 산술 연산 Payload를 삽입한 뒤
# 예상한 계산 결과가 HTTP 응답에 포함되는지 확인한다.

# 랜덤 숫자를 사용하는 이유:
# 고정된 "12345" 같은 문자열이 원래 페이지에 존재하여
# 오탐(False Positive)이 발생하는 것을 줄이기 위해서이다.
def _test_parameter(
    target,
    name,
    method,
    location,
    extra_params,
    timeout,
):

    # 1. 랜덤한 산술식 생성
    
    # 예:
    # a = 2450
    # b = 7231
    
    # 서버가 명령어를 실제로 실행하면
    # a * b의 결과가 HTTP 응답에 나타나는지 확인한다.
    a = random.randint(1000, 5000)
    b = random.randint(5000, 9000)

    # 서버 응답에서 찾아야 할 예상 결과
    expected = str(a * b)

    # 2. Linux / Unix 계열 Shell Payload 생성
    
    # ;       → 앞 명령과 새로운 명령을 구분
    # printf  → 계산 결과를 응답으로 출력
    # $(( ))  → Shell 산술 연산
    
    # 예:
    # ;printf %s $((245*123))
    
    # 서버에서 명령어가 실행될 경우:
    # 30135
    # 와 같은 계산 결과가 출력된다.
    
    # 파일 생성/삭제 등의 명령이 아니라
    # 단순 산술 연산만 사용하므로
    # 비파괴적인 방식으로 취약 여부를 확인한다.
    payload = f";printf %s $(({a}*{b}))"

    # 기존에 필요한 추가 파라미터 복사
    params = dict(extra_params)

    # 현재 진단 대상 파라미터에 Payload 삽입
    params[name] = payload

    try:

        # 3. 파라미터 위치에 따라 HTTP 요청 전송
        # Query String 파라미터
        
        # 예:
        # GET /test?url=;printf...
        if location == "query":
            response = requests.request(
                method,
                target,
                params=params,
                timeout=timeout,
            )

        # JSON Body 파라미터
        
        # 예:
        # {
        #     "url": ";printf..."
        # }
        elif location == "json":
            response = requests.request(
                method,
                target,
                json=params,
                timeout=timeout,
            )

        # 일반 Form Body
        
        # 예:
        # url=;printf...
        else:
            response = requests.request(
                method,
                target,
                data=params,
                timeout=timeout,
            )

    # HTTP 요청 자체가 실패한 경우
    
    # 네트워크 오류, Timeout 등의 경우에는
    # 취약/안전을 판단할 수 없으므로 unknown으로 반환
    except requests.RequestException as e:
        return {
            "parameter": name,
            "method": method,
            "location": location,
            "result": "unknown",
            "error": str(e),
        }

    # 4. OS Command Injection 취약 여부 판정
    
    # 우리가 미리 계산한 expected 값이
    # HTTP 응답 본문(response.text)에 존재하는지 검사한다.
    
    # 예:
    # Payload:
    # ;printf %s $((245*123))
    
    # Expected:
    # 30135
    
    # Response:
    # ...
    # 30135
    # ...
    
    # → 서버에서 산술 명령이 실행되었다고 판단
    # → vulnerable
    vulnerable = expected in response.text

    # 5. 개별 파라미터 진단 결과 반환
    
    # vulnerable:
    # 예상한 연산 결과가 응답에서 확인됨
    
    # safe:
    # 현재 Payload를 사용한 진단에서는
    # 명령 실행 결과가 확인되지 않음
    
    # detection = arithmetic_response:
    # 산술 연산 결과를 기반으로 취약점을 탐지했다는 의미
    return {
        "parameter": name,
        "method": method,
        "location": location,
        "result": "vulnerable" if vulnerable else "safe",
        "detection": "arithmetic_response" if vulnerable else None,
        "status_code": response.status_code,
    }

