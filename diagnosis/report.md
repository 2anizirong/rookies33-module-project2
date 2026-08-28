# AI Security Intelligence Report

## 1. 종합 위험도

- Severity: **HIGH**
- AI Risk Score: **8.2 / 10**
- 판단 근거: SSRF 취약점이 확인되었고, IMDSv1에 접근하여 임시 자격증명이 노출되었으며 해당 크레덴셜로 실제 AWS API 접근(S3: ListBuckets, Lambda: ListFunctions/GetFunction)이 확인됨. 조회·열람 수준의 권한에 한정되나, 자격증명 탈취와 클라우드 인프라 열람까지 체인이 완결되어 고위험으로 평가.

## 2. 취약점 분류

- 취약점: Server-Side Request Forgery (SSRF) via query parameter leading to AWS IMDSv1 credential exposure
- CWE: CWE-918
- 설명: 서버가 신뢰되지 않은 url 쿼리 파라미터를 사용해 서버 측 요청을 수행하면서 내부 링크-로컬(169.254.169.254) EC2 메타데이터 서비스(IMDSv1)에 접근을 허용하였다. IP 표기 우회(hex/octal)로 필터를 우회해 IMDSv1에 도달, 임시 자격증명을 획득하고 이를 통해 제한적 범위의 AWS API 호출이 가능해졌다.

### 공격 체인

1. 입력 파라미터 발견: GET query 'url'
2. 서버 측 요청 수행 감지(SSRF sink 존재)
3. 필터 우회: hex_ip 및 octal_ip 포맷으로 169.254.169.254 접근 성공(200)
4. IMDS 노출: IMDSv1 접근 가능, IMDSv2 미강제
5. 임시 자격증명 노출 및 IAM Role 존재 확인
6. 클라우드 API 접근: S3 ListBuckets, Lambda ListFunctions/GetFunction 성공(열람/정보노출)

## 3. 자동 진단 증거

- **stage1: GET query 파라미터 'url' 1개 발견**
  - 의미: 사용자 제어 입력으로 서버가 외부 요청을 수행할 수 있는 진입점 존재
- **stage2: 'url' 파라미터 사용 시 서버 요청 발생 감지**
  - 의미: SSRF sink 확인
- **stage3: direct/decimal_ip는 403 차단, hex_ip·octal_ip 기법은 200 응답으로 우회 성공**
  - 의미: IP 표기 변조로 필터 우회 가능(차단목록 기반 방어 우회)
- **stage3: imds_access_confirmed=true, imds_v2_protected=false**
  - 의미: IMDSv1 노출 및 IMDSv2 미강제 상태
- **stage4: data_extracted=true, temporary_credentials_exposed=true, iam_role_detected=true**
  - 의미: 인스턴스 역할 기반 임시 크레덴셜 유출 확정
- **stage5: principal_type=IAMRole; S3: ListBuckets; Lambda: ListFunctions/GetFunction**
  - 의미: 탈취한 크레덴셜로 제한적 조회성 API 호출 가능(인프라 열람/정보노출)

## 4. 관련 CVE

- 직접 대응 CVE 확인: 아니오
- 설명: 본 대상은 특정 공개 제품이 아니며, 자동 진단 증거는 자체 애플리케이션의 SSRF 취약점이다. 유사 패턴의 공개 CVE는 참고용으로만 연결했다.

### CVE-2021-22214

- 관계: similar_attack_pattern
- 설명: GitLab SSRF 취약점
- 현재 진단과의 관계: 동일한 CWE-918 유형의 SSRF로 내부 자원 접근 가능성이 논의된 공개 사례. 본 시스템의 SSRF 메커니즘과 유사 패턴.

### CVE-2021-28918

- 관계: similar_attack_pattern
- 설명: netmask 옥탈 처리 취약점으로 인한 IP 우회
- 현재 진단과의 관계: 옥탈 표기 등으로 필터 우회가 가능한 사례. 본 진단의 octal_ip/hex_ip 우회 성공과 직접 유사.

## 5. 실제 침해 / 공개 사례

### Capital One 데이터 유출 사건 (2019)

- 설명: SSRF를 통해 EC2 IMDS에 접근, 인스턴스 역할 임시 토큰을 탈취한 뒤 AWS 리소스에 접근한 사건 체인이 법원 문서 및 공개 발표로 확인됨.
- 유사점: SSRF → IMDSv1 접근 → 임시 자격증명 탈취 → 클라우드 API 열람이라는 공격 흐름이 본 진단 체인과 동일 패턴

## 6. 공식 보안 권고

- **AWS / IMDSv2 전환/강제 및 IMDS 접근 제한**
  - 권고: IMDSv2 사용 및 hop limit 등 방어 심층화 권고, 169.254.169.254 접근 제한 권장.
  - 적용 이유: 본 시스템은 IMDSv1 노출 및 v2 미강제이므로 직접적 적용
- **MITRE ATT&CK / T1552.005 Cloud Instance Metadata API**
  - 권고: 메타데이터 API를 통한 크레덴셜 탈취 기법 기술.
  - 적용 이유: IMDSv1에서 임시 크레덴셜 노출 사실과 일치
- **MITRE ATT&CK / T1580 Cloud Infrastructure Discovery**
  - 권고: ListBuckets 등 나열/열람 기반 인프라 디스커버리 설명.
  - 적용 이유: S3 ListBuckets, Lambda ListFunctions/GetFunction 확인과 일치
- **OWASP / SSRF 예방 치트시트**
  - 권고: 허용목록, 주소 정규화, 내부 주소 차단, 리다이렉션 재검증, IMDSv2는 방어 심층화 수단으로 명시.
  - 적용 이유: hex/octal 우회가 성공한 환경에서 차단목록 의존의 한계를 보완하는 직접적 지침

## 7. 내부 보안 가이드 연계

- **Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md / 허용목록 기반 SSRF 방어 및 IMDS 차단**
  - 관계: direct
  - 내용: 목적지 정규화/허용목록, 내부·링크로컬(169.254.169.254) 차단, IMDSv2 전환·IMDSv1 비활성화 권고.
  - 진단과의 관계: 현재 hex/octal 우회 성공 및 IMDSv1 노출 상태에 대한 즉시 적용 통제
- **CWE-918 Server-Side Request Forge.md / SSRF 정의와 대응**
  - 관계: direct
  - 내용: Loopback/사설/링크로컬 차단, DNS 해석 후 실제 IP 검사, 리다이렉션 최종 목적지 재검증.
  - 진단과의 관계: 169.254.169.254 접근 성공 및 필터 우회 문제에 직접 부합
- **소프트웨어_개발보안_가이드(2021.12.29).pdf / 구현 단계 시큐어코딩(서버사이드 요청 위조)**
  - 관계: direct
  - 내용: 입력 데이터 검증/웹 서비스 요청 및 결과 검증/신뢰되지 않는 URL 자동 접속 통제 등.
  - 진단과의 관계: url 파라미터 기반 서버 요청 검증 원칙 제공
- **주요정보통신기반시설_기술적_취약점_분석_평가_방법_상세가이드.pdf / 계정·권한 관리 및 로깅(일반 통제)**
  - 관계: indirect
  - 내용: IAM 관련 변경 알림·로깅·감사 등 관리 통제 언급.
  - 진단과의 관계: 임시 자격증명 노출 영향 최소화를 위한 보조 통제

## 8. 종합 분석

### 공격 시나리오

공격자는 애플리케이션의 GET ?url= 파라미터를 이용해 서버가 지정한 대상에 요청하도록 유도한다. 직접 IP 또는 십진 표기는 403으로 차단되었으나, 169.254.169.254를 hex/octal 표기로 변형하여 필터를 우회하고 IMDSv1 엔드포인트에 접근한다. IMDSv2가 강제되지 않아 메타데이터에서 임시 자격증명을 획득하고, 해당 크레덴셜로 AWS API(S3 ListBuckets, Lambda ListFunctions/GetFunction)를 호출하여 환경 정보를 열람한다.

### 확인된 영향

- SSRF sink 존재 및 필터(hex/octal) 우회 성공
- IMDSv1 접근 가능, IMDSv2 미강제
- 임시 자격증명 노출 및 IAM Role 존재
- 노출된 크레덴셜로 S3 ListBuckets, Lambda ListFunctions/GetFunction 호출 성공(인프라 열람/정보노출)

### 잠재 영향

- 내부 메타데이터 추가 열람 및 환경 식별 확대
- 같은 IAM Role 범위 내에서 추가적인 조회성 API 호출 확대 가능성(권한이 허용하는 범위에 한함)
- 내부 네트워크 서비스에 대한 SSRF 기반 접근/스캐닝 가능성(현재 증거로 기능/권한은 입증되지 않음)

### 진단 한계

- 확인된 클라우드 권한은 조회/열람(ListBuckets, ListFunctions/GetFunction)에 한정됨. 쓰기/삭제/실행 권한은 확인되지 않음.
- IAM Role 명칭, Account ID, 리소스 실제 이름/값은 증거에 없음.
- 외부 자료는 사실 보강 참고일 뿐, 시스템 사실은 자동 진단 증거에 한함.

## 9. 대응방안

- **[HIGH] EC2 Instance Metadata Service에서 IMDSv2를 강제하고 IMDSv1 비활성화**
  - 근거: 현재 IMDSv1로 자격증명이 노출됨. IMDSv2 토큰 기반 접근으로 크레덴셜 탈취 위험을 현저히 완화.
- **[HIGH] SSRF 방어: 목적지 URL 정규화 후 허용목록(도메인/IP) 기반으로만 서버 요청 허용**
  - 근거: hex/octal IP 우회가 성공했으므로 차단목록 의존을 중단하고 허용목록 중심으로 전환해야 함.
- **[HIGH] 링크-로컬(169.254.169.254), localhost, RFC1918 등 내부 주소 전면 차단 및 네트워크 레벨에서 IMDS 접근 제한**
  - 근거: 메타데이터(169.254.169.254)로의 서버 요청을 애플리케이션·네트워크 계층에서 모두 차단하여 방어 심층화.
- **[HIGH] URL 파서 강화: IP 주소를 표준 정규화하여 비교하고, 10진/16진/8진/혼합 표기 및 숫자형 호스트명 거부**
  - 근거: hex_ip·octal_ip 우회가 가능한 상태. 정규화 후 정책 평가로 우회 벡터 차단.
- **[HIGH] 서버 사이드 HTTP 클라이언트에서 리다이렉션 비활성화 또는 각 홉마다 최종 목적지 재검증**
  - 근거: 리다이렉션을 통한 내부/IMDS 우회 가능성 축소.
- **[HIGH] WAF/프록시에 EC2 메타데이터 SSRF 관련 매니지드 룰 적용**
  - 근거: 애플리케이션 앞단에서 알려진 메타데이터 접근 패턴 차단으로 탐지·차단 강화.
- **[MEDIUM] 노출된 임시 자격증명 무효화(세션 만료 대기 또는 인스턴스 프로파일 재발급) 및 CloudTrail/로그로 오남용 여부 점검**
  - 근거: 이미 크레덴셜 노출이 확인됨. 악용 흔적 확인 및 재발급/만료로 영향 축소.
- **[MEDIUM] 최소 권한 원칙으로 인스턴스 IAM Role 재검토(불필요한 List/Get 권한 축소)**
  - 근거: 자격증명 유출 시 노출 범위를 최소화.
- **[MEDIUM] 앱 레벨 요청 제한: 허용 프로토콜(HTTP/HTTPS)만 허용, 요청 바디/헤더 크기 제한, 타임아웃 및 아웃바운드 Egress 제어**
  - 근거: SSRF 악용을 통한 대량 스캐닝/데이터 유출 억제.
- **[LOW] 보안 테스트 파이프라인에 SSRF 전용 테스트(내부 주소/IMDS 시그니처, IP 인코딩 우회 케이스) 추가**
  - 근거: 재발 방지 및 회귀 테스트 자동화.

## 10. 검색 출처

### Web Search

- CWE - CWE-918: Server-Side Request Forgery (SSRF) (4.20): https://cwe.mitre.org/data/definitions/918?utm_source=openai
- Unsecured Credentials: Cloud Instance Metadata API, Sub-technique T1552.005 - Enterprise | MITRE ATT&CK®: https://attack.mitre.org/techniques/T1552/005/?utm_source=openai
- Cloud Infrastructure Discovery, Technique T1580 - Enterprise | MITRE ATT&CK®: https://attack.mitre.org/techniques/T1580/?utm_source=openai
- NVD - CVE-2021-22214: https://nvd.nist.gov/vuln/detail/CVE-2021-22214?utm_source=openai
- NVD - CVE-2021-28918: https://nvd.nist.gov/vuln/detail/CVE-2021-28918?utm_source=openai
- PowerPoint Presentation: https://d1.awsstatic.com/events/reinvent/2019/Protecting_you_from_you_Misconfiguration-caused_breaches_SEC222-S.pdf?utm_source=openai
- Western District of Washington | United States v. Paige Thompson: https://www.justice.gov/usao-wdwa/united-states-v-paige-thompson?utm_source=openai
- Press Release | Capital One: https://www.capitalone.com/about/newsroom/capital-one-announces-data-security-incident/?utm_source=openai
- Transition to using Instance Metadata Service Version 2 - Amazon Elastic Compute Cloud: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-transition-to-version-2.html?utm_source=openai
- Limit access to the Instance Metadata Service - Amazon Elastic Compute Cloud: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-limiting-access.html?utm_source=openai
- Access instance metadata for an EC2 instance - Amazon Elastic Compute Cloud: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html?utm_source=openai
- Baseline rule groups - AWS WAF, AWS Firewall Manager, AWS Shield Advanced, and AWS Shield network security director: https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html?utm_source=openai
- AWS Prescriptive Guidance - AWS Security Reference Architecture (AWS SRA) – core architecture: https://docs.aws.amazon.com/pdfs/prescriptive-guidance/latest/security-reference-architecture/security-reference-architecture.pdf?utm_source=openai
- NSA & CISA | Use Secure Cloud Identity and Access Management Practices: https://media.defense.gov/2024/Mar/07/2003407866/-1/-1/0/CSI-CloudTop10-Identity-Access-Management.PDF?utm_source=openai
- Server Side Request Forgery Prevention - OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html?utm_source=openai
- Untitled web source: https://attack.mitre.org/techniques/T1552/005/
- Untitled web source: https://cwe.mitre.org/data/definitions/918
- Untitled web source: https://cwe.mitre.org/data/published/cwe_v2.12.pdf
- Untitled web source: https://www.capitalone.com/about/newsroom/capital-one-announces-data-security-incident/
- Untitled web source: https://cwe.mitre.org/
- Untitled web source: https://security.glexia.com/threat-intelligence/attack/techniques/T1552.005-cloud-instance-metadata-api
- Untitled web source: https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1552.html
- Untitled web source: https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Instance%20Metadata%20API/
- Untitled web source: https://www.elastic.co/guide/en/security/current/suspicious-instance-metadata-service-imds-api-request.html
- Untitled web source: https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/integrations/kubernetes/credential_access_kubernetes_pod_exec_cloud_instance_metadata
- Untitled web source: https://docs-cortex.paloaltonetworks.com/r/Cortex-Cloud/Cortex-Cloud-Analytics-Alert-Reference-by-data-source/Unusual-cloud-Instance-Metadata-Service-IMDS-access?contentId=IYsx5O2VxscbC_YI33QaIw
- Untitled web source: https://attack.mitre.org/datacomponents/DC0075/
- Untitled web source: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-transition-to-version-2.html
- Untitled web source: https://jnswire.s3.amazonaws.com/jns-media/78/ef/9136644/BRODERICKvCAPITAL.pdf
- Untitled web source: https://resources.reliaquest.com/image/upload/v1729540499/20241022_ALL_CloudAttacks.pdf
- Untitled web source: https://cybersecurityhoy.com/wp-content/uploads/2022/06/chapter-2_-using-threat-intelligence-_-comptia-cysa-study-guide-exam-cs0-002-2nd-edition.pdf
- Untitled web source: https://s3.amazonaws.com/assets.paloaltonetworksacademy.net/csf/unit42_cloud-threat-report-vol6.pdf
- Untitled web source: https://info.mitre-engenuity.org/hubfs/CTID/Threat_Informed_Defense_Adoption_Handbook_Sept2021.pdf
- Untitled web source: https://en.wikipedia.org/wiki/Capital_One
- Untitled web source: https://www.reddit.com/r/crowdstrike/comments/18dnavb
- Untitled web source: https://www.reddit.com/r/tech/comments/i74kyf
- Untitled web source: https://www.reddit.com/r/SecOpsDaily/comments/1vryoiv/attackers_exploit_mlflow_ssrf_flaw_to_steal_cloud/
- Untitled web source: https://www.reddit.com/r/SecOpsDaily/comments/1rrlnl5/t1059009_cloud_api_in_mitre_attck_explained/
- Untitled web source: https://www.reddit.com/r/u_Expert-Inspector4889/comments/1ukhz74/kubernetes_rbac_misconfiguration_to_cluster/
- Untitled web source: https://nvd.nist.gov/vuln/detail/CVE-2024-27132
- Untitled web source: https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service//
- Untitled web source: https://aws.amazon.com/blogs/security/tag/ssrf/
- Untitled web source: https://docs.aws.amazon.com/pdfs/prescriptive-guidance/latest/security-reference-architecture/security-reference-architecture.pdf
- Untitled web source: https://aws.amazon.com/security/security-bulletins/AWS-2025-021/
- Untitled web source: https://github.com/mlflow/mlflow/security/advisories
- Untitled web source: https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html
- Untitled web source: https://repost.aws/knowledge-center/security-best-practices
- Untitled web source: https://github.com/mlflow/mlflow/security/advisories/GHSA-7gwp-5pfp-969j
- Untitled web source: https://docs.aws.amazon.com/pdfs/security-ir/latest/userguide/sir-ug.pdf
- Untitled web source: https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/
- Untitled web source: https://docs.aws.amazon.com/securityhub/latest/userguide/exposure-ec2-instance.html
- Untitled web source: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
- Untitled web source: https://security-tracker.debian.org/tracker/CVE-2024-27132
- Untitled web source: https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf
- Untitled web source: https://docs.aws.amazon.com/whitepapers/latest/aws-security-best-practices/aws-security-best-practices.pdf
- Untitled web source: https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/aws-security-incident-response-guide.pdf
- Untitled web source: https://d1.awsstatic.com/events/reinvent/2019/Protecting_you_from_you_Misconfiguration-caused_breaches_SEC222-S.pdf
- Untitled web source: https://www.reddit.com/r/SecOpsDaily/comments/1vsp27o/simple_scans_for_cloud_metadata_service_wed_aug/
- Untitled web source: https://www.reddit.com/r/privacychain/comments/1tiz2ee/field_note_95_defeating_serverside_request/
- Untitled web source: https://www.reddit.com/r/aws/comments/g9trin
- Untitled web source: https://www.reddit.com/r/Pentesting/comments/1m19qi7
- Untitled web source: https://www.reddit.com/r/cybersources/comments/1m19ol4
- Untitled web source: https://www.reddit.com/r/cybersecurity/comments/1m19ncv
- Untitled web source: https://www.reddit.com/r/bugbounty/comments/1m19mcr
- Untitled web source: https://www.reddit.com/r/SideProject/comments/1m19prr
- Untitled web source: https://www.reddit.com/r/indiehackers/comments/1m19s01
- Untitled web source: https://www.reddit.com/r/linuxadmin/comments/1vs8wfg/cve202664849_mlflow_ssrf_guard_bypassed_via_http/
- Untitled web source: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- Untitled web source: https://www.repost.aws/knowledge-center/ec2-linux-metadata-retrieval
- Untitled web source: https://nvd.nist.gov/vuln/detail/CVE-2019-3396
- Untitled web source: https://www.eresussec.com/en/advisories/eresus-adv-2026-002
- Untitled web source: https://github.com/aw-junaid/bug-bounty/blob/main/resources/cheatsheets/Server-Side%20Request%20Forgery.md
- Untitled web source: https://community.atlassian.com/forums/Confluence-articles/Confluence-CVEs-and-common-questions/ba-p/1062634
- Untitled web source: https://github.com/advisories/GHSA-gp2f-7wcm-5fhx
- Untitled web source: https://www.elastic.co/guide/en/security/current/web-server-cloud-metadata-ssrf-request.html
- Untitled web source: https://reinforce.awsevents.com/content/dam/reinforce/2024/slides/TDR329_Elevating-security-investigations-with-generative-AI.pdf
- Untitled web source: https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/05/CSA_research_note_lmdeploy_cve_2026_33626_ai_inference_exploitation_20260507-csa-styled.pdf
- Untitled web source: https://www.doyensec.com/resources/teleport-cloud-audit-q1-2021.pdf
- Untitled web source: https://www.sans.org/webcasts/downloads/123885/slides
- Untitled web source: https://faradaysec.com/wp-content/uploads/2022/07/AWS-Common-Issues-Part-2.pdf
- Untitled web source: https://www.reddit.com/r/bugbounty/comments/tyznjy
- Untitled web source: https://www.reddit.com/r/mcp/comments/1qj6txu/markitdowns_mcp_server_will_fetch_any_uri/
- Untitled web source: https://www.reddit.com/r/aws/comments/1qicix3/psa_mcp_servers_on_ec2_with_imdsv1_can_leak_your/
- Untitled web source: https://www.reddit.com/r/linuxquestions/comments/1aelymd
- Untitled web source: https://www.reddit.com/r/aws/comments/17lj2wo
- Untitled web source: https://www.reddit.com/r/mcp/comments/1vmdlq6/built_an_mcp_fetch_server_that_actually_gets_ssrf/
- Untitled web source: https://www.reddit.com/r/SecOpsDaily/comments/1vy40kd/obfuscating_ip_addresses_as_hostnames_tue_aug_25th/
- Untitled web source: https://www.capitalonesettlement.com/Content/Documents/Complaint.pdf
- Untitled web source: https://www.docketalarm.com/cases/Washington_Western_District_Court/2--19-cr-00159/USA_v._Thompson/1/
- Untitled web source: https://www.justice.gov/usao-wdwa/united-states-v-paige-thompson
- Untitled web source: https://s3.documentcloud.org/documents/20974985/capitalone-hack-june-2021-superseeding-indictment.pdf?t=1625010698689
- Untitled web source: https://files.lbr.cloud/310462/import-Complaint-against-Capital-One-and-AWS.pdf
- Untitled web source: https://www.dandodiary.com/wp-content/uploads/sites/893/2022/09/Capital-One-Order.pdf
- Untitled web source: https://app.midpage.ai/case/united-states-v-thompson-1000196118807
- Untitled web source: https://app.midpage.ai/document/usa-v-paige-thompson--4e69dfd3-3461-4286-926b-95075801b008
- Untitled web source: https://www.casemine.com/judgement/us/623d6f66b50db948c50f4fd4
- Untitled web source: https://www.scribd.com/document/421801705/Paige-Thompson-memorandum-8-13-19
- Untitled web source: https://techearl.com/capital-one-breach-ssrf
- Untitled web source: https://www.mlex.com/mlex/articles/2089022/seattle-tech-worker-arrested-for-theft-of-capital-one-stored-data
- Untitled web source: https://appsecuritystandards.org/blog/capital-one-ssrf-how-a-metadata-endpoint-became-a-80m-breach
- Untitled web source: https://breachline.io/research/ssrf-cloud-metadata-attack-chains
- Untitled web source: https://techcrunch.com/2019/08/28/federal-grand-jury-indicts-paige-thompson-on-two-counts-related-to-the-capital-one-data-breach/
- Untitled web source: https://www.reddit.com/r/cybersecurity/comments/djn3eo
- Untitled web source: https://www.reddit.com/r/netsec/comments/cm1k9g
- Untitled web source: https://www.reddit.com/r/devops/comments/cl50q6
- Untitled web source: https://www.reddit.com/r/sysadmin/comments/cjjynh
- Untitled web source: https://www.reddit.com/r/cybersecurity/comments/k7kkzv
- Untitled web source: https://www.reddit.com/r/aws/comments/cl4h6t
- Untitled web source: https://www.sparkproxy.io/blog/securing-proxy-servers-against-ssrf-and-proxy-abuse
- Untitled web source: https://github.com/labring/FastGPT/security/advisories/GHSA-jhqw-944x-xh94
- Untitled web source: https://bblabs.es/en/academy/avanzado/ssrf-bypasses-completo
- Untitled web source: https://securelayer7.net/lab/cve-2026-69192-ip-address-address4-leading-zero-octal-ssrf
- Untitled web source: https://bugbountyreality.com/tools/ssrf-ip-obfuscation-generator
- Untitled web source: https://cyber-security.wiki/docs/application-security/web/Server-Side-Request-Forgery-SSRF/
- Untitled web source: https://github.com/twentyhq/twenty/security/advisories/GHSA-vrcj-hv2q-c58m
- Untitled web source: https://owasp.org/www-community/pages/controls/SSRF_Prevention_in_Nodejs
- Untitled web source: https://waf-bypass.dev/
- Untitled web source: https://learn.secbyte.org/blog/ssrf-url-bypass-ctf-walkthrough
- Untitled web source: https://owasp.org/www-project-web-security-testing-guide/assets/archive/OWASP_Testing_Guide_v3.pdf
- Untitled web source: https://owasp.org/www-project-code-review-guide/assets/OWASP_Code_Review_Guide_v2.pdf
- Untitled web source: https://wangchuhan.cn/publication/sp24-b/sp24-SSRF.pdf
- Untitled web source: https://vaadata.com/blog/wp-content/uploads/2022/01/SSRF_vulnerability_cheat_sheet.pdf
- Untitled web source: https://cheatsheetseries.owasp.org/assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_Orange_Tsai_Talk.pdf
- Untitled web source: https://www.reddit.com/r/hackthebox/comments/1ry6lxa/htb_facts_got_admin_on_camaleon_cms_cant_get_a/
- Untitled web source: https://www.reddit.com/r/netsec/comments/mf8i8i
- Untitled web source: https://www.reddit.com/r/bugbounty/comments/1uugmbp/help_with_ssrf/
- Untitled web source: https://www.reddit.com/r/u_TheDecipherist/comments/1qg38wk/owasp_modsecurity_deep_dive/
- Untitled web source: https://www.reddit.com/r/bugbounty/comments/1fwsq04
- Untitled web source: https://www.reddit.com/r/netsecstudents/comments/1pc65jy/struggling_with_detecting_obfuscated_ips_in/
- Untitled web source: https://www.reddit.com/r/bugbounty/comments/mqvh48
- Untitled web source: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-limiting-access.html
- Untitled web source: https://docs.aws.amazon.com/us_en/AWSEC2/latest/UserGuide/retrieve-iid.html
- Untitled web source: https://docs.aws.amazon.com/whitepapers/latest/ipv6-on-aws/supporting-amazon-vpc-services.html
- Untitled web source: https://media.defense.gov/2024/Mar/07/2003407866/-1/-1/0/CSI-CloudTop10-Identity-Access-Management.PDF
- Untitled web source: https://repost.aws/knowledge-center/ec2-linux-metadata-retrieval
- Untitled web source: https://www.cisa.gov/topics/cybersecurity-best-practices/executive-order-improving-nations-cybersecurity
- Untitled web source: https://www.cisa.gov/news-events/directives
- Untitled web source: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
- Untitled web source: https://www.cisa.gov/sites/default/files/2023-06/CSSO-SCUBA-eVRF%20Guidebook-guidance%20documentV2_508c.pdf
- Untitled web source: https://www.cisa.gov/sites/default/files/publications/CISA%20Cloud%20Security%20Technical%20Reference%20Architecture_Version%201.pdf
- Untitled web source: https://media.defense.gov/2024/Mar/07/2003407866/-1/-1/0/CSI-CLOUDTOP10-IDENTITY-ACCESS-MANAGEMENT.PDF
- Untitled web source: https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/d7ba04c4-7ae3-11ef-899d-368457bb1542/policies-feb9-2026.pdf
- Untitled web source: https://www.reddit.com/r/bugbounty/comments/1r09arm/can_i_gain_access_to_aws_ec2_via_ssrf_blind/
- Untitled web source: https://www.reddit.com/r/aws/comments/16lmi01
- Untitled web source: https://www.reddit.com/r/aws/comments/ry6gm9
- Untitled web source: https://attack.mitre.org/techniques/T1580/
- Untitled web source: https://attack.mitre.org/techniques/
- Untitled web source: https://d3fend.mitre.org/offensive-technique/attack/T1580/
- Untitled web source: https://attack.mitre.org/datacomponents/DC0017/
- Untitled web source: https://attack.mitre.org/detectionstrategies/DET0169/
- Untitled web source: https://attack.mitre.org/datacomponents/DC0083/
- Untitled web source: https://attack.mitre.org/detectionstrategies/DET0402/
- Untitled web source: https://attack.mitre.org/?tour=true
- Untitled web source: https://attack.mitre.org/techniques/T1526/
- Untitled web source: https://mitre.garnet.ai/mitre/mitre/ta0007/t1580
- Untitled web source: https://attackevals.mitre.org/results/enterprise/?evaluation=er7&scenario=1&vendor=trendmicro&view=individualParticipant
- Untitled web source: https://www.mitre.org/news-insights/news-release/mitre-center-threat-informed-defense-and-industry-map-cloud-security
- Untitled web source: https://www.sans.org/webcasts/downloads/124240/slides
- Untitled web source: https://pages.awscloud.com/rs/112-TZM-766/images/AWS_SANS_MITRE%20ATT%26CK_whitepaper.pdf?linkId=102638760&sc_campaign=AWS_Marketplace&sc_channel=sm&sc_country=Global&sc_geo=GLOBAL&sc_outcome=awareness&sc_publisher=FACEBOOK&trk=MP_SANSWP_Threat1_FACEBOOK
- Untitled web source: https://file.techscience.com/files/onlinefirst/2026/2.28/TSP_CMC_77606/TSP_CMC_77606.pdf
- Untitled web source: https://nvd.nist.gov/vuln/detail/CVE-2021-28918
- Untitled web source: https://advisories.gitlab.com/npm/netmask/CVE-2021-28918/
- Untitled web source: https://github.com/advisories/GHSA-pph6-vfjv-vpjw
- Untitled web source: https://nvd.nist.gov/vuln/detail/CVE-2023-22817
- Untitled web source: https://github.com/b4rdia/HackTricks/blob/master/pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf.md
- Untitled web source: https://github.com/advisories/GHSA-qw2m-4pqf-rmpp
- Untitled web source: https://github.com/advisories/GHSA-794r-5rp2-fpg8
- Untitled web source: https://isc.sans.edu/diary/Simple%2BScans%2Bfor%2BCloud%2BMetadata%2BService/33260/
- Untitled web source: https://opencve.alliance.unm.edu/cve/CVE-2024-0455
- Untitled web source: https://github.com/advisories/GHSA-h47f-gmjp-m7rr
- Untitled web source: https://access.redhat.com/security/cve/cve-2026-72552
- Untitled web source: https://nvd.nist.gov/vuln/detail/cve-2024-20404
- Untitled web source: https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/04/CSA_research_note_lmdeploy-ssrf-ai-inference-exploitation_20260425-csa-styled-2.pdf
- Untitled web source: https://insiderllm.com/pdfs/openclaw-security-report-february-2026.pdf
- Untitled web source: https://unit42.paloaltonetworks.com/server-side-request-forgery-exposes-data-of-technology-industrial-and-media-organizations/?_wpnonce=e121760fa3&lg=en&pdf=print
- Untitled web source: https://isomer-user-content.by.gov.sg/36/a5531b14-3ea9-47db-9653-2d247a9f9d54/20_May_2026.pdf
- Untitled web source: https://nvd.nist.gov/vuln/detail/CVE-2021-22214
- Untitled web source: https://gitlab.com/gitlab-org/cves/-/blob/master/2021/CVE-2021-22214.json
- Untitled web source: https://www.jenkins.io/security/advisory/2018-06-25/
- Untitled web source: https://cve.mitre.org/cgi-bin/cvename.cgi?name=2018-1000600
- Untitled web source: https://vulners.com/nuclei/NUCLEI%3ACVE-2018-1000600
- Untitled web source: https://docs.gitlab.com/user/application_security/gitlab_advisory_database/
- Untitled web source: https://advisories.gitlab.com/maven/org.jenkins-ci.plugins/urltrigger/CVE-2018-1000606/
- Untitled web source: https://www.jenkins.io/security/advisory/2018-01-22/
- Untitled web source: https://www.jenkins.io/security/advisory/2018-10-10/
- Untitled web source: https://forum.gitlab.com/t/about-cve-2021-22214-vulnerability/67929
- Untitled web source: https://www.jenkins.io/security/advisory/2018-02-14/
- Untitled web source: https://handouts.secappdev.org/handouts/2022/jimmanico_requestforgery.pdf
- Untitled web source: https://conference.hitb.org/hitbsecconf2019ams/materials/D2T1%20-%20Hacking%20Jenkins%20-%20Orange%20Tsai.pdf
- Untitled web source: https://www.caloes.ca.gov/wp-content/uploads/Homeland-Security/Documents/Cyber-Advisories/Cal-CSIC-Cyber-Advisory-Multipule-GitLab-Pipeline-Vulnerabilities.pdf
- Untitled web source: https://www.reddit.com/r/bugbounty/comments/pdq10v
- Untitled web source: https://downloads.regulations.gov/CISA-2023-0027-0023/attachment_1.pdf
- Untitled web source: https://www.youtube.com/watch?v=--rd5bVX-Qc
- Untitled web source: https://www.cve.org/Resources/Media/Archives/Blogs/2017/2017-12-31_All-2017-Archived-Blogs.pdf
- Untitled web source: https://www.reddit.com/r/oscp/comments/nm4a36
- Untitled web source: https://arxiv.org/abs/2107.08760

### File Search

- Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md
- 소프트웨어_개발보안_가이드(2021.12.29).pdf
- 주요정보통신기반시설_기술적_취약점_분석_평가_방법_상세가이드.pdf
- CWE-918 Server-Side Request Forge.md
