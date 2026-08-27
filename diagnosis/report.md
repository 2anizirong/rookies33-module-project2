# AI Security Intelligence Report

## 1. 종합 위험도

- Severity: **HIGH**
- AI Risk Score: **8.2 / 10**
- 판단 근거: SSRF sink confirmed via url parameter with successful decimal/hex/octal IP filter bypass; IMDSv1 reachable (IMDSv2 not enforced); temporary AWS credentials exposed; and those credentials successfully used to access cloud APIs (S3 ListBuckets; Lambda ListFunctions/GetFunction). Read/list scope only, so not critical.

## 2. 취약점 분류

- 취약점: Server-Side Request Forgery (SSRF)
- CWE: CWE-918
- 설명: The application accepts a user-controlled url (GET, query) that the server uses to make outbound requests. Input filters can be bypassed using alternative IP encodings (decimal/hex/octal), enabling access to internal resources including the EC2 instance metadata service (IMDSv1). Exposed temporary credentials from the instance role allowed read/enumeration against AWS services.

### 공격 체인

1. User supplies url parameter causing server-side HTTP request (sink confirmed)
2. Filter bypass using decimal/hex/octal IP notation to reach link-local host
3. Access EC2 IMDSv1 (v2 not enforced) and extract temporary credentials
4. Use temporary credentials to call AWS APIs: S3 ListBuckets; Lambda ListFunctions/GetFunction

## 3. 자동 진단 증거

- **Parameter discovery: url (GET, query); server-side request detected for this parameter.**
  - 의미: Confirms a controllable SSRF sink exists.
- **Bypass diagnosis: decimal_ip/hex_ip/octal_ip techniques returned HTTP 200; direct technique blocked (403).**
  - 의미: Indicates blacklist-style filtering is in place but is bypassable via alternative IP encodings—classic SSRF filter evasion.
- **IMDS exposure: IMDSv1 reachable; v2 not enforced; data extracted; IAM role detected; temporary credentials exposed.**
  - 의미: Instance metadata service is accessible via SSRF, enabling credential theft (T1552.005).
- **Cloud impact: Principal type IAMRole; confirmed permissions S3:ListBuckets; Lambda:ListFunctions,GetFunction; overall_impact=medium.**
  - 의미: Temporary credentials are valid and permit read/enumeration across S3 buckets and Lambda functions (information disclosure).

## 4. 관련 CVE

- 직접 대응 CVE 확인: 아니오
- 설명: The assessed target is not a known product/version with a published CVE. External CVEs are provided only as similar attack patterns.

### CVE-2019-8451

- 관계: similar_attack_pattern
- 설명: Atlassian Jira SSRF vulnerability
- 현재 진단과의 관계: Demonstrates SSRF leading to internal/metadata access patterns similar to this case; not a direct match to the assessed system.

### CVE-2020-8555

- 관계: similar_attack_pattern
- 설명: Kubernetes kube-controller-manager SSRF
- 현재 진단과의 관계: Illustrates SSRF to link-local/loopback targets (e.g., metadata services); conceptually aligned with observed IMDS access.

### CVE-2021-28918

- 관계: similar_attack_pattern
- 설명: netmask parsing flaw allowing octal IP bypass
- 현재 진단과의 관계: Shows how octal/alternative IP formats can bypass filters, consistent with successful decimal/hex/octal bypass here.

## 5. 실제 침해 / 공개 사례

### Capital One breach (2019)

- 설명: Publicly documented incident where SSRF enabled access to EC2 IMDS to obtain credentials, facilitating data theft.
- 유사점: High similarity in attack chain (SSRF → IMDS → credentials).

## 6. 공식 보안 권고

- **MITRE / CWE-918 Server-Side Request Forgery**
  - 권고: Defines SSRF and associated risks including access to internal resources via server-initiated requests.
  - 적용 이유: Directly classifies the observed vulnerability.
- **MITRE ATT&CK / T1552.005 Credentials from Instance Metadata**
  - 권고: Describes obtaining credentials from cloud instance metadata services.
  - 적용 이유: Matches the confirmed extraction of temporary credentials from IMDSv1.
- **AWS / IMDSv2 defense in depth**
  - 권고: Recommend enforcing IMDSv2 and disabling IMDSv1; explains session-oriented tokens and hop limit to mitigate SSRF abuse.
  - 적용 이유: IMDSv1 is currently accessible; v2 not enforced.
- **AWS / Configure and limit access to IMDS**
  - 권고: Documents enabling IMDSv2, transition guidance, and limiting access to metadata service.
  - 적용 이유: Actionable steps to close the confirmed exposure.
- **NSA/CISA / Cloud IAM secure practices**
  - 권고: Advocates minimizing exposure of metadata and enforcing least privilege.
  - 적용 이유: Supports reducing blast radius of any exposed temporary credentials.

## 7. 내부 보안 가이드 연계

- **OWASP Server-Side Request Forgery (SSRF) Prevention Cheat Sheet / Application and network-layer SSRF mitigations**
  - 관계: direct
  - 내용: Prefer allow-lists; validate and normalize destinations; restrict protocols; disable redirects; block link-local/loopback/RFC1918; move to IMDSv2/disable v1; note bypass risks of deny-lists and alternative IP encodings.
  - 진단과의 관계: Directly addresses the observed bypasses and IMDSv1 exposure.
- **소프트웨어 개발보안 가이드 (2021.12.29) / Avoid DNS-based trust for security decisions**
  - 관계: indirect
  - 내용: Do not rely on reverse DNS or DNS lookups for trust decisions; validate by resolved IP and ranges instead.
  - 진단과의 관계: Supports robust target validation in SSRF defenses.

## 8. 종합 분석

### 공격 시나리오

An attacker supplies a crafted url in the GET query. The server performs a request on behalf of the attacker. Although direct requests to sensitive targets are blocked (403), the attacker bypasses filters using decimal/hex/octal IP encodings to reach link-local 169.254.169.254 (EC2 IMDSv1). The attacker retrieves temporary credentials for the instance IAM role and uses them to call AWS APIs including S3 ListBuckets and Lambda ListFunctions/GetFunction.

### 확인된 영향

- SSRF via url parameter with successful filter bypass using decimal/hex/octal IP encodings
- Access to EC2 IMDSv1 (v2 not enforced) and extraction of temporary credentials for an IAM role
- Use of exposed credentials to perform: S3 ListBuckets (bucket enumeration) and Lambda ListFunctions/GetFunction (function enumeration and metadata), i.e., information disclosure/enumeration
- Overall cloud impact assessed as medium in diagnostics

### 잠재 영향

- If additional permissions are attached to the same role (not confirmed here), attacker could escalate to data exfiltration from S3 objects, modification/deployment of Lambda functions, or broader lateral movement
- Even with read-only scope, function metadata (via GetFunction) may reveal code locations or configuration details aiding reconnaissance
- Continued exposure increases risk of role policy changes or chained abuses by other actors

### 진단 한계

- Only one SSRF sink (url) confirmed
- Successful cloud API calls are limited to read/enumeration (S3 ListBuckets; Lambda ListFunctions/GetFunction); no write/delete/execute capabilities confirmed
- No specific resource names, account IDs, ARNs, or credential values were captured in this assessment

## 9. 대응방안

- **[HIGH] Enforce IMDSv2 and disable IMDSv1 on affected EC2 instances (and set hop limit appropriately).**
  - 근거: Directly mitigates credential theft via SSRF by requiring session tokens and reducing unauthenticated access.
- **[HIGH] Implement strict allow-list validation and normalization for outbound destinations used by the server (protocols, hosts/IPs, ports).**
  - 근거: Prevents attacker-supplied URLs from reaching internal/link-local addresses; avoid blacklist-only controls prone to bypass.
- **[HIGH] Block link-local, loopback, and private address ranges at application and egress network layers; disable HTTP redirects for SSRF flows.**
  - 근거: Stops access to IMDS (169.254.169.254) and other internal targets even if application filters are bypassed.
- **[HIGH] Immediately rotate and revoke any exposed temporary credentials; review CloudTrail/CloudWatch logs for use of the instance role.**
  - 근거: Limits ongoing abuse and provides detection of any credential utilization.
- **[MEDIUM] Tighten IAM role to least privilege, removing unneeded list/read permissions if not required by workload.**
  - 근거: Reduces reconnaissance value and blast radius if credentials are exposed again.
- **[MEDIUM] Centralize outbound HTTP(S) via a proxy with policy enforcement and DNS/IP egress controls; monitor for obfuscated IP patterns.**
  - 근거: Adds defense-in-depth to detect/stop SSRF attempts and IP-encoding bypasses.
- **[MEDIUM] Input handling hardening: canonicalize and re-resolve hostnames to IP, verify against CIDR allow-list, and reject on any redirect or DNS rebinding.**
  - 근거: Addresses common SSRF evasion techniques, including alternate IP representations and DNS tricks.
- **[LOW] Add WAF rules and application telemetry to detect SSRF indicators (e.g., requests targeting metadata endpoints, obfuscated IPs).**
  - 근거: Improves detection and response time but should not replace application/network controls.

## 10. 검색 출처

### Web Search

- CWE - CWE-918: Server-Side Request Forgery (SSRF) (4.20): https://cwe.mitre.org/data/definitions/918.html?trk=article-ssr-frontend-pulse_little-text-block&utm_source=openai
- Unsecured Credentials: Cloud Instance Metadata API, Sub-technique T1552.005 - Enterprise | MITRE ATT&CK®: https://attack.mitre.org/techniques/T1552/005/?utm_source=openai
- Server Side Request Forgery Prevention - OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html?utm_source=openai
- NVD - CVE-2019-8451: https://nvd.nist.gov/vuln/detail/CVE-2019-8451?utm_source=openai
- NVD - cve-2020-8555: https://nvd.nist.gov/vuln/detail/cve-2020-8555?utm_source=openai
- NVD - CVE-2021-28918: https://nvd.nist.gov/vuln/detail/CVE-2021-28918?utm_source=openai
- Western District of Washington | Seattle Tech Worker Arrested for Data Theft Involving Large Financial Services Company | United States Department of Justice: https://www.justice.gov/usao-wdwa/pr/seattle-tech-worker-arrested-data-theft-involving-large-financial-services-company?utm_source=openai
- Server-Side Request Forgery Exposes Data of Technology, Industrial and Media Organizations: https://unit42.paloaltonetworks.com/server-side-request-forgery-exposes-data-of-technology-industrial-and-media-organizations/?utm_source=openai
- Add defense in depth against open firewalls, reverse proxies, and SSRF vulnerabilities with enhancements to the EC2 Instance Metadata Service | AWS Security Blog: https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service//?utm_source=openai
- Use the Instance Metadata Service to access instance metadata - Amazon Elastic Compute Cloud: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html?utm_source=openai
- Enforce only IMDSv2 access to my EC2 instance metadata | AWS re:Post: https://repost.aws/knowledge-center/ssm-ec2-enforce-imdsv2?utm_source=openai
- Limit access to the Instance Metadata Service - Amazon Elastic Compute Cloud: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-limiting-access.html?utm_source=openai
- Remediating exposures for EC2 instances - AWS Security Hub: https://docs.aws.amazon.com/securityhub/latest/userguide/exposure-ec2-instance.html?utm_source=openai
- NSA & CISA | Use Secure Cloud Identity and Access Management Practices: https://media.defense.gov/2024/Mar/07/2003407866/-1/-1/0/CSI-CloudTop10-Identity-Access-Management.PDF?utm_source=openai
- Access instance metadata for an EC2 instance - Amazon Elastic Compute Cloud: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html?utm_source=openai
- ListBuckets - Amazon S3: https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBuckets.html?utm_source=openai
- Untitled web source: https://attack.mitre.org/techniques/T1552/005/
- Untitled web source: https://cwe.mitre.org/data/published/cwe_v2.12.pdf
- Untitled web source: https://mitre.garnet.ai/mitre/mitre/ta0006/t1522
- Untitled web source: https://cwe.mitre.org/data/definitions/918.html?trk=article-ssr-frontend-pulse_little-text-block
- Untitled web source: https://attack.mitre.org/datacomponents/DC0076/
- Untitled web source: https://attack.mitre.org/techniques/T1580/
- Untitled web source: https://attack.mitre.org/datacomponents/
- Untitled web source: https://attack.mitre.org/detectionstrategies/DET0169/
- Untitled web source: https://security.glexia.com/threat-intelligence/attack/techniques/T1552.005-cloud-instance-metadata-api
- Untitled web source: https://www.justice.gov/usao-wdwa/pr/seattle-tech-worker-arrested-data-theft-involving-large-financial-services-company
- Untitled web source: https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service//
- Untitled web source: https://security.glexia.com/threat-intelligence/attack/techniques/T1059.009-cloud-api
- Untitled web source: https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Instance%20Metadata%20API/
- Untitled web source: https://media.licdn.com/dms/document/media/v2/D561FAQF1UQBqz3qcDA/feedshare-document-pdf-analyzed/feedshare-document-pdf-analyzed/0/1710131584207?e=1768435200&t=RHAD0JWcDzDOJxWjgAjnOWmHewi7sJ2T6Usy3EIl3Qg&v=beta
- Untitled web source: https://cybersecurityhoy.com/wp-content/uploads/2022/06/chapter-2_-using-threat-intelligence-_-comptia-cysa-study-guide-exam-cs0-002-2nd-edition.pdf
- Untitled web source: https://jnswire.s3.amazonaws.com/jns-media/78/ef/9136644/BRODERICKvCAPITAL.pdf
- Untitled web source: https://www.petefreitag.com/presentations/2023-cwe-25.pdf
- Untitled web source: https://en.wikipedia.org/wiki/Server-side_request_forgery
- Untitled web source: https://www.capitalonesettlement.com/Content/Documents/Complaint.pdf
- Untitled web source: https://www.reddit.com/r/bugbounty/comments/13f3r7k
- Untitled web source: https://www.reddit.com/r/SecOpsDaily/comments/1rrlnl5/t1059009_cloud_api_in_mitre_attck_explained/
- Untitled web source: https://www.reddit.com/r/crowdstrike/comments/18dnavb
- Untitled web source: https://www.reddit.com/r/privacychain/comments/1tiz2ee/field_note_95_defeating_serverside_request/
- Untitled web source: https://www.reddit.com/r/crowdstrike/comments/1dvyikz
- Untitled web source: https://www.reddit.com/r/crowdstrike/comments/17s63ri
- Untitled web source: https://nvd.nist.gov/vuln/detail/CVE-2019-8451
- Untitled web source: https://opencve.alliance.unm.edu/cve/CVE-2019-8451
- Untitled web source: https://nvd.nist.gov/vuln/detail/cve-2020-8555
- Untitled web source: https://github.com/kubernetes/kubernetes/issues/91542
- Untitled web source: https://kubernetes.io/docs/reference/issues-security/official-cve-feed/
- Untitled web source: https://jira.atlassian.com/browse/JRASERVER-69793--
- Untitled web source: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8555
- Untitled web source: https://github.com/kubernetes/kubernetes/issues/99425
- Untitled web source: https://unit42.paloaltonetworks.com/server-side-request-forgery-exposes-data-of-technology-industrial-and-media-organizations/
- Untitled web source: https://advisories.gitlab.com/golang/k8s.io/kubernetes/CVE-2020-8555/
- Untitled web source: https://www.tenable.com/blog/cve-2019-8451-proof-of-concept-available-for-server-side-request-forgery-ssrf-vulnerability-in
- Untitled web source: https://jira.atlassian.com/browse/JSWSERVER-26815
- Untitled web source: https://unit42.paloaltonetworks.com/server-side-request-forgery-exposes-data-of-technology-industrial-and-media-organizations/?_wpnonce=3df28d88da&lg=en&pdf=print
- Untitled web source: https://unit42.paloaltonetworks.com/server-side-request-forgery-exposes-data-of-technology-industrial-and-media-organizations/?_wpnonce=9f6c41a3cd&lg=en&pdf=print
- Untitled web source: https://owasp.org/www-chapter-bangkok/slides/2023/2023-03-31_OWASP-API.pdf
- Untitled web source: https://raw.githubusercontent.com/dohsimpson/kubernetes-doc-pdf/master/PDFs/Reference.pdf
- Untitled web source: https://cert.europa.eu/publications/security-advisories/2022-047/pdf
- Untitled web source: https://www.venustech.com.cn/uploads/2020/08/170947121504.pdf
- Untitled web source: https://arxiv.org/abs/2006.15275
- Untitled web source: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
- Untitled web source: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-options.html
- Untitled web source: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
- Untitled web source: https://aws.amazon.com/blogs/aws/amazon-ec2-instance-metadata-service-imdsv2-by-default/
- Untitled web source: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-transition-to-version-2.html
- Untitled web source: https://repost.aws/knowledge-center/ssm-ec2-enforce-imdsv2
- Untitled web source: https://docs.aws.amazon.com/prescriptive-guidance/latest/bot-control/techniques.html
- Untitled web source: https://repost.aws/knowledge-center/ec2-linux-metadata-retrieval
- Untitled web source: https://aws.amazon.com/blogs/security/get-the-full-benefits-of-imdsv2-and-disable-imdsv1-across-your-aws-infrastructure/
- Untitled web source: https://docs.aws.amazon.com/prescriptive-guidance/latest/bot-control/static-controls.html
- Untitled web source: https://docs.aws.amazon.com/waf/latest/developerguide/ddos-automatic-app-layer-response-bp.html
- Untitled web source: https://docs.aws.amazon.com/pdfs/prescriptive-guidance/latest/security-reference-architecture-generative-ai/security-reference-architecture-generative-ai.pdf
- Untitled web source: https://repost.aws/knowledge-center/waf-block-common-attacks
- Untitled web source: https://docs.aws.amazon.com/ec2/latest/devguide/ec2-dg.pdf
- Untitled web source: https://windows2026.net/?_=%2Fpdfs%2Fautoscaling%2Fec2%2Fuserguide%2Fas-dg.pdf%23Xj2F0BkBaIL4qvKHMogVSxgonMEQVCmD%2F6r8
- Untitled web source: https://aws-shield-tlr.s3.amazonaws.com/2020-Q1_AWS_Shield_TLR.pdf
- Untitled web source: https://awsdocs.s3.amazonaws.com/EC2/2014-02-01/ec2-ug-2014-02-01.pdf
- Untitled web source: https://govapps.md.gov/GovForms/uploads/Appointees/systems-manager-automation-runbook-guide_58.pdf
- Untitled web source: https://www.youtube.com/watch?v=7jYF7jX8AKo
- Untitled web source: https://www.youtube.com/watch?v=B9HPYzVk_dM
- Untitled web source: https://www.reddit.com/r/linuxquestions/comments/1aelymd
- Untitled web source: https://www.reddit.com/r/aws/comments/1bioamv
- Untitled web source: https://www.reddit.com/r/aws/comments/wzvepj
- Untitled web source: https://www.reddit.com/r/aws/comments/xld63m
- Untitled web source: https://www.reddit.com/r/aws/comments/drpdiv
- Untitled web source: https://www.reddit.com/r/aws/comments/ry6gm9
- Untitled web source: https://www.reddit.com/r/aws/comments/1cxywu8
- Untitled web source: https://www.reddit.com/r/aws/comments/rxs3aw
- Untitled web source: https://www.reddit.com/r/netsec/comments/euli42
- Untitled web source: https://www.reddit.com/r/aws/comments/1gh16j1
- Untitled web source: https://www.reddit.com/r/aws/comments/16whe39
- Untitled web source: https://portswigger.net/web-security/ssrf
- Untitled web source: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- Untitled web source: https://wiki.athena-ctf.com/docs/web/server-side/ssrf
- Untitled web source: https://michalszalkowski.com/payload/ssrf/
- Untitled web source: https://cyber-security.wiki/docs/application-security/web/Server-Side-Request-Forgery-SSRF/
- Untitled web source: https://skills.rest/skill/ssrf-ip-filter-bypass
- Untitled web source: https://portswigger.net/web-security/ssrf/lab-ssrf-with-blacklist-filter
- Untitled web source: https://securelayer7.net/lab/cve-2026-69192-ip-address-address4-leading-zero-octal-ssrf
- Untitled web source: https://bblabs.es/en/academy/avanzado/ssrf-bypasses-completo
- Untitled web source: https://bugbountyreality.com/tools/ssrf-ip-obfuscation-generator
- Untitled web source: https://github.com/yaklang/hack-skills/blob/main/skills/ssrf-server-side-request-forgery/SKILL.md
- Untitled web source: https://labs.trace37.com/blog/enigma-ssrf-engine/
- Untitled web source: https://www.prosec-networks.com/wp-content/uploads/wstg-v4.2.pdf
- Untitled web source: https://raw.githubusercontent.com/akr3ch/BugBountyBooks/main/Bug%20Bounty%20Bootcamp%20The%20Guide%20to%20Finding%20and%20Reporting%20Web%20Vulnerabilities%20by%20Vickie%20Li.pdf
- Untitled web source: https://vaadata.com/blog/wp-content/uploads/2022/01/SSRF_vulnerability_cheat_sheet.pdf
- Untitled web source: https://catalogimages.wiley.com/images/db/pdf/9781119735380.excerpt.pdf
- Untitled web source: https://www.reddit.com/r/hackthebox/comments/1ry6lxa/htb_facts_got_admin_on_camaleon_cms_cant_get_a/
- Untitled web source: https://wangchuhan.cn/publication/sp24-b/sp24-SSRF.pdf
- Untitled web source: https://www.reddit.com/r/mcp/comments/1v937uv/what_i_learned_building_a_pdf_readwrite_mcp/
- Untitled web source: https://www.reddit.com/r/SecOpsDaily/comments/1vy40kd/obfuscating_ip_addresses_as_hostnames_tue_aug_25th/
- Untitled web source: https://www.reddit.com/r/netsec/comments/mf8i8i
- Untitled web source: https://www.reddit.com/r/bugbounty/comments/pdq10v
- Untitled web source: https://www.reddit.com/r/netsecstudents/comments/1pc65jy/struggling_with_detecting_obfuscated_ips_in/
- Untitled web source: https://www.reddit.com/r/bugbounty/comments/1uugmbp/help_with_ssrf/
- Untitled web source: https://www.reddit.com/r/hacking/comments/i0vl35
- Untitled web source: https://media.defense.gov/2024/Mar/07/2003407866/-1/-1/0/CSI-CloudTop10-Identity-Access-Management.PDF
- Untitled web source: https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-144.pdf
- Untitled web source: https://media.defense.gov/2024/Mar/07/2003407866/-1/-1/0/CSI-CLOUDTOP10-IDENTITY-ACCESS-MANAGEMENT.PDF
- Untitled web source: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-limiting-access.html
- Untitled web source: https://maturitymodel.security.aws.dev/en/2.-foundational/imdsv2/
- Untitled web source: https://www.cisa.gov/eviction-strategies-tool/info-attack/T1580
- Untitled web source: https://aws.amazon.com/security/security-bulletins/AWS-2025-021/
- Untitled web source: https://www.nist.gov/system/files/documents/itl/cloud/NIST_SP-500-291_Version-2_2013_June18_FINAL.pdf
- Untitled web source: https://docs.aws.amazon.com/securityhub/latest/userguide/exposure-ec2-instance.html
- Untitled web source: https://www.cisa.gov/sites/default/files/2023-06/CSSO-SCUBA-eVRF%20Guidebook-guidance%20documentV2_508c.pdf
- Untitled web source: https://www.cisa.gov/news-events/directives
- Untitled web source: https://csrc.nist.rip/CSRC/media/Publications/nistir/8006/draft/documents/draft_nistir_8006.pdf
- Untitled web source: https://nvd.nist.gov/vuln/detail/cve-2026-27739
- Untitled web source: https://www.reddit.com/r/SecOpsDaily/comments/1vsp27o/simple_scans_for_cloud_metadata_service_wed_aug/
- Untitled web source: https://www.reddit.com/r/NISTControls/comments/nfcjdw
- Untitled web source: https://www.reddit.com/r/aws/comments/e18e5n
- Untitled web source: https://nvd.nist.gov/vuln/detail/CVE-2021-28918
- Untitled web source: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-28918
- Untitled web source: https://nvd.nist.gov/vuln/detail/cve-2021-29418
- Untitled web source: https://advisories.gitlab.com/npm/netmask/CVE-2021-28918/
- Untitled web source: https://nvd.nist.gov/vuln/detail/CVE-2021-29921
- Untitled web source: https://www.kodemsecurity.com/cve-archive/cve-2021-28918
- Untitled web source: https://security.snyk.io/vuln/SNYK-JS-NETMASK-1089716
- Untitled web source: https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=ssrf
- Untitled web source: https://security-tracker.debian.org/tracker/CVE-2021-28918
- Untitled web source: https://osv.dev/vulnerability/GHSA-4c7m-wxvm-r7gc
- Untitled web source: https://research.atomicorp.com/cves/CVE-2021-28918/
- Untitled web source: https://www.resolvedsecurity.com/vulnerability-catalog/CVE-2021-28918
- Untitled web source: https://isomer-user-content.by.gov.sg/36/ca18fc73-dfb9-49b3-9746-6449e9e1156c/07-April-2021.pdf
- Untitled web source: https://cwe.mitre.org/data/published/cwe_v4.10.pdf
- Untitled web source: https://cwe.mitre.org/data/published/cwe_v4.12.pdf
- Untitled web source: https://cwe.mitre.org/data/published/cwe_v4.9.pdf
- Untitled web source: https://cwe.mitre.org/data/published/cwe_v4.14.pdf
- Untitled web source: https://cwe.mitre.org/data/published/cwe_v4.15.pdf
- Untitled web source: https://www.reddit.com/r/webdev/comments/mfqq44
- Untitled web source: https://docs.aws.amazon.com/lambda/latest/api/API_ListFunctions.html
- Untitled web source: https://docs.aws.amazon.com/lambda/latest/api/API_GetFunction.html
- Untitled web source: https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBuckets.html
- Untitled web source: https://docs.aws.amazon.com/AmazonS3/latest/userguide/list-buckets.html
- Untitled web source: https://docs.aws.amazon.com/cli/latest/reference/s3api/list-buckets.html
- Untitled web source: https://docs.aws.amazon.com/lambda/latest/dg/example_lambda_GetFunction_section.html
- Untitled web source: https://docs.aws.amazon.com/cli/latest/reference/lambda/list-functions.html?highlight=variable
- Untitled web source: https://docs.aws.amazon.com/pdfs/lambda/latest/api/lambda-api.pdf
- Untitled web source: https://docs.aws.amazon.com/cli/v1/reference/s3api/list-buckets.html
- Untitled web source: https://docs.aws.amazon.com/botocore/latest/reference/services/lambda/client/list_functions.html
- Untitled web source: https://aws.amazon.com/about-aws/whats-new/2024/10/amazon-s3-new-region-bucket-name-filtering-listbuckets-api/
- Untitled web source: https://docs.aws.amazon.com/ja_jp/lambda/latest/api/API_GetFunction.html
- Untitled web source: https://awsdocs.s3.amazonaws.com/S3/latest/s3-api.pdf
- Untitled web source: https://docs.aws.amazon.com/boto3/latest/reference/services/lambda/paginator/ListFunctions.html
- Untitled web source: https://docs.aws.amazon.com/sdk-for-net/v3/developer-guide/aws-sdk-net-v3-dg.pdf
- Untitled web source: https://platform.softwareone.com/files/product-media-files/PCP-4838-8135/7085ed9b0c3b3b8087e0af022396f68c84eb0ad1bb7e5e853302a9a29a3aa849.pdf
- Untitled web source: https://venus.strandls.com/biodiv/content/documents/2f9e433b-e148-4941-9965-dc3b07285444/ca66111de4264982841417db6b9b4a3e.pdf
- Untitled web source: https://docs.aws.amazon.com/es_es/AmazonS3/latest/userguide/s3-userguide.pdf
- Untitled web source: https://www.reddit.com/r/aws/comments/1624do1
- Untitled web source: https://www.reddit.com/r/devops/comments/t9epkn
- Untitled web source: https://www.reddit.com/r/aws/comments/k5oi2j
- Untitled web source: https://www.reddit.com/r/aws/comments/11s34ow
- Untitled web source: https://www.reddit.com/r/aws/comments/1d29cvb
- Untitled web source: https://www.reddit.com/r/aws/comments/d6hkfa
- Untitled web source: https://www.reddit.com/r/aws/comments/164j5de
- Untitled web source: https://www.reddit.com/r/aws/comments/14fx8zp
- Untitled web source: https://www.reddit.com/r/aws/comments/dt4zjc
- Untitled web source: https://www.reddit.com/r/aws/comments/xtxyuv

### File Search

- Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md
- 소프트웨어_개발보안_가이드(2021.12.29).pdf
- 주요정보통신기반시설_기술적_취약점_분석_평가_방법_상세가이드.pdf
