# SSRF-클라우드 자격증명 탈취 체인 자동 진단 도구

SK쉴더스 루키즈 33기 모듈프로젝트2 (2026.08.26 ~ 08.31)


## 프로젝트 개요
SSRF 취약점을 시작점으로 클라우드 내부 자격증명(IMDS)까지 탈취하는
전체 공격 체인을 자동으로 재현/탐지하고, 생성형 AI가 공격 흐름 전체를
근거로 위험도와 대응방안을 판단해주는 자동진단 도구입니다.

배경: `localhost`/점(.) 문자열 필터만으로는 10진수 IP 변환(예: 127.0.0.1
→ 2130706433) 등으로 손쉽게 우회 가능하며, 2019년 Capital One 침해사고처럼
SSRF 하나가 IMDS 접근 → IAM 자격증명 탈취 → S3 대량 유출로 이어질 수 있습니다.


## 폴더 구조
```
rookies33-module-project2/
│
├── dashboard/                          # Streamlit 대시보드
│   └── src/
│       ├── config.json                 # 대시보드 설정
│       ├── dashboard.py                # 메인 대시보드 진입점
│       ├── run_pipeline.py             # 진단 파이프라인 실행
│       └── report_parser.py            # 리포트 파싱
│
├── diagnosis/                          # SSRF 자동 진단 엔진
│   ├── ai/                             # SSRF 체인 AI 분석 (기존)
│   │   ├── analyze.py                  # 전체 로그 → AI 판단 오케스트레이션
│   │   ├── evidence_extractor.py       # 진단 증거 추출
│   │   ├── report_generator.py         # 보고서 생성
│   │   └── web_research.py             # 웹서치 기반 보안 자료 조사
│   │
│   ├── ai_etc/                         # 추가 취약점 체인 AI 분석 (추가)
│   │   ├── analyze_etc.py              # 추가 취약점 진단 결과 AI 판단 오케스트레이션
│   │   ├── evidence_extractor_etc.py   # 추가 취약점 진단 증거 추출
│   │   ├── report_generator_etc.py     # 추가 취약점 보고서 생성
│   │   └── web_research_etc.py         # 추가 취약점 관련 웹서치 기반 보안 자료 조사
│   │
│   ├── src/                            # 진단 Stage 모듈
│   │   ├── payloads.py                 # 공격 페이로드 정의
│   │   ├── stage1_parameter_discovery.py   # 파라미터 탐색
│   │   ├── stage2_sink_discovery.py        # SSRF Sink 탐지
│   │   ├── stage3_bypass_diagnosis.py      # 필터 우회 기법 진단
│   │   ├── stage4_imds_exposure.py         # IMDS 자격증명 탈취
│   │   ├── stage5_cloud_impact.py          # S3/Lambda 접근 범위 점검
│   │   ├── stage6_sqli_diagnosis.py        # SQL Injection 진단
│   │   ├── stage7_stored_xss.py            # Stored/Reflected XSS 진단
│   │   ├── stage8_os_command_injection.py  # OS Command Injection 진단
│   │   └── stage9_login_limit.py           # 로그인 제한 진단
│   │
│   └── main.py                         # 전체 파이프라인 실행 오케스트레이터
│
├── web/                                # SSRF 취약 웹 서비스
│   ├── templates/                      # Flask HTML 템플릿
│   │   ├── base.html
│   │   ├── gallery.html
│   │   ├── image_detail.html
│   │   ├── index.html
│   │   ├── login.html
│   │   ├── new_post.html
│   │   ├── post.html
│   │   ├── preview.html
│   │   ├── register.html
│   │   └── upload.html
│   ├── app.py                          # Flask 취약 웹 서버 - SSRF/XSS/SQLi 진입점
│   └── metadata_server.py              # 로컬 mock IMDS 서버
│
├── .env / .env.example                 # 환경변수 (OPENAI_API_KEY, AWS 설정 등)
├── .gitignore                          # .env, *.pem, *.db 등 커밋 방지
├── README.md
└── requirements.txt                    # 전체 의존 패키지
```


## 핵심 기능
 
### SSRF 공격 체인 (Stage 1~5)
1. 파라미터 자동 탐색 (Arjun 활용)
2. SSRF Sink 탐지
3. 필터 우회 진단 (10진수 IP, 리다이렉트, 8진수, 16진수 등)
4. IMDS 자격증명 탈취 (169.254.169.254)
5. S3/Lambda 접근 범위 점검

### 추가 취약점 진단 (Stage 6~9)
6. SQL Injection 진단
7. Stored/Reflected XSS 진단
8. OS Command Injection 진단
9. 로그인 횟수 제한 진단
    
### AI 분석
- SSRF 체인: `diagnosis/ai/` — 전체 공격 체인 로그 → 위험도 판단 + 대응방안
- 추가 취약점 체인: `diagnosis/ai_etc/` — 추가 취약 진단 결과 → 웹서치 → 위험도 판단


## 역할 분담
 
| 파트 | 담당자 | 담당 영역 |
|---|---|---|
| 웹/AWS 구축 | 김민성, 김상현, 김이안 | `web/`, AWS EC2/IAM/S3/Lambda |
| SSRF 진단 도구 | 김태회, 안준엽, 조윤호 | `diagnosis/src/`, `diagnosis/ai/` |
| 추가 진단 도구 | 김상현, 김이안, 김태회, 안준엽 | `diagnosis/ai_etc` |
| 대시보드 | 김민성 | `dashboard/` 


## ⭐⭐⭐ 실행 방법

### 환경 설정
```bash
pip install -r requirements.txt
cp .env.example .env   # OPENAI_API_KEY 등 입력
```
 
### 취약 웹 서버 실행 (EC2)
```bash
# 백그라운드 실행 (SSH 끊겨도 유지)
nohup python3 web/app.py > server.log 2>&1 &
```
 
### 전체 진단 파이프라인 실행
```bash
# SSRF + XSS 통합 진단
python diagnosis/main.py http://<EC2_IP>:5000/fetch \
  --base-url http://<EC2_IP>:5000 \
  --skip-sink \
  -o diagnosis/scan_result.json
```
 
### AI 분석 실행
 
**SSRF 체인 분석:**
```bash
cd diagnosis
python -m ai.analyze --input scan_result.json
```
 
**XSS 체인 분석:**
```bash
cd diagnosis/ai_etc
python analyze_etc.py --input ../scan_result.json
python report_generator_etc.py
```
 
### 대시보드 실행
```bash
streamlit run dashboard/src/dashboard.py
```


## ⭐⭐⭐ 주의사항
- `.env` 파일은 절대 git에 커밋하지 않습니다!!! (OpenAI/AWS 키 노출 방지).
- AWS 실제 자격증명(IAM Access Key 등)은 커밋/로그/JSON 결과에 절대 남기지 않습니다.
- 로컬 mock IMDS와 실제 AWS IMDS(169.254.169.254) 대상 코드를 명확히 분리합니다.
- `diagnosis/`와 `web/`은 공격 도구/공격 대상 관계이므로 실제 배포 환경이 아닌
  팀이 직접 구축한 격리된 환경에서만 실행합니다.
  

## 협업 컨벤션

### 커밋 메시지 규칙

`태그: 작업 내용` 형식으로 작성합니다.

| 태그 | 설명 |
|---|---|
| `feat` | 새로운 기능 추가 |
| `fix` | 버그 수정 |
| `aws` | AWS 인프라/IAM/S3/EC2 관련 |
| `bypass` | SSRF 우회 기법 추가/수정 |
| `docs` | 문서 수정 (README, 기획서 등) |
| `chore` | 설정, 패키지 설치 등 자잘한 작업 |
| `refactor` | 기능 변화 없는 코드 정리 |
| `test` | 테스트 코드 관련 |

**예시**
```
feat: stage7 stored XSS 진단 도구 추가
aws: IMDS 임시 자격증명 탈취 로직 추가
fix: 대시보드 결과 JSON 파싱 오류 수정
```

### 브랜치 전략

- `main` : 항상 동작하는 상태만 유지
- `web` : 웹/AWS 팀 작업 브랜치
- `diagnosis` : 진단 도구 팀 작업 브랜치
- `dashboard` : 대시보드 팀 작업 브랜치
  
```bash
git checkout -b web
git checkout -b diagnosis
git checkout -b dashboard
```

### EC2 배포 (코드 업데이트 시)
```bash
ssh -i yuk-keypair.pem ubuntu@<EC2_IP>
cd rookies33-module-project2
git pull origin main
kill $(lsof -t -i:5000)
nohup python3 web/app.py > server.log 2>&1 &
```

자기 브랜치에서 작업 후 `main`으로 merge하여 통합 테스트합니다.

### 작업 전후 습관

```bash
# 작업 시작 전 최신 상태로 동기화
git pull origin main

# 작업 후
git add .
git commit -m "feat: 작업 내용"
git push origin 브랜치명
```

### 코드 스타일

- 함수/변수명: `snake_case`
- 우회 기법 함수는 역할이 드러나는 이름 사용 (예: `bypass_decimal_ip`)
- 커밋 전 `.env` 및 AWS 자격증명 파일이 스테이징에 포함되지 않았는지 `git status`로 확인
