# CSPM 자동 대응 프로토타입

Prowler(탐지)와 Cloud Custodian(조치)을 잇는 파이프라인.

Prowler 가 findings 를 뱉으면, 해당 체크에 대응하는 Custodian 정책을 찾아
dryrun 으로 실행하고 결과를 조치 로그로 남긴다.

Custodian 은 findings 를 입력으로 받지 않고 AWS 를 직접 조회하는 도구다.
따라서 두 도구의 연결점은 **`Prowler 의 metadata.event_code` ↔ `Custodian 정책 이름`**
매핑(`mapping.yml`)뿐이다.

---

## 실행 방법

### 준비물

- Python 3 + PyYAML
- Cloud Custodian (`custodian` 이 PATH 에 있어야 한다)
- AWS 자격증명 (Custodian 이 실제로 AWS 를 조회한다)

```bash
pip install pyyaml c7n
```

### 실행

```bash
python -m response <prowler-output.ocsf.json>
```

동봉된 샘플로 확인:

```bash
python -m response sample-findings.ocsf.json
```

**라이브러리로 부를 수도 있다.** 통합 파이프라인에서 findings 를 파일이 아니라
DB·API 로 받는 경우를 위해 진입점을 둘로 나눠 두었다.

```python
from response import run, run_raw

records = run(findings)          # 이미 파싱된 dict 리스트
records = run_raw(raw_findings)  # OCSF 원본 리스트
```

`run()` 은 파일을 읽지도 로그를 저장하지도 않는다. 결과 레코드만 돌려주므로
입력과 출력을 호출부가 정할 수 있다.

**산출물 위치**는 실행한 디렉토리 기준이다. `CSPM_WORK_DIR` 로 바꿀 수 있다.

```bash
CSPM_WORK_DIR=/tmp/cspm python -m response findings.json   # /tmp/cspm/out, /tmp/cspm/logs
```

### 조치 대상 범위 설정

실행 전에 **어느 계정·리전을 대상으로 할지** 정해야 한다. 범위 밖 finding 은
`out_of_scope` 로 기록되고 처리되지 않는다.

```bash
cp response/scope.example.yml response/scope.yml    # 실제 계정을 여기에
```

`scope.yml` 은 **git 에서 제외된다.** 환경변수를 쓰면 파일 없이도 된다.

```bash
export CSPM_SCOPE_ACCOUNTS=123456789012,210987654321
export CSPM_SCOPE_REGIONS=ap-northeast-2
```

우선순위는 **환경변수 > `scope.yml` > `scope.example.yml`** 이고,
어느 출처를 썼는지 실행할 때 콘솔에 표시된다.

### 승인 프롬프트

`mode: approve` 인 체크는 dryrun 으로 대상을 확인한 뒤 물어본다.

```
  ── 승인 요청: s3-account-public-block ──
     · arn:aws:s3:::example-bucket
     주의: 정적 웹사이트 호스팅 버킷이 있으면 사이트가 내려간다
  1건을 조치하시겠습니까? (y/N)
```

파이프·CI 처럼 **비대화형이면 묻지 않고** `approval_pending` 으로 남긴다.
일괄 처리하려면 플래그를 쓴다.

```bash
python -m response --yes findings.json    # 전부 승인
python -m response --no  findings.json    # 전부 거부 (조치 방법 출력)
```

### 실행 결과

`sample-findings.ocsf.json` 은 더미 계정(`123456789012`)으로 되어 있다.
`scope.yml` 의 계정이 다르면 **전부 `out_of_scope`** 로 나온다.
실제 판정까지 보려면 계정을 맞추거나 Prowler 를 직접 돌려 나온 findings 를 넣는다.

```
[1/4] findings 파싱: sample-findings.ocsf.json
      전체 finding 7건
      FAIL 6건 추출
      범위 [scope.yml] 계정 123456789012 / 리전 ap-northeast-2
[2/4] 매핑 로드: .../mapping.yml
      매핑 항목 5건
      [주의] s3_bucket_kms_encryption: 신규 객체만 영향. KMS 요청 비용이 발생한다
      실행 대상 4건 / 제외 2건
[3/4] Custodian dryrun 실행: 정책 3개
  - s3-no-secure-transport (finding 2건)
      대상 2건으로 범위 제한 (Name)
      dryrun 대상 리소스 2건 / ARN 확보 2건
      조회 계정 123456789012
  ...
[4/4] 조치 로그 저장: .../logs/actions-20260812-093049.json

=== 요약 ===
  still_open                2건
  approval_pending          1건
  not_supported             1건
  unmapped                  1건
  합계                      5건
```

### Prowler 로 findings 만들기

```bash
prowler aws --output-formats json-ocsf --services s3
```

`output/` 아래 생기는 `*.ocsf.json` 을 인자로 넘기면 된다.

---

## 파일 구조

```
cspm/
├── response/                      # 통합 시 이 폴더를 통째로 옮긴다
│   ├── __init__.py                #   run · run_raw 를 공개
│   ├── __main__.py                #   python -m response 진입
│   ├── run.py                     #   파이프라인 조립 + CLI
│   ├── config.py                  #   경로·상수
│   ├── findings.py                #   #2 파싱 (입력 구조에 의존하는 유일한 곳)
│   ├── scope.py                   #   #1 조치 대상 범위 필터
│   ├── mapping.py                 #   #3 매핑 조회 + mode 판정
│   ├── scoping.py                 #   #4 실행 범위 제한 (실조치 안전장치)
│   ├── executor.py                #   #5·6 Custodian 실행 + 대조
│   ├── approval.py                #   #7 승인 프롬프트
│   ├── reporter.py                #   #8 조치 로그
│   ├── mapping.yml                #   event_code -> 정책 이름 매핑
│   ├── scope.example.yml          #   대상 계정·리전 예시 (실제 값은 scope.yml)
│   └── policies/                  #   서비스별로 한 파일
│       └── s3.yml                 #     S3 정책 3종
├── sample-findings.ocsf.json      # 동작 확인용 샘플 findings
├── README.md
├── out/                           # Custodian dryrun 결과 (자동 생성)
└── logs/                          # 조치 로그 (자동 생성)
```

**설정(`mapping.yml`, `policies/`)이 패키지 안에 있는 이유** — 코드와 짝이라 함께
움직여야 한다. 떨어뜨리면 통합할 때 한쪽만 옮겨져 매핑이 깨진다.

**산출물(`out/`, `logs/`)이 패키지 밖인 이유** — 실행할 때마다 생기는 것이라
코드 디렉토리를 더럽히면 안 되고, 통합 시 오케스트레이터가 한곳에 모을 수 있어야 한다.

### 정책 파일

**서비스별로 한 파일에 모은다.** `policies/s3.yml` 에 S3 정책이 전부 들어 있다.
정책이 늘어도 파일이 흩어지지 않고, 같은 리소스 타입을 한 번에 실행할 때
조회 결과를 공유할 수 있다.

정책은 **필터(무엇이 위반인가) + 액션(어떻게 고치는가)** 로 이뤄진다.
액션이 있지만 **실행은 항상 `--dryrun` 이라 실제 변경은 일어나지 않는다.**

#### 이름 규칙 — check_id 의 언더바를 하이픈으로

```
s3_bucket_kms_encryption   (Prowler check_id)
s3-bucket-kms-encryption   (정책 이름)
```

이 규칙 덕분에 `mapping.yml` 에서 `policy` 를 **생략해도 코드가 찾아낸다.**
이름이 어긋나 매핑이 깨지는 실수가 줄어든다. 규칙과 다른 이름을 쓸 때만 명시한다.

정책 이름의 첫 조각이 곧 파일 이름이다. `s3-bucket-kms-encryption` → `policies/s3.yml`

#### metadata — 정책만 봐도 알 수 있게

Custodian 이 지원하는 정식 필드라 `validate` 를 통과하고 코드로 파싱할 수 있다.

```yaml
  - name: s3-bucket-kms-encryption
    resource: aws.s3
    description: SSE-KMS 기본 암호화가 설정되지 않은 버킷
    metadata:
      prowler_check: s3_bucket_kms_encryption      # 출처 체크
      remediation_summary: 기본 암호화를 SSE-KMS 로 활성화한다
      note: |
        판단 근거나 주의사항
```

`mapping.yml` 에 흩어져 있는 정보를 정책 옆에도 남겨, 정책 파일만 열어도
무엇을 왜 하는지 알 수 있다.

#### 액션 문법 확인

```bash
custodian schema aws.s3.actions.set-bucket-encryption
custodian schema aws.s3.actions.set-statements
custodian schema aws.s3.actions.set-public-block
custodian validate response/policies/s3.yml
```

`set-statements` 에서 `remove: "*"` 를 쓰지 않는다. 기존 구문을 전부 지우면
정당한 접근 허용까지 날아가므로 Deny 구문만 얹는다.

---

## 동작 방식

한 번 실행하면 아래 순서로 돈다. **각 단계는 앞 단계의 출력만 보고 판단한다.**

```
① 범위 필터 → ② 파싱 → ③ 매핑 → ④ 범위 제한 → ⑤ 실행 → ⑥ 대조 → ⑦ 승인 → ⑧ 로그
```

### ① 범위 필터 — 우리 계정인가

| | |
|---|---|
| 입력 | 파싱된 finding 목록 |
| 출력 | 대상 계정·리전의 finding 만 |

대상이 아닌 건은 `out_of_scope` 로 기록하고 이후 단계를 건너뛴다.
설정은 **환경변수 → `scope.yml` → `scope.example.yml`** 순으로 읽는다.

```
      범위 [scope.yml] 계정 123456789012 / 리전 ap-northeast-2
      범위 밖 2건 제외
```

계정 ID 는 코드에 하드코딩하지 않는다. 실제 값이 든 `scope.yml` 은 git 에서 제외되고,
저장소에는 더미가 든 `scope.example.yml` 만 올라간다.

### ② 파싱 — 무엇을 꺼내는가

| | |
|---|---|
| 입력 | Prowler JSON-OCSF |
| 출력 | 평평한 dict 리스트 |

`status_code == "FAIL"` 인 건만 남기고 12개 필드를 뽑는다.
**입력 구조에 의존하는 곳은 여기뿐**이라, 스캔 파트의 형식이 바뀌면
`FIELD_PATHS` 만 갈아끼우면 된다.

| 내부 키 | OCSF 경로 |
|---|---|
| `check_id` | `metadata.event_code` |
| `resource_uid` | `resources[0].uid` |
| `account_uid` | `cloud.account.uid` |
| `finding_uid` | `finding_info.uid` |
| `severity` · `region` · `resource_type` · `service` · `scan_time` | 각 대응 경로 |
| `remediation_desc` · `remediation_refs` | `remediation.desc` · `remediation.references` |

없는 필드는 `None` 으로 두고 경고를 출력한다. 파싱 실패로 중단하지 않는다.
`remediation_*` 은 선택 필드라 없어도 경고하지 않는다.

### ③ 매핑 — 어떻게 조치할 것인가

| | |
|---|---|
| 입력 | `check_id` |
| 출력 | 정책 이름 + 조치 방식(`mode`) |

`mapping.yml` 을 조회해 `mode` 를 확정한다. **`auto` 와 `approve` 만 다음 단계로
넘어가고**, 나머지는 여기서 상태가 확정된다.

```
auto            → 실행
approve         → 실행 후 사람에게 확인
manual          → 실행 안 함. reason 에 조치 안내
not_supported   → 실행 안 함. reason 에 불가 사유
매핑에 없음      → unmapped
```

### ④ 범위 제한 — 대상 리소스만 남긴다

| | |
|---|---|
| 입력 | 정책 이름 + 대상 finding 묶음 |
| 출력 | `out/_scoped/<정책>.yml` (정책 하나만 담긴 문서) |

**Custodian 은 정책을 계정 전체에 대해 돌린다.** 원본 정책을 그대로 실행하면
findings 에 없는 리소스까지 대상이 된다. dryrun 이면 무해하지만 실조치를 켜는 순간
**의도하지 않은 리소스까지 고치게 된다.**

그래서 실행 전에 대상 리소스 이름을 필터로 얹은 임시 정책을 만든다.

```yaml
filters:
  - type: value          # <- 자동으로 맨 앞에 끼워 넣는다
    key: Name
    op: in
    value: [example-bucket]
  - not:
    - type: bucket-encryption
      ...
```

- 어떤 필드로 좁힐지는 `mapping.yml` 의 `scope_key` 로 정한다 (S3 는 `Name`,
  EC2 는 `InstanceId`). ARN 의 마지막 조각과 대조한다.
- `blast_radius: account` 인 체크는 **범위 제한을 하지 않는다.** 계정 설정 하나를
  보는 것이라 리소스 필터를 얹으면 판정이 어긋난다.
- `scope_key` 가 없으면 경고를 출력하고 계정 전체를 대상으로 돈다.
  **실조치 단계에서는 반드시 지정해야 한다.**

### ⑤ 실행 — 정책당 1회

| | |
|---|---|
| 입력 | 범위를 좁힌 정책 |
| 출력 | `out/<정책>/resources.json` |

같은 정책에 걸린 findings 를 묶어 **정책당 1회만** 실행한다. Custodian 은 finding 을
입력으로 받지 않고 AWS 전체를 조회하므로, finding 마다 실행하면 완전히 같은 조회를
반복하게 된다. findings 100건이 같은 체크면 실행은 1회다.

```bash
custodian run -s out out/_scoped/s3-no-kms-encryption.yml --dryrun
```

**`--dryrun` 은 항상 붙는다.** 정책에 `actions` 가 있지만 실제 변경은 일어나지 않고
"무엇을 할 계획인지"만 출력된다. 실조치를 켜려면 `run_custodian(dry_run=False)` 로
바꾸면 되지만, 조치 전 스냅샷과 롤백이 붙기 전에는 켜지 않는다.

한 정책이 실패해도 **나머지 정책은 계속 진행한다.** 실패한 묶음만 `failed` 가 된다.

### ⑥ 대조 — 의도한 대상이 걸렸는가

| | |
|---|---|
| 입력 | 실행 결과 + finding 묶음 |
| 출력 | finding 별 status |

**Prowler 스캔은 과거 시점의 사진이고, Custodian 실행은 지금 이 순간의 상태다.**
그래서 조치 직전에 "지금도 그런가"를 다시 확인한다.

범위 제한을 먼저 하므로 이 단계는 **"의도한 대상이 제대로 걸렸는지" 검증**이다.
범위 제한이 없던 시절에는 "어느 게 내 대상인가"를 고르는 역할이었다.

판정 순서 — 앞의 조건이 걸리면 뒤는 보지 않는다.

```
1. 계정이 다름              → account_mismatch
2. 계정 단위 체크            → 리소스 유무로 판정
3. ARN 을 못 뽑음           → arn_not_found
4. finding 의 ARN 이 결과에 있음 → still_open (조치 대상 확정)
5. 없음                     → already_fixed
```

**1번이 맨 앞인 이유** — 조회 대상 계정은 findings 가 아니라 **실행자의 자격증명**이
정한다. 계정이 다르면 ARN 이 안 맞는 게 당연한데 그걸 `already_fixed` 로 남기면
"이미 조치됨"으로 오독된다. Custodian 이 `out/<정책>/metadata.json` 에 남기는
`config.account_id` 를 finding 의 `account_uid` 와 비교한다.

①의 범위 필터와 역할이 다르다. **①은 사전 차단, ⑥은 자격증명이 잘못됐을 때의 안전망**이다.

리소스에서 ARN 을 찾을 때는 `BucketArn` → `Arn` → `arn` 순으로 시도한다.

### ⑦ 승인 — 사람에게 묻는다

| | |
|---|---|
| 입력 | `mode: approve` 이면서 `still_open` 인 건 |
| 출력 | `approved` / `declined` / `approval_pending` |

**dryrun 을 먼저 돌린 뒤에 묻는다.** 무엇을 고칠지 보여줘야 판단할 수 있기 때문이다.

```
  ── 승인 요청: s3-account-public-block ──
     · arn:aws:s3:::example-bucket
     주의: 정적 웹사이트 호스팅 버킷이 있으면 사이트가 내려간다
  1건을 조치하시겠습니까? (y/N)
```

- **y** → `approved`. 지금은 dryrun 이라 실제 변경은 없다.
- **n** → `declined`. 조치 방법과 참고 링크를 출력한다.
- **비대화형** (파이프·CI) → 묻지 않고 `approval_pending` 으로 남긴다.
  자동 실행 중에 입력을 기다리며 멈추면 안 되기 때문이다.

`--yes` · `--no` 플래그로 일괄 처리할 수 있다.

### ⑧ 로그 — 결과 기록

| | |
|---|---|
| 입력 | 모든 finding (제외된 건 포함) |
| 출력 | `logs/actions-<타임스탬프>.json` + 콘솔 요약 |

①~⑦ 에서 걸러진 건까지 **전부** 기록한다. "왜 조치하지 않았는지"가 남아야
다음 파트가 집계할 수 있다.


## status 값의 의미

| status | 의미 | 실행 여부 |
|---|---|---|
| `still_open` | **지금도 위반 상태다.** Prowler 스캔 시점의 문제가 아직 남아 있다 — 조치 대상으로 확정 | 실행함 |
| `already_fixed` | **더 이상 위반이 아니다.** 스캔 이후 해소됐거나, 두 도구의 판정 기준이 다르거나, 리소스가 삭제된 경우 | 실행함 |
| `out_of_scope` | 조치 대상 계정·리전이 아니다. 범위 설정(`scope.yml`)에서 걸렀다 | 실행 안 함 |
| `unmapped` | `mapping.yml` 에 해당 `check_id` 항목이 없다. 매핑을 추가해야 처리된다 | 실행 안 함 |
| `not_supported` | 조치 도구 자체가 없다 (`mode: not_supported`). 예: MFA Delete 는 루트 자격증명 필요 | 실행 안 함 |
| `manual_required` | 도구는 있지만 조치가 위험해 사람이 처리해야 한다 (`mode: manual`) | 실행 안 함 |
| `approved` | 승인자가 조치를 승인했다. **dryrun 이라 실제 변경은 아직 없다** | 실행함 |
| `declined` | 승인자가 거부했다. `reason` 에 조치 방법이 담긴다 | 실행함 |
| `approval_pending` | 승인이 필요한데 물을 수 없었다 (비대화형 실행) | 실행함 |
| `failed` | Custodian 실행이 실패했거나 결과 파일을 읽지 못했다. `reason` 에 에러 메시지가 담긴다. **한 정책이 실패해도 나머지 정책은 계속 진행한다** | 시도함 |
| `arn_not_found` | dryrun 결과에서 ARN 필드를 찾지 못했거나, finding 에 `resource_uid` 가 없어 대조할 수 없다 | 실행함 |
| `account_mismatch` | finding 의 `account_uid` 와 Custodian 이 실제로 조회한 계정이 다르다. 다른 계정 자격증명으로 실행한 경우이며, 대조를 생략한다 | 실행함 |

**Prowler 스캔은 과거 시점의 사진이고, Custodian 실행은 지금 이 순간의 상태다.**
그래서 고치기 직전에 "지금도 그런가"를 다시 확인한다. `still_open` 만 실제 조치 대상이다.

다만 `already_fixed` 는 원인이 셋(이미 해소 / 판정 기준 차이 / 리소스 삭제)인데
코드가 구분하지 못한다. **"안전하다"가 아니라 "더 볼 필요가 있다"에 가깝다.**
건수가 많으면 매핑이나 정책 필터를 다시 봐야 한다. `arn_not_found` 도 마찬가지다.

### 조치 로그 형식

```json
[
  {
    "finding_uid": "prowler-s3_bucket_secure_transport_policy-...",
    "check_id": "s3_bucket_secure_transport_policy",
    "resource_uid": "arn:aws:s3:::example-app-bucket",
    "account_uid": "123456789012",
    "region": "ap-northeast-2",
    "severity": "Medium",
    "policy_name": "s3-no-secure-transport",
    "status": "still_open",
    "reason": null,
    "mode": "auto",
    "disruption": "none",
    "blast_radius": "resource",
    "propagation_delay": "immediate",
    "risk_note": "HTTP 로만 접근하던 클라이언트가 있으면 차단된다",
    "executed_at": "2026-08-05T14:30:00"
  }
]
```

---

## 조치 위험도 (remediation)

**severity 와 disruption 은 다른 축이다.** severity 는 "문제가 얼마나 심각한가",
disruption 은 "고치는 행위가 얼마나 위험한가"다. RDS 암호화는 severity 가 높지만
조치하려면 DB 를 재생성해야 해서 자동으로 돌릴 수 없다.

그래서 **mode 는 disruption 이 결정한다. severity 는 mode 에 관여하지 않는다.**
(severity 는 처리 우선순위와 승인 기한에만 쓴다.)

### disruption

| 값 | 의미 | 예시 |
|---|---|---|
| `none` | 설정 변경만, 재시작·재생성 없음 | S3 암호화, 퍼블릭 차단, IMDSv2 |
| `restart` | 리소스 재시작 필요 | 일부 파라미터 그룹 변경 |
| `recreate` | 리소스 재생성 필요 (사실상 중단) | RDS 암호화, EBS 암호화 |
| `traffic` | 네트워크 경로 변경, 정당한 트래픽까지 영향 | 보안그룹·NACL 규칙 제거 |
| `access` | 권한 변경, 앱 동작 영향 | IAM 정책 축소 |
| `destructive` | 되돌릴 수 없는 파기 | 노출된 액세스 키 삭제 |

### mode 결정 규칙

| disruption | mode |
|---|---|
| `none` | `auto` — 바로 dryrun 실행 |
| `restart` / `traffic` | `approve` — 승인 큐 (구현 전까지는 기록만) |
| `recreate` / `access` / `destructive` | `manual` — 사람이 직접 처리 |

조치 도구 자체가 없으면 disruption 과 무관하게 `not_supported` 다.

### blast_radius

`resource` / `account` 두 값이며, **판정 방식이 달라진다.**

- `resource`: finding 의 `resource_uid` 와 dryrun 결과의 ARN 을 대조한다.
- `account`: 계정 설정 하나를 보는 체크이므로 ARN 대조를 하지 않는다. 정책에 걸린
  리소스가 하나라도 있으면 "계정에 문제가 있다"로 판정한다.

계정 단위 체크에 리소스 단위로 대조하면 판정 단위가 어긋난다
(`s3_account_level_public_access_blocks` 가 그 사례다).

### propagation_delay

`immediate` / `seconds` / `minutes`. 조치 후 반영까지 걸리는 시간이다.
IAM 변경은 수십 초, CloudFront 는 수 분 걸려서, 조치 직후 재확인하면 아직 반영되지
않아 "실패"로 오판한다. **지금은 로그에 기록만 하고, 조치 후 재확인 기능이 붙을 때
대기 시간으로 쓴다.**

---

## 매핑 추가하기

새 Prowler 체크를 붙이려면 `mapping.yml` 에 항목을 추가하고,
해당 서비스 파일(`policies/<서비스>.yml`)에 정책을 넣는다.

```yaml
<prowler 의 metadata.event_code>:
  # policy 는 생략한다 - check_id 의 언더바를 하이픈으로 바꾼 이름을 자동으로 쓴다.
  # 조치 도구가 없을 때만 policy: null 을 명시한다
  remediation:
    mode: auto                 # auto / approve / manual / not_supported
    disruption: none           # none / restart / recreate / traffic / access / destructive
    blast_radius: resource     # resource / account
    propagation_delay: immediate
    reversible: true
    cost_impact: none          # none / low / high
    risk_note: "자동 조치라도 남아 있는 위험"
    scope_key: Name            # 범위 제한에 쓸 리소스 필드 (S3=Name, EC2=InstanceId)
```

- `remediation` 이 없거나 키가 빠지면 **`mode: manual`, `disruption: recreate`** 로
  간주한다. 모르는 조치는 위험하다고 보는 쪽이 안전하다.
- 조치 불가 항목도 `mode: not_supported` 로 **명시적으로** 남긴다. 매핑에 아예 없으면
  `unmapped` 가 되어 "아직 검토 안 한 체크"와 구분되지 않는다.
- `risk_note` 가 있으면 실행 전에 콘솔에 `[주의]` 로 출력되고 로그에도 남는다.

---

## 이번 범위 밖

| 티켓 | 내용 | 상태 |
|---|---|---|
| #4 | 범위 필터 (계정·환경 태그로 대상 판정) | 환경 태그 규약 확정 후 |
| #5 | 분기 로직 (severity + 조치 가능 여부 → auto/manual) | severity 임계값 합의 후 |

지금은 **모든 findings 를 동일하게 처리한다.**

나중에 붙을 것: 예외 태그 처리, 소유자 알림, 조치 후 확인, 승인 기한.
끼워넣기 쉽도록 `main.py` 는 파서 / 매핑 / 실행 / 로그를 함수 단위로 분리해 두었다.

- #4 범위 필터 → `main()` 의 파싱과 매핑 사이에 finding 리스트를 거르는 함수 하나
- #5 분기 로직 → `resolve_policy()` 뒤에 severity 를 보고 status 를 정하는 함수 하나
- 알림·승인 → `write_log()` 옆에 로그 레코드를 소비하는 함수로

### 하지 않는 것

- 실제 조치(actions) 실행 — **dryrun 만 한다**
- 이벤트 모드 / Lambda 배포
- 예외 태그, 알림, 승인 기한

---
