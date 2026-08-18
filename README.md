# CSPM 자동 대응 프로토타입

Prowler(탐지)와 Cloud Custodian(조치)을 잇는 파이프라인.

Prowler 가 findings 를 뱉으면, 해당 체크에 대응하는 Custodian 정책을 찾아
dryrun 으로 실행하고, 사람의 승인을 받아 조치한다. Custodian 으로 다룰 수 없는
건은 사람이 직접 처리할 수 있도록 CLI 명령과 콘솔 절차를 안내한다.

Custodian 은 findings 를 입력으로 받지 않고 AWS 를 직접 조회하는 도구다.
따라서 두 도구의 연결점은 **`Prowler 의 metadata.event_code` ↔ `Custodian 정책 이름`**
매핑(`mapping.yml`)뿐이다.

**실행이 두 단계로 나뉜다.** 승인이 비동기이기 때문이다 — CLI 는 그 자리에서
물어보지만 웹은 실행이 끝난 뒤 사람이 나중에 누른다.

```
Phase 1  run()        무엇을 조치해야 하는지 판정한다. 조치는 하지 않는다
Phase 2  remediate()  승인된 건만 받아 다시 검증하고 조치한다
```

**실제 조치는 아직 나가지 않는다.** 정책에 `actions` 가 있지만 실행은 항상
`--dryrun` 이고, Phase 2 도 `apply=False` 가 기본이다.

---

## 실행 방법

### 준비물

- Python 3 + PyYAML
- Cloud Custodian (`custodian` 이 PATH 에 있어야 한다)
- AWS 자격증명 (Custodian 이 실제로 AWS 를 조회한다)

```bash
pip install pyyaml c7n
```

### Phase 1 — 판정

```bash
python -m response <prowler-output.ocsf.json>
```

동봉된 샘플로 확인:

```bash
python -m response sample-findings.ocsf.json
```

**대화형이면 `approve` 건마다 물어보고**, 파이프·CI 처럼 비대화형이면 묻지 않고
`approval_pending` 으로 남긴다. 웹 연동은 이 비대화형 경로를 쓴다.

```bash
python -m response findings.json < /dev/null    # 묻지 않고 승인 대기로
python -m response --yes findings.json          # 전부 승인
python -m response --no  findings.json          # 전부 거부
```

### Phase 2 — 승인된 건 조치

**CLI** — Phase 1 에서 승인한 건을 그 자리에서 조치한다. 랩 검증용 경로다.

```bash
python -m response --apply <findings.json>
```

`--apply` 는 **AWS 리소스를 실제로 바꾼다.** 승인한 건에만 나가고, 실행 직전에
`apply` 를 그대로 입력받는 확인을 한 번 더 거친다. 비대화형이면 실행하지 않는다 —
`--yes --apply` 로 확인 없이 전부 나가는 것을 막기 위해서다.

되돌리는 것은 자동화되어 있지 않다. 조치 직후 로그의 `rollback_cli` 에 명령이 남는다.

**라이브러리** — 웹이나 오케스트레이터가 승인 목록을 넘긴다.

```python
from response import run, remediate

records = run(findings)                     # Phase 1
pending = [r for r in records if r["status"] == "approval_pending"]

# ... 사람이 웹에서 승인하고 approved_at 을 붙여서 돌려준다 ...

results = remediate(approvals)              # Phase 2 (재검증만)
results = remediate(approvals, apply=True)  # 실조치까지
```

입력은 **`check_id` · `resource_uid` · `account_uid`** 만 있으면 된다. 정책·위험도·범위는
조치 시점에 다시 읽는다. 승인 이후 매핑이나 정책이 바뀌었을 수 있기 때문이다.

**`approved_at` 을 함께 보내야 한다.** 없으면 승인 만료 검사가 통과된다.

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

**산출물 위치**는 실행한 디렉토리 기준이다. `CSPM_WORK_DIR` 로 바꿀 수 있다.

```bash
CSPM_WORK_DIR=/tmp/cspm python -m response findings.json   # /tmp/cspm/out, /tmp/cspm/logs
```

### 승인 프롬프트 (CLI)

dryrun 으로 대상을 확인한 뒤 **리소스마다** 물어본다.

```
  ──────────────────────────────────────────────────────────────────
  승인 요청  ·  s3_bucket_kms_encryption  (Medium)
  ──────────────────────────────────────────────────────────────────
  조치   set-bucket-encryption(crypto=aws:kms, key=alias/aws/s3)
  주의   SSE-KMS 기본 암호화 적용 후 새로 저장되는 객체는 KMS 권한이 필요할 수 있으며 …
  영향   중단=access · 범위=resource

  대상 2건 - 건별로 확인합니다

  [1/2] arn:aws:s3:::example-app-bucket  [ap-northeast-2]
          조치할까요? (y/n, a=나머지 모두 승인, q=나머지 모두 거부)
```

**건별로 묻는 이유** — 같은 체크에 걸렸어도 리소스마다 사정이 다르다. 한 버킷은
고쳐도 되지만 다른 버킷은 정적 웹사이트를 호스팅 중일 수 있다.

`y` 승인 · `n` 거부(조치 방법 출력) · `a` 나머지 모두 승인 · `q` 나머지 모두 거부.

**정책에 걸렸지만 finding 이 없는 리소스가 있으면 경고가 함께 뜬다.**

```
  [경고] finding 이 없는 리소스 4건도 함께 조치됩니다
         · arn:aws:s3:::marketing-static-site
```

승인하면 이것들도 같이 바뀐다. 계정·리전 단위 체크에서 주로 발생한다(④ 참고).

### 실행 결과

```
[1/4] findings 파싱: output/prowler-output-…ocsf.json
      전체 finding 639건
      FAIL 384건 추출
      범위 [scope.yml] 계정 196338354352 / 리전 ap-northeast-2
[2/4] 매핑 로드: .../mapping.yml
      매핑 항목 102건
      [주의] s3_bucket_kms_encryption: SSE-KMS 기본 암호화 적용 후 …
      실행 대상 27건 / 제외 357건
[3/4] Custodian dryrun 실행: 정책 20개
      자동 실행 설정: 미연결(스텁) - 모든 조치가 승인을 거칩니다
  - s3-bucket-kms-encryption (finding 4건)
      대상 4건으로 범위 제한 (Name)
      dryrun 대상 리소스 4건 / ARN 확보 4건
      조회 계정 196338354352
[4/4] 조치 로그 저장: .../logs/actions-20260816-204927.json

=== 요약 ===
  approved                 27건
  manual_required         357건
  합계                    384건

  자동화 후보 11건 - 대시보드에서 켤 수 있습니다
```

**`자동 실행 설정` 줄을 매번 찍는다.** 아무것도 자동으로 나가지 않는다는 사실을
실행할 때마다 눈으로 확인할 수 있어야 하기 때문이다.

### Prowler 로 findings 만들기

```bash
prowler aws --output-formats json-ocsf
```

`output/` 아래 생기는 `*.ocsf.json` 을 인자로 넘기면 된다. `output/` 은 계정 ID 와
리소스 ARN 이 평문으로 남으므로 git 에서 제외된다.

---

## 파일 구조

```
cspm/
├── response/                      # 통합 시 이 폴더를 통째로 옮긴다
│   ├── __init__.py                #   run · run_raw · remediate 를 공개
│   ├── __main__.py                #   python -m response 진입
│   ├── run.py                     #   Phase 1 조립 + CLI
│   ├── remediation.py             #   Phase 2 - 승인된 건 재검증 후 조치
│   ├── config.py                  #   경로·상수
│   ├── scope.py                   #   ① 조치 대상 범위 필터
│   ├── findings.py                #   ② 파싱 (입력 구조에 의존하는 유일한 곳)
│   ├── mapping.py                 #   ③ 매핑 조회 + mode 판정
│   ├── policy_meta.py             #   정책 파일 접근 전담 + 정합성 검사
│   ├── runbook.py                 #   사람이 직접 조치할 때의 안내 조회
│   ├── scoping.py                 #   ④ 실행 범위 제한 (조치 안전장치)
│   ├── executor.py                #   ⑤⑥ Custodian 실행 + 대조
│   ├── approval.py                #   ⑦ 승인 프롬프트 (CLI)
│   ├── optin.py                   #   자동 실행 여부 조회 (DB 연결 전 스텁)
│   ├── reporter.py                #   ⑧ 조치 로그
│   ├── mapping.yml                #   판정 결과 - 어디로 보낼까 (102종)
│   ├── runbook.yml                #   수동 조치 안내 - CLI · 콘솔 절차 (83종)
│   ├── scope.example.yml          #   대상 계정·리전 예시 (실제 값은 scope.yml)
│   └── policies/                  #   서비스별로 한 파일 (정책 20개)
│       ├── s3.yml  ec2.yml  iam.yml  vpc.yml  cloudtrail.yml
├── sample-findings.ocsf.json      # 동작 확인용 샘플
├── README.md
├── output/                        # Prowler 결과 (git 제외)
├── out/                           # Custodian dryrun 결과 (자동 생성)
└── logs/                          # 조치 로그 (자동 생성)
```

**설정이 패키지 안에 있는 이유** — 코드와 짝이라 함께 움직여야 한다. 떨어뜨리면
통합할 때 한쪽만 옮겨져 매핑이 깨진다.

**산출물이 패키지 밖인 이유** — 실행할 때마다 생기는 것이라 코드 디렉토리를
더럽히면 안 되고, 통합 시 오케스트레이터가 한곳에 모을 수 있어야 한다.

### 세 설정 파일의 역할 분담

```
mapping.yml       판정에 대한 서술    왜 이 mode 인가, 왜 자동화 못 하는가
policies/*.yml    조치에 대한 서술    실행하면 무슨 일이 일어나는가
runbook.yml       사람에 대한 안내    직접 고치려면 무엇을 어떻게 하는가
```

**판정 근거는 `mapping.yml` 에 둔다.** `mode` 가 `manual` 이면 `policy` 가 null 이라
정책 파일이 아예 없고, 그러면 근거를 적을 자리가 사라진다.

### mapping.yml

```yaml
<check_id>:
  policy: <정책 이름 | null>     # 생략하면 언더바를 하이픈으로 바꾼 이름
  mode: approve | manual | not_supported
  auto_eligible: true | false    # mode=approve 일 때
  auto_reason: <문자열>          # auto_eligible=false 일 때
  scope_key: <필드명 | null>     # 계정·리전 단위면 null
  risk_note: <문자열>            # 이 mode 로 판정한 근거
  runbook: <runbook.yml 의 키>   # mode=manual 일 때
```

**`auto` 는 mode 가 아니다.** 조치 가능한 체크는 전부 `approve` 로 시작하고,
사용자가 대시보드에서 자동 실행을 켠 뒤에야 승인 없이 돈다.

**`not_supported` 는 현재 쓰지 않는다.** 담당자가 할 일이 `manual` 과 같아서
(콘솔에서 직접 고치는 것) 굳이 나누지 않았다. 코드는 두 값을 모두 받는다.

### policies/*.yml

**서비스별로 한 파일**에 모은다. 정책이 100개로 늘어도 파일은 서비스 수만큼이다.

> 실행할 때는 이 파일을 그대로 넘기지 않는다. 정책 하나만 뽑아 별도 파일로 쓴다
> (④ 참고). 파일로 묶는 이득은 **정리** 뿐이고 실행 성능과는 무관하다.

```yaml
policies:
  - name: s3-bucket-kms-encryption
    resource: aws.s3
    description: 기본 암호화가 SSE-KMS 로 설정되어 있지 않은 S3 Bucket
    metadata:
      prowler_check: s3_bucket_kms_encryption
      approve:                      # 조치를 실행하면 무슨 일이 일어나는가
        disruption: access          # none / access / traffic / recreate / destructive
        blast_radius: resource      # resource / account / region / multi-account
        propagation_delay: minutes   # 정책에만 있고 코드는 읽지 않는다
        reversible: true
        cost_impact: low            # none / low / medium / high
      auto:                         # auto_eligible=true 일 때만
        warning: …
        allowed_scopes: [resource]
        rollback_cli: …
        cooldown: 24h
        post_notification: log
    filters: …
    actions: …
```

#### 이름 규칙 — check_id 의 언더바를 하이픈으로

```
s3_bucket_kms_encryption   (Prowler check_id)
s3-bucket-kms-encryption   (정책 이름)
```

정책 이름의 첫 조각이 곧 파일 이름이다. `s3-bucket-kms-encryption` → `policies/s3.yml`

#### 실행 전 정합성 검사

정책을 손으로 쓰고 서로 리뷰하는 구조라, 코드가 세 가지를 대조해 경고한다.

```
[경고] <정책>: metadata.prowler_check 가 매핑 키와 다름
[경고] <정책>: blast_radius='org' 는 코드가 모르는 값 - 리소스 단위로 처리됨
[경고] <정책>: auto_eligible=true 인데 reversible=False - 되돌리기 어려운 조치
```

**자동화 자격을 결정하는 건 사람이다.** 코드는 **앞뒤가 안 맞는 선언만** 잡는다 —
되돌릴 수 없거나 리소스를 재생성·파기하는 조치를 승인 없이 돌리겠다는 경우.

"계정 단위라서 위험하다" 같은 판단은 하지 않는다. IAM 비밀번호 정책은 계정
단위지만 즉시 누구를 막지 않고 되돌릴 수 있어 자동화해도 된다. 기계적 조건으로
사람의 판단을 뒤집으면 경고만 쌓이고 진짜 문제가 묻힌다.

#### 액션 문법 확인

```bash
custodian schema aws.s3.actions.set-bucket-encryption
custodian validate response/policies/s3.yml
```

`set-statements` 에서 `remove: "*"` 를 쓰지 않는다. 기존 구문을 전부 지우면
정당한 접근 허용까지 날아가므로 Deny 구문만 얹는다.

### runbook.yml

Custodian 으로 조치할 수 없는 건(`mode: manual`)의 안내다. `mapping.yml` 의
`runbook` 키가 여기를 가리킨다.

```yaml
iam_root_mfa_enabled:
  method: console                 # cli_or_console / console / guide
  description: Enable **MFA** for the root user …
  command_template: null          # 복붙할 CLI. 없으면 null
  console_steps:
    - Sign in to the AWS Management Console as the root user …
    - Open the account menu and click "Security credentials"
  docs_url: https://hub.prowler.com/check/iam_root_mfa_enabled
```

Prowler 도 `remediation.desc` 로 안내를 주지만 영문 원문이고 CLI 명령이 없다.
**runbook 이 있으면 그것을 우선하고, 없으면 Prowler 안내로 넘어간다.**

파일이 없어도 실행을 막지 않는다. 안내가 빠질 뿐 판정은 그대로 된다.

---

## 동작 방식

### Phase 1 — 판정

```
① 범위 필터 → ② 파싱 → ③ 매핑 → ④ 범위 제한 → ⑤ 실행 → ⑥ 대조 → ⑦ 승인 → ⑧ 로그
```

**단위가 두 번 바뀐다.** ①②③ 은 finding 건별, ③ 끝에서 정책별로 묶이고,
④⑤⑥ 은 정책 단위, ⑦⑧ 은 다시 건별이다.

같은 체크에 걸린 finding 100건이어도 **Custodian 실행은 1회**다.

### ① 범위 필터 — 우리 계정인가

| | |
|---|---|
| 입력 | 파싱된 finding 목록 |
| 출력 | 대상 계정·리전의 finding 만 |

대상이 아닌 건은 `out_of_scope` 로 기록하고 이후 단계를 건너뛴다.
계정 ID 는 코드에 하드코딩하지 않는다. 실제 값이 든 `scope.yml` 은 git 에서 제외되고,
저장소에는 더미가 든 `scope.example.yml` 만 올라간다.

### ② 파싱 — 무엇을 꺼내는가

| | |
|---|---|
| 입력 | Prowler JSON-OCSF |
| 출력 | 평평한 dict 리스트 |

`status_code == "FAIL"` 인 건만 남기고 필드를 뽑는다.
**입력 구조에 의존하는 곳은 여기뿐**이라, 스캔 파트의 형식이 바뀌면
`FIELD_PATHS` 만 갈아끼우면 된다.

| 내부 키 | OCSF 경로 |
|---|---|
| `check_id` | `metadata.event_code` |
| `resource_uid` | `resources[0].uid` |
| `account_uid` | `cloud.account.uid` |
| `finding_uid` | `finding_info.uid` |
| `remediation_desc` · `remediation_refs` | `remediation.desc` · `remediation.references` |

없는 필드는 `None` 으로 두고 경고를 출력한다. 파싱 실패로 중단하지 않는다.

### ③ 매핑 — 어디로 보낼 것인가

| | |
|---|---|
| 입력 | `check_id` |
| 출력 | 정책 이름 + `mode` + 조치 속성 |

```
approve         → 실행 후 사람에게 확인
manual          → 실행 안 함. reason 에 조치 안내 (runbook)
not_supported   → 실행 안 함. reason 에 조치 안내
매핑에 없음      → unmapped
```

finding 에 두 가지가 붙는다. **출처가 다른 데이터라 섞지 않는다.**

```python
finding["mapping"]      # mapping.yml    - mode · scope_key · risk_note · runbook
finding["policy_meta"]  # policies/*.yml - metadata.approve · metadata.auto
```

`manual` 은 담당자가 콘솔에서 직접 고치는 것이므로 **조치 안내를 받는다.**
`runbook.yml` → Prowler 의 `remediation.desc` 순으로 찾는다.

### ④ 범위 제한 — 대상 리소스만 남긴다

| | |
|---|---|
| 입력 | 정책 이름 + 대상 finding 묶음 |
| 출력 | `out/_scoped/<정책>.yml` (정책 하나만 담긴 문서) |

**Custodian 은 목록을 받지 못한다. 조건만 받는다.**

```
못 함:      [bucket-a, bucket-b] 를 대상으로 해라
할 수 있음:  암호화 안 된 버킷을 대상으로 해라
```

그대로 실행하면 계정의 **모든** 위반 리소스가 걸린다. 그래서 우리 대상만 통과하는
조건을 맨 앞에 끼워 넣는다.

```yaml
filters:
  - type: value          # <- 자동으로 삽입
    key: Name
    op: in
    value: [example-bucket]
  - not:
    - type: bucket-encryption
      ...
```

**Custodian 은 필터에 걸린 걸 전부 조치한다. 실행 후 선별이 불가능하므로
이 단계가 유일한 방어선이다.**

- 어떤 필드로 좁힐지는 `mapping.yml` 의 `scope_key` 가 정한다 (S3 는 `Name`,
  EC2 는 `InstanceId`). ARN 의 마지막 조각과 대조한다.
- **계정·리전 단위 체크는 범위 제한을 하지 않는다.** 설정 하나를 보는 것이라
  리소스 필터를 얹으면 판정이 어긋난다. `blast_radius` 가
  `account` · `region` · `multi-account` 면 여기 해당한다.
- `scope_key` 가 없으면 경고를 출력하고 계정 전체를 대상으로 돈다.

> **알려진 한계** — 계정·리전 단위 체크는 범위 제한이 없어 `resources.json` 에
> findings 에 없는 리소스가 섞인다. 승인 화면의 경고가 유일한 방어이고, 자동
> 실행에는 그 눈이 없다.

### ⑤ 실행 — 정책당 1회

| | |
|---|---|
| 입력 | 범위를 좁힌 정책 |
| 출력 | `out/<정책>/resources.json` · `metadata.json` |

```bash
custodian run -s out out/_scoped/s3-bucket-kms-encryption.yml --dryrun
```

**`resources.json` 은 조치 결과가 아니다.** 그 정책의 필터를 통과한 리소스 목록,
즉 "위반으로 판정된 것"이다. dryrun 이라 액션은 실행되지 않았다.

한 정책이 실패해도 **나머지 정책은 계속 진행한다.** 실패한 묶음만 `failed` 가 된다.

### ⑥ 대조 — 의도한 대상이 걸렸는가

| | |
|---|---|
| 입력 | 실행 결과 + finding 묶음 |
| 출력 | finding 별 status |

**Prowler 스캔은 과거 시점의 사진이고, Custodian 실행은 지금 이 순간의 상태다.**

```
1. 계정이 다름                   → account_mismatch
2. 계정·리전 단위 체크            → 리소스 유무로 판정
3. ARN 을 못 뽑음                → arn_not_found
4. finding 의 ARN 이 결과에 있음  → still_open (조치 대상 확정)
5. 없음                          → already_fixed
```

**1번이 맨 앞인 이유** — 조회 대상 계정은 findings 가 아니라 **실행자의 자격증명**이
정한다. 계정이 다르면 ARN 이 안 맞는 게 당연한데 그걸 `already_fixed` 로 남기면
"이미 조치됨"으로 오독된다. Custodian 이 `metadata.json` 에 남기는
`config.account_id` 를 finding 의 `account_uid` 와 비교한다.

**2번은 목록으로 관리한다.** 처음에는 `account` 만 특별 취급했는데 `region` 이
추가되면서 같은 오판이 다시 생겼다. `policy_meta.ACCOUNT_SCOPED` 에 모아 두었고
새 값이 생기면 여기 추가한다. `blast_radius` 가 비어 있으면 리소스 단위로 둔다 —
모르는 것을 계정 단위로 취급하면 "리소스가 걸렸으니 문제 있음"으로 단정하게 된다.

①의 범위 필터와 역할이 다르다. **①은 사전 차단, ⑥은 자격증명이 잘못됐을 때의 안전망**이다.

### ⑦ 승인 — 사람에게 묻는다

| | |
|---|---|
| 입력 | `mode: approve` 이면서 `still_open` 인 건 |
| 출력 | `approved` / `declined` / `approval_pending` / `auto_approved` |

`still_open` 인 건만 묻는다. 이미 해소됐거나 대조가 안 된 건은 물을 이유가 없다.

**자동 실행이 켜져 있으면 묻지 않는다.** `optin.is_opted_in()` 이 판단하는데,
지금은 DB 연결 전이라 **항상 `False`** 다. 즉 모든 조치가 승인을 거친다.

비대화형이면 `approval_pending` 으로 남긴다. 자동 실행 중에 입력을 기다리며
멈추면 안 되기 때문이다. **웹 연동은 이 경로를 쓴다.**

### ⑧ 로그 — 결과 기록

| | |
|---|---|
| 입력 | 모든 finding (제외된 건 포함) |
| 출력 | `logs/actions-<타임스탬프>.json` + 콘솔 요약 |

①~⑦ 에서 걸러진 건까지 **전부** 기록한다. **레코드 수는 항상 FAIL finding 수와 같다.**

레코드 21필드는 네 곳에서 모인다.

```
finding          check_id · resource_uid · account_uid · severity · status · reason
mapping.yml      mode · risk_note · auto_eligible · auto_reason
policies/*.yml   disruption · blast_radius · reversible · cost_impact
runbook.yml      runbook (method · command_template · console_steps · docs_url)
```

**`runbook` 은 구조 그대로 담는다.** `reason` 에 문자열로도 들어가지만, 웹 화면이
CLI 복사 버튼과 콘솔 절차를 나눠 그리려면 구조가 필요하기 때문이다.

### Phase 2 — 승인된 건 조치

```
승인 목록 → 만료 검사 → 범위 필터 → 매핑 재조회 → dryrun 재실행 → 대조 → 조치
```

**승인 시점의 판정을 그대로 믿지 않는다.** 승인은 과거의 판단이고 조치는 지금
나간다. 그 사이에 누가 이미 고쳤을 수 있다.

```
[조치 1/3] 승인 건 3건 접수
      만료 1건 제외
[조치 2/3] 매핑 재조회
[조치 3/3] 조치 전 재검증: 정책 2개
  - s3-bucket-kms-encryption (승인 2건)
      dryrun 대상 리소스 0건 / ARN 확보 0건
      조치할 건이 없습니다 (전부 해소되었거나 대조 불가)
```

- **승인 만료** — 기본 24시간. `approved_at` 이 없으면 만료로 보지 않는다
- **범위 재확인** — 승인 이후 대상 계정이 바뀌었을 수 있다
- **매핑 재조회** — 승인 이후 정책이나 위험도 판정이 바뀌었을 수 있다

`apply=False` 가 기본이라 **조치 직전까지만 가고 `ready` 로 남는다.**
`apply=True` 로 부르면 범위를 한 번 더 좁혀 `still_open` 인 건만 조치한다.

## status 값

| | status |
|---|---|
| **조치 대상** | `still_open` · `approved` · `auto_approved` · `ready` |
| **조치 완료** | `remediated` |
| **조치 안 함** | `out_of_scope` · `unmapped` · `not_supported` · `manual_required` · `declined` · `approval_pending` · `expired` · `no_longer_open` · `blocked` |
| **판정 불가 · 실패** | `already_fixed` · `arn_not_found` · `account_mismatch` · `failed` · `remediation_failed` · `still_failing` · `remediation_unverified` |

**`auto_approved` 는 지금 나오지 않는다.** `optin.is_opted_in()` 이 항상 `False` 라
자동 실행이 켜지지 않기 때문이다. DB 를 연결하면 그때부터 나온다.

**조치 후 3종은 `--apply` 경로에서만 나온다.** `still_failing` 은 조치를 내보냈는데
정책이 여전히 걸리는 경우다 — 실패일 수도 있고 **반영이 아직 안 된 것일 수도 있다**
(재확인이 즉시 돌기 때문). `remediation_unverified` 는 조치는 나갔는데 재확인 자체가
실패한 경우이고, `blocked` 는 서킷브레이커가 막은 경우다.

**`already_fixed` 는 "안전하다"가 아니다.** 원인이 셋(이미 해소 / 두 도구의 판정
기준 차이 / 리소스 삭제)인데 코드가 구분하지 못한다. 조회 권한이 없어 안 보이는
경우도 여기로 떨어진다. 건수가 많으면 매핑이나 정책 필터를 다시 봐야 한다.
