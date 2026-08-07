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
python main.py <prowler-output.ocsf.json>
```

동봉된 샘플로 확인:

```bash
python main.py sample-findings.ocsf.json
```

`sample-findings.ocsf.json` 은 더미 계정(`123456789012`)과 더미 버킷명으로 되어 있다.
그대로 실행하면 파이프라인은 끝까지 돌지만 **전부 `account_mismatch`** 로 나온다
(계정 대조가 작동한다는 확인은 된다). 실제 대조까지 보려면 `cloud.account.uid` 와
`resources[0].uid` 를 본인 계정·버킷으로 바꾸거나, Prowler 를 직접 돌려 나온
findings 를 넣으면 된다.

실행하면 `logs/actions-<타임스탬프>.json` 이 생기고, 콘솔에는 status 별 건수가 요약된다.

```
[1/4] findings 파싱: sample-findings.ocsf.json
      전체 finding 7건
      FAIL 6건 추출
[2/4] 매핑 로드: .../mapping.yml
      매핑 항목 4건
      실행 대상 4건 / 제외 2건
[3/4] Custodian dryrun 실행: 정책 3개
  - s3-no-secure-transport (finding 2건)
      실행: custodian run -s .../out .../policies/s3-no-secure-transport.yml --dryrun
      dryrun 대상 리소스 2건 / ARN 확보 2건
  ...
[4/4] 조치 로그 저장: .../logs/actions-20260805-151011.json

=== 요약 ===
  dryrun_matched               1건
  dryrun_not_matched           1건
  not_fixable                  1건
  unmapped                     1건
  합계                         4건
```

### Prowler 로 findings 만들기

```bash
prowler aws --output-formats json-ocsf --services s3
```

`output/` 아래 생기는 `*.ocsf.json` 을 `main.py` 인자로 넘기면 된다.

---

## 파일 구조

```
cspm/
├── policies/                      # 정책 파일당 정책 1개 (매핑된 정책만 골라 실행하기 위함)
│   ├── s3-no-secure-transport.yml   # HTTPS 강제 정책이 없는 버킷
│   ├── s3-no-kms-encryption.yml     # SSE-KMS 기본 암호화가 없는 버킷
│   └── s3-account-public-block.yml  # 퍼블릭 액세스 차단이 완전하지 않은 버킷
├── mapping.yml                    # event_code -> 정책 이름 매핑
├── main.py                        # 파서 -> 매핑 -> 실행 -> 로그
├── sample-findings.ocsf.json      # 동작 확인용 샘플 findings
├── README.md
├── out/                           # Custodian dryrun 결과 (자동 생성)
└── logs/                          # 조치 로그 (자동 생성)
```

### 정책 파일

**모든 정책은 필터만 있고 actions 블록이 없다.** dryrun 으로 "걸리는 리소스"만
확인하는 단계이며, 실제 조치는 이 프로토타입의 범위가 아니다.

문법은 아래 명령으로 확인했고, 3개 모두 `custodian validate` 를 통과한다.

```bash
custodian schema aws.s3.filters.bucket-encryption
custodian schema aws.s3.filters.check-public-block
```

---

## 처리 흐름

| 단계 | 티켓 | 하는 일 |
|---|---|---|
| 파서 | #1 | OCSF JSON 을 읽어 `status_code == "FAIL"` 만 남기고 필요한 필드 추출 |
| 매핑 조회 | #2 | `check_id`(= `metadata.event_code`)로 `mapping.yml` 조회 |
| 실행기 | #6 | 정책당 1회 `custodian run --dryrun`, 결과와 finding 대조 |
| 로그 | #7 | `logs/actions-<타임스탬프>.json` 저장 + 콘솔 요약 |

### 파서가 추출하는 필드

| 키 | OCSF 경로 |
|---|---|
| finding_uid | `finding_info.uid` |
| check_id | `metadata.event_code` |
| severity | `severity` |
| status_code | `status_code` |
| resource_uid | `resources[0].uid` |
| resource_type | `resources[0].type` |
| service | `resources[0].group.name` |
| region | `resources[0].region` |
| account_uid | `cloud.account.uid` |
| scan_time | `time_dt` |

없는 필드는 `None` 으로 두고 경고를 출력한다. 파싱 실패로 중단하지 않는다.

### 실행기가 정책당 1회만 도는 이유

같은 정책에 걸린 findings 를 묶어서 Custodian 을 **정책당 1회만** 실행한다.
Custodian 은 finding 을 입력으로 받지 않고 AWS 전체를 조회하므로, finding 마다
실행하면 완전히 같은 조회를 반복하게 된다.

실행 후 `out/<정책이름>/resources.json` 을 읽어, finding 의 `resource_uid` 와
일치하는 리소스가 있는지 대조한다. 리소스에서 ARN 을 찾을 때는
`BucketArn` → `Arn` → `arn` 순으로 시도한다 (S3 버킷은 `BucketArn` 을 쓴다).

### 계정 대조

조회 대상 계정은 **findings 파일이 아니라 실행자의 자격증명**이 결정한다.
Custodian 은 boto3 기본 자격증명 체인(`~/.aws/credentials` 기본 프로필 →
환경변수 → 인스턴스 역할)을 그대로 따르며, findings 파일은 "어떤 정책을 돌릴지"만 정한다.

그래서 ARN 대조에 앞서 계정부터 맞춰본다. Custodian 이 `out/<정책이름>/metadata.json` 의
`config.account_id` 에 자신이 조회한 계정을 남기므로, 이걸 finding 의 `account_uid` 와
비교한다 (추가 의존성 없음).

다르면 `account_mismatch` 로 기록하고 대조를 생략한다. 이 확인이 없으면 A 계정 findings 를
B 계정 자격증명으로 실행했을 때 **에러 없이 전부 `dryrun_not_matched`** 가 되어
"이미 조치됨"으로 오독된다.

`metadata.json` 에서 계정을 확인하지 못하면 경고를 출력하고 대조는 건너뛴다.

---

## status 값의 의미

| status | 의미 | 실행 여부 |
|---|---|---|
| `dryrun_matched` | 정책 dryrun 결과에 finding 의 리소스가 **있다**. Prowler 탐지와 Custodian 판정이 일치한다 — 조치 대상으로 확정 | 실행함 |
| `dryrun_not_matched` | dryrun 결과에 해당 리소스가 **없다**. 두 도구의 판정 기준 차이이거나, 스캔 이후 이미 조치된 경우 | 실행함 |
| `unmapped` | `mapping.yml` 에 해당 `check_id` 항목이 없다. 매핑을 추가해야 처리된다 | 실행 안 함 |
| `not_supported` | 조치 도구 자체가 없다 (`mode: not_supported`). 예: MFA Delete 는 루트 자격증명 필요 | 실행 안 함 |
| `manual_required` | 도구는 있지만 조치가 위험해 사람이 처리해야 한다 (`mode: manual`) | 실행 안 함 |
| `approval_pending` | 승인이 필요한 조치 (`mode: approve`). 승인 흐름 구현 전까지는 기록만 한다 | 실행 안 함 |
| `failed` | Custodian 실행이 실패했거나 결과 파일을 읽지 못했다. `reason` 에 에러 메시지가 담긴다. **한 정책이 실패해도 나머지 정책은 계속 진행한다** | 시도함 |
| `arn_not_found` | dryrun 결과에서 ARN 필드를 찾지 못했거나, finding 에 `resource_uid` 가 없어 대조할 수 없다 | 실행함 |
| `account_mismatch` | finding 의 `account_uid` 와 Custodian 이 실제로 조회한 계정이 다르다. 다른 계정 자격증명으로 실행한 경우이며, 대조를 생략한다 | 실행함 |

`dryrun_not_matched` 와 `arn_not_found` 는 "안전하다"는 뜻이 아니라 **"판정 불가"** 에
가깝다. 건수가 많으면 매핑이나 정책 필터를 다시 봐야 한다.

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
    "status": "dryrun_matched",
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

새 Prowler 체크를 붙이려면 `mapping.yml` 에 항목을 추가하고, `policy` 이름과
같은 이름의 파일을 `policies/` 에 만든다.

```yaml
<prowler 의 metadata.event_code>:
  policy: <policies/ 아래 정책 이름>   # 조치 도구가 없으면 null
  remediation:
    mode: auto                 # auto / approve / manual / not_supported
    disruption: none           # none / restart / recreate / traffic / access / destructive
    blast_radius: resource     # resource / account
    propagation_delay: immediate
    reversible: true
    cost_impact: none          # none / low / high
    risk_note: "자동 조치라도 남아 있는 위험"
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
