"""체크-정책 매핑 조회와 조치 방식 판정 - 동작 방식 ③ (README 참고).

Custodian 은 findings 를 입력으로 받지 않고 AWS 를 직접 조회하므로,
두 도구의 유일한 연결점이 mapping.yml 이다.

mapping.yml 은 **라우팅**만 담는다. 조치가 어떤 성질인지는 정책 파일의
metadata 가 담고, 이 모듈이 둘을 묶어 finding 에 붙인다.
"""

import yaml

from .config import MAPPING_PATH
from .policy_meta import check_auto_claim, check_prowler_link, load_meta


def load_mapping(path=MAPPING_PATH):
    """mapping.yml 을 읽는다."""
    print(f"[2/4] 매핑 로드: {path}")
    with open(path, "r", encoding="utf-8") as f:
        mapping = yaml.safe_load(f) or {}
    print(f"      매핑 항목 {len(mapping)}건")
    return mapping


# 항목에 키가 빠졌을 때 쓰는 기본값.
# 모르는 조치는 "위험하다"고 보는 쪽이 안전하므로 mode 를 manual 로 둔다.
DEFAULT_ENTRY = {
    "mode": "manual",
    # 판정 근거. mode 를 그렇게 정한 이유이므로 mode 와 같은 파일에 둔다
    "risk_note": None,
    # 자동 실행 승격 자격. 모르면 자동화하지 않는 쪽이 안전하다
    "auto_eligible": False,
    "auto_reason": None,
    # 범위 제한에 쓸 Custodian 리소스 필드 (예: S3 는 Name, EC2 는 InstanceId).
    # 없으면 범위 제한 없이 계정 전체를 대상으로 돈다
    "scope_key": None,
    # 사람이 직접 조치할 때의 안내. 비워두면 Prowler 의 remediation.desc 를 쓴다
    "guide": None,
}

# Custodian 을 실제로 돌리는 mode.
#
# **auto 는 매핑에 없다.** 조치 가능한 체크는 전부 approve 로 시작하고,
# 사용자가 대시보드에서 자동 실행을 켠 뒤에야 auto 로 돈다(executor 참고).
# 사람을 거치지 않는 경로를 기본값으로 두지 않기 위해서다.
EXECUTABLE_MODES = ("approve",)

# 실행하지 않는 mode 는 여기서 status 가 확정된다
MODE_STATUS = {
    "not_supported": "not_supported",
    "manual": "manual_required",
}


def check_id_to_policy(check_id):
    """Prowler check_id 를 정책 이름으로 바꾼다.

        s3_bucket_kms_encryption  ->  s3-bucket-kms-encryption

    언더바만 하이픈으로 바꾼다. 이 규칙 덕분에 mapping.yml 에서 policy 를
    생략해도 정책을 찾을 수 있고, 이름이 어긋나 매핑이 깨지는 실수가 줄어든다.
    """
    return check_id.replace("_", "-") if check_id else None


def build_reason(finding, entry, mode):
    """조치하지 않는 건에 담을 사유를 만든다.

    어느 mode 든 **사람이 무엇을 해야 하는지**를 담는다. manual 이든
    not_supported 든 담당자가 할 일은 같기 때문이다 - 콘솔에서 직접 고치는 것.
    안내 없이 "왜 못 하는지"만 주면 받는 사람이 할 수 있는 게 없다.

    우선순위: mapping.yml 의 guide -> Prowler 의 remediation.desc
    """
    guide = entry.get("guide") or finding.get("remediation_desc")
    if guide:
        return guide
    return f"조치 방법 안내 없음 (mode={mode})"


def resolve_policy(finding, mapping):
    """finding 의 check_id 로 정책과 조치 방식을 찾는다.

    반환: (policy_name, status, reason, entry)
      - 매핑 없음            -> (None, "unmapped", ...)
      - 실행하지 않는 mode   -> (None, MODE_STATUS[mode], 사유)
      - 정상                 -> (정책이름, None, None)

    entry 는 항상 채워서 돌려준다. 매핑에 없으면 DEFAULT_ENTRY 를 쓴다.
    """
    check_id = finding.get("check_id")
    raw = mapping.get(check_id) if check_id else None

    if raw is None:
        return None, "unmapped", f"mapping.yml 에 '{check_id}' 항목이 없음", dict(DEFAULT_ENTRY)

    # 빠진 키는 기본값으로 채운다
    entry = dict(DEFAULT_ENTRY)
    entry.update(raw or {})

    mode = entry.get("mode")
    if mode not in EXECUTABLE_MODES:
        status = MODE_STATUS.get(mode)
        if status is None:
            # 알 수 없는 mode 는 실행하지 않는다
            return None, "unmapped", f"알 수 없는 mode: {mode}", entry
        return None, status, build_reason(finding, entry, mode), entry

    # policy 를 적어두면 그걸 쓰고, 없으면 check_id 를 변환해 찾는다.
    # policy: null 을 명시한 경우(실행할 정책 없음)와 키를 생략한 경우를 구분한다
    policy_name = raw["policy"] if "policy" in raw else check_id_to_policy(check_id)

    if not policy_name:
        return None, "unmapped", f"mode={mode} 지만 policy 가 비어 있음", entry

    return policy_name, None, None, entry


def group_by_policy(findings, mapping):
    """finding 마다 매핑을 조회해 상태를 채우고, 실행 대상만 정책별로 묶는다.

    반환: {정책이름: [finding, ...]}

    실행 대상 finding 에는 두 가지를 붙인다.
      finding["mapping"]      라우팅 정보 (mode · scope_key · guide)
      finding["policy_meta"]  조치 속성 (metadata.approve · metadata.auto)

    정책 파일은 **정책당 한 번만** 읽는다. finding 마다 읽으면 같은 파일을
    반복해서 파싱하게 된다.
    """
    findings_by_policy = {}
    meta_cache = {}
    warned = set()      # 같은 체크의 경고를 반복 출력하지 않기 위함

    for finding in findings:
        policy_name, status, reason, entry = resolve_policy(finding, mapping)
        finding["mapping"] = entry
        finding["status"] = status
        finding["reason"] = reason
        finding["policy_name"] = policy_name
        finding["policy_meta"] = None
        if not policy_name:
            continue

        check_id = finding.get("check_id")
        if policy_name not in meta_cache:
            meta_cache[policy_name] = load_meta(policy_name)
            # 정책과 매핑이 어긋나면 실행 전에 알린다. 손으로 정책을 쓰는
            # 구조라 출처 체크만 복사해 남는 실수가 생긴다
            for warning in (
                check_prowler_link(policy_name, check_id),
                # 자동화 선언과 정책 속성이 어긋나는지 - 사람의 판정에 대한 이견
                check_auto_claim(policy_name, entry.get("auto_eligible"),
                                 meta_cache[policy_name]),
            ):
                if warning:
                    print(f"      [경고] {warning}")

        finding["policy_meta"] = meta_cache[policy_name]
        findings_by_policy.setdefault(policy_name, []).append(finding)

        # 남아 있는 위험은 실행 전에 눈에 띄게 알린다
        note = entry.get("risk_note")
        if note and check_id not in warned:
            warned.add(check_id)
            print(f"      [주의] {check_id}: {note}")

    executed = sum(len(v) for v in findings_by_policy.values())
    print(f"      실행 대상 {executed}건 / 제외 {len(findings) - executed}건")
    return findings_by_policy
