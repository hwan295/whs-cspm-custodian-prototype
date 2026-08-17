"""실행 범위 제한 - 실행 전에 대상 리소스로 정책을 좁힌다.

Custodian 은 정책을 계정 전체에 대해 돌린다. 원본 정책을 그대로 실행하면
findings 에 없는 리소스까지 대상이 된다. dryrun 동안은 무해하지만
actions 를 붙이는 순간 **의도하지 않은 리소스까지 고치게 된다.**

**auto 가 켜지면 이 단계가 유일한 방어선이다.** 승인 화면이 없어 사람이
초과 대상을 볼 기회가 없기 때문이다. 그래서 실행기와 별도 모듈로 두었다.
"""

import os

import yaml

from .config import SCOPED_DIR
from .policy_meta import find_policy, is_account_scoped


def extract_resource_name(arn):
    """ARN 에서 리소스 식별자(마지막 조각)를 뽑는다.

        arn:aws:s3:::example                       -> example
        arn:aws:ec2:ap-…:123:instance/i-0abc       -> i-0abc
    """
    if not arn:
        return None
    tail = arn.split(":")[-1]
    if "/" in tail:
        tail = tail.split("/")[-1]
    return tail or None


def extract_scope_value(resource_uid, scope_key):
    """scope_key 가 요구하는 형태로 식별자를 뽑는다.

    **필드마다 요구하는 값이 다르다.** InstanceId 는 i-0abc 를 원하지만
    TrailARN 은 ARN 전체를 원한다. 무조건 마지막 조각을 넣으면
    `key: TrailARN, value: [trail-이름]` 처럼 절대 맞지 않는 필터가 만들어진다.
    실제로 CloudTrail 정책이 이 때문에 0건을 반환해 "이미 해소됨" 으로
    오판한 적이 있다.

    이름이 arn 으로 끝나는 필드는 ARN 을 그대로 쓴다
    (TrailARN · SubnetArn · BucketArn 등).
    """
    if not resource_uid:
        return None
    if scope_key and scope_key.lower().endswith("arn"):
        return resource_uid
    return extract_resource_name(resource_uid)


def build_scoped_policy(policy_name, findings):
    """findings 의 리소스만 대상으로 하는 임시 정책 파일을 만든다.

    서비스 파일에서 해당 정책 하나만 꺼내 별도 문서로 쓴다. 같은 파일의 다른
    정책까지 실행되면 안 되기 때문이다.

    반환: (실행할 정책 경로, 설명) / 실패 시 (None, 에러메시지)
    """
    policy, error = find_policy(policy_name)
    if error:
        return None, error

    head = findings[0] if findings else {}
    scope_key = (head.get("mapping") or {}).get("scope_key")
    approve = (head.get("policy_meta") or {}).get("approve") or {}

    names = sorted({
        value for value in (
            extract_scope_value(f.get("resource_uid"), scope_key) for f in findings
        ) if value
    })

    # 계정·리전 단위 체크는 설정 하나를 보는 것이라 리소스 필터를 얹으면 판정이 어긋난다
    if is_account_scoped(approve):
        note = f"{approve.get('blast_radius')} 단위 체크 - 범위 제한 없이 실행"
    elif not scope_key:
        note = "경고: scope_key 가 없어 계정 전체를 대상으로 실행"
    elif not names:
        note = "경고: 대상 리소스 이름을 뽑지 못해 범위 제한 없이 실행"
    else:
        # 이름 필터를 맨 앞에 둔다. 뒤쪽 필터는 걸러진 리소스에 대해서만 평가된다
        scope_filter = {"type": "value", "key": scope_key, "op": "in", "value": names}
        policy = dict(policy)
        policy["filters"] = [scope_filter] + list(policy.get("filters") or [])
        note = f"대상 {len(names)}건으로 범위 제한 ({scope_key})"

    try:
        os.makedirs(SCOPED_DIR, exist_ok=True)
        dst = os.path.join(SCOPED_DIR, f"{policy_name}.yml")
        with open(dst, "w", encoding="utf-8") as f:
            yaml.safe_dump({"policies": [policy]}, f, allow_unicode=True, sort_keys=False)
    except (OSError, yaml.YAMLError) as e:
        return None, f"범위 제한 정책 생성 실패: {e}"

    return dst, note
