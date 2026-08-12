"""실행 범위 제한 - 실행 전에 대상 리소스로 정책을 좁힌다.

Custodian 은 정책을 계정 전체에 대해 돌린다. 원본 정책을 그대로 실행하면
findings 에 없는 리소스까지 대상이 된다. dryrun 동안은 무해하지만
actions 를 붙이는 순간 **의도하지 않은 리소스까지 고치게 된다.**

그래서 실행기와 별도 모듈로 두었다. 실조치의 안전장치라 눈에 띄어야 한다.
"""

import os

import yaml

from .config import POLICY_DIR, SCOPED_DIR


def policy_file(policy_name):
    """정책이 들어 있는 서비스별 파일 경로.

    정책 이름의 첫 조각이 서비스다.
        s3-bucket-kms-encryption  ->  policies/s3.yml
        ec2-instance-imdsv2       ->  policies/ec2.yml

    서비스별로 묶는 이유 - 정책이 늘어도 파일이 흩어지지 않고, 나중에 같은
    리소스 타입을 한 번에 실행할 때 조회 결과를 공유할 수 있다.
    """
    service = policy_name.split("-")[0]
    return os.path.join(POLICY_DIR, f"{service}.yml")


def find_policy(policy_name):
    """서비스 파일에서 해당 이름의 정책 하나를 꺼낸다.

    반환: (정책 dict, 에러메시지)
    """
    path = policy_file(policy_name)
    if not os.path.isfile(path):
        return None, f"정책 파일이 없음: {path}"

    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError) as e:
        return None, f"정책 파일을 읽지 못함: {e}"

    for policy in doc.get("policies") or []:
        if policy.get("name") == policy_name:
            return policy, None

    return None, f"{path} 에 '{policy_name}' 정책이 없음"


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


def build_scoped_policy(policy_name, findings):
    """findings 의 리소스만 대상으로 하는 임시 정책 파일을 만든다.

    서비스 파일에서 해당 정책 하나만 꺼내 별도 문서로 쓴다. 같은 파일의 다른
    정책까지 실행되면 안 되기 때문이다.

    반환: (실행할 정책 경로, 설명) / 실패 시 (None, 에러메시지)
    """
    policy, error = find_policy(policy_name)
    if error:
        return None, error

    remediation = (findings[0].get("remediation") or {}) if findings else {}
    scope_key = remediation.get("scope_key")

    names = sorted({
        n for n in (extract_resource_name(f.get("resource_uid")) for f in findings) if n
    })

    # 계정 단위 체크는 계정 설정 하나를 보는 것이라 리소스 필터를 얹으면 판정이 어긋난다
    if remediation.get("blast_radius") == "account":
        note = "계정 단위 체크 - 범위 제한 없이 실행"
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
