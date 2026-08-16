"""정책 파일 접근과 metadata 해석.

정책 파일(policies/<서비스>.yml)을 읽는 곳을 여기 하나로 모은다.
범위 제한(scoping)·승인(approval)·로그(reporter)가 모두 같은 파일을 보기 때문에,
파일을 여는 코드가 흩어지면 서로 다른 정책을 집는 사고가 난다.

mapping.yml 과 역할이 나뉜다.
    mapping.yml     판정에 대한 서술 - 왜 이 mode 인가, 왜 자동화 못 하는가
    metadata.approve 조치에 대한 서술 - 실행하면 무슨 일이 일어나는가

**판정 근거는 mapping.yml 에 둔다.** mode 가 manual / not_supported 면
policy 가 null 이라 정책 파일이 아예 없고, 그러면 근거를 적을 자리가 사라진다.
"""

import os

import yaml

from .config import POLICY_DIR


def policy_file(policy_name):
    """정책이 들어 있는 서비스별 파일 경로.

    정책 이름의 첫 조각이 서비스다.
        s3-bucket-kms-encryption  ->  policies/s3.yml
        ec2-instance-imdsv2       ->  policies/ec2.yml
    """
    service = policy_name.split("-")[0]
    return os.path.join(POLICY_DIR, f"{service}.yml")


def find_policy(policy_name):
    """서비스 파일에서 해당 이름의 정책 하나를 꺼낸다.

    이름으로 정확히 찾는다. 파일에 정책이 여러 개 들어 있어서 첫 정책을 집으면
    다른 체크의 필터와 액션을 쓰게 된다.

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


def load_meta(policy_name):
    """정책의 metadata 를 꺼낸다.

    반환: {"prowler_check": ..., "approve": {...}, "auto": {...}}
    정책을 못 찾으면 빈 블록을 돌려준다. metadata 가 없다고 실행을 막지는 않는다.
    """
    policy, error = find_policy(policy_name)
    if error:
        return {"prowler_check": None, "approve": {}, "auto": {}}

    metadata = policy.get("metadata") or {}
    return {
        "prowler_check": metadata.get("prowler_check"),
        "approve": metadata.get("approve") or {},
        "auto": metadata.get("auto") or {},
    }


# auto 승격이 안전하려면 정책 속성이 만족해야 하는 조건.
#
# **자격을 결정하는 건 사람이다.** mapping.yml 의 auto_eligible 이 판정 결과이고,
# 여기는 그 판정에 이견이 있을 때 알려주는 역할만 한다. 기계적 조건만으로는
# 잡을 수 없는 위험이 있기 때문이다 - 예를 들어 SSE-KMS 전환은 세 조건을 모두
# 만족하지만 cross-account 접근 주체의 KMS 권한 영향은 코드가 확인할 수 없다.
#
# rollback_cli 는 조건에서 뺐다. 정책 작성 중에는 metadata.auto 블록이 없는
# 경우가 많아 경고만 쌓인다. 실조치를 켤 때 다시 넣는다.
AUTO_REQUIRED = {
    "reversible": True,
    "blast_radius": "resource",
    "disruption": "none",
}


def check_auto_claim(policy_name, declared, meta):
    """mapping.yml 의 auto_eligible 이 정책 속성과 맞는지 본다.

    자동화하겠다고 선언했는데 되돌릴 수 없거나, 계정 전체에 영향을 주거나,
    서비스가 중단되는 조치면 알린다. 정책을 손으로 쓰고 서로 리뷰하는 구조라
    선언과 속성이 어긋나는 실수를 여기서 잡는다.

    metadata.approve 가 아직 없는 정책은 건너뛴다. 작성 중인 정책에
    경고를 쏟으면 진짜 문제가 묻힌다.

    반환: 경고 메시지 / 이견 없으면 None
    """
    if not declared:
        return None

    approve = (meta or {}).get("approve") or {}
    if not approve:
        return None

    unmet = [
        f"{key}={approve.get(key)!r} (필요: {want!r})"
        for key, want in AUTO_REQUIRED.items()
        if approve.get(key) != want
    ]
    if not unmet:
        return None
    return f"{policy_name}: auto_eligible=true 인데 {' / '.join(unmet)}"


def check_prowler_link(policy_name, check_id):
    """정책의 metadata.prowler_check 가 매핑 키와 맞는지 본다.

    이름 변환 규칙(언더바→하이픈) 덕에 어긋날 일이 적지만, 규칙과 다른 이름을
    쓰거나 정책을 복사해 만들 때 출처 체크만 그대로 남는 실수가 생긴다.
    정책이 늘고 손으로 작성할수록 값이 커지는 검사다.

    반환: 경고 메시지 / 문제 없으면 None
    """
    declared = load_meta(policy_name).get("prowler_check")
    if declared is None:
        return f"{policy_name}: metadata.prowler_check 가 없음"
    if declared != check_id:
        return (
            f"{policy_name}: metadata.prowler_check={declared} 인데 "
            f"매핑 키는 {check_id} - 둘 중 하나가 잘못됨"
        )
    return None
