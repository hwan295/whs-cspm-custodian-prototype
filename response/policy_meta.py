"""정책 파일 접근과 metadata 해석.

정책 파일(policies/<서비스>.yml)을 읽는 곳을 여기 하나로 모은다.
범위 제한(scoping)·승인(approval)·로그(reporter)가 모두 같은 파일을 보기 때문에,
파일을 여는 코드가 흩어지면 서로 다른 정책을 집는 사고가 난다.

metadata 는 두 블록으로 나뉜다.
    approve   조치를 실행하면 무슨 일이 일어나는가 (승인 화면과 로그가 쓴다)
    auto      승인 없이 돌려도 되는가, 돌린다면 무슨 안전장치가 필요한가

mapping.yml 과 역할이 다르다. mapping 은 "이 체크를 어디로 보낼까"(라우팅)이고,
여기는 "그 조치가 어떤 성질인가"(조치 속성)다. 조치 속성은 정책과 한 몸이라
정책 파일에 둔다 - 정책을 리뷰하는 사람이 한 파일만 보고 판단할 수 있어야 한다.
"""

import os

import yaml

from .config import POLICY_DIR

# auto 승격 자격 조건. 넷을 모두 만족해야 한다.
#
# 되돌릴 수 있고(reversible), 리소스 하나만 건드리고(blast_radius),
# 서비스 중단이 없고(disruption), 되돌리는 방법이 적혀 있을 것(rollback_cli).
#
# 넷 다 정책 파일 안에 있어서 리뷰어가 한 파일만 보고 검증할 수 있다.
# 계정 단위 체크는 blast_radius 에서 자동으로 탈락한다 - 계정 전체가 한 번에
# 바뀌는 조치는 사람이 매번 확인해야 하기 때문이다.
AUTO_REQUIRED = {
    "reversible": True,
    "blast_radius": "resource",
    "disruption": "none",
}


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


def compute_eligible(meta):
    """auto 승격 자격을 조건으로 계산한다.

    반환: (자격 여부, 미달 사유)
    """
    approve = meta.get("approve") or {}
    unmet = [
        f"{key}={approve.get(key)!r} (필요: {want!r})"
        for key, want in AUTO_REQUIRED.items()
        if approve.get(key) != want
    ]
    if not (meta.get("auto") or {}).get("rollback_cli"):
        unmet.append("rollback_cli 없음")

    if unmet:
        return False, " / ".join(unmet)
    return True, None


def resolve_eligible(policy_name, meta):
    """파일에 적힌 auto.eligible 과 계산 결과를 맞춰본다.

    사람이 적은 값을 그대로 믿지 않는다. 정책을 손으로 쓰고 서로 리뷰하는
    구조라, 조건을 못 채운 정책에 eligible: true 가 붙는 실수를 여기서 잡는다.

    - 적힌 값이 없으면 계산 결과를 쓴다
    - false 로 적혀 있으면 그대로 둔다 (조건을 채워도 자동화하지 않겠다는 판단)
    - true 인데 조건 미달이면 false 로 낮추고 경고한다

    반환: (자격 여부, 사유)
    """
    computed, unmet = compute_eligible(meta)
    auto = meta.get("auto") or {}
    declared = auto.get("eligible")

    if declared is None:
        return computed, auto.get("reason") or unmet

    if declared is False:
        # 사람이 명시적으로 막은 것. 사유는 사람이 적은 걸 우선한다
        return False, auto.get("reason") or unmet

    if not computed:
        print(f"[!] {policy_name}: auto.eligible=true 지만 조건 미달 - {unmet}")
        return False, unmet

    return True, None


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
