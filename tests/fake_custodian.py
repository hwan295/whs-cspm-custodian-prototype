#!/usr/bin/env python3
"""가짜 custodian - AWS 없이 파이프라인 전체를 돌려보기 위한 스텁.

**왜 필요한가.** 이 저장소의 코드는 Custodian 의 실행 결과(`resources.json`)를
읽어 판정한다. 진짜 Custodian 은 AWS 자격증명을 요구하므로, 자격증명이 없는
사람은 코드가 도는 것조차 볼 수 없다. 리뷰가 불가능해진다.

**무엇을 흉내내는가.** 진짜 Custodian 이 하는 일 중 결과 파일을 쓰는 부분만
흉내낸다. 필터를 실제로 평가하지는 않는다.

    -s <out_dir> <policy.yml>     실행 형태
    <out_dir>/<정책이름>/resources.json    걸린 리소스
    <out_dir>/<정책이름>/metadata.json     조회 계정·리전

**핵심 관찰 지점 두 가지.**

1. 범위 제한(④)이 걸렸는지 - 정책 맨 앞의 `op: in` 필터를 읽어 그 대상만
   남긴다. 필터가 없으면 인벤토리 전체를 남긴다. 범위 제한이 빠지면
   "finding 에 없는 리소스까지 걸린다" 는 것이 눈에 보인다.

2. `--dryrun` 이 있는지 - 없으면 **실조치로 간주해 상태를 바꾼다.**
   해당 리소스를 `_state.json` 에 적어두고, 이후 조회에서 제외한다.
   그래야 조치 후 재확인(`_confirm`)이 `remediated` 로 떨어지는 것을 볼 수 있다.

인벤토리에는 **findings 에 없는 리소스가 섞여 있다.** 초과 조치 경고가
동작하는지 보기 위해서다.
"""

import json
import os
import sys
from datetime import datetime

import yaml

ACCOUNT_ID = "123456789012"
REGION = "ap-northeast-2"

# 이 계정에 있다고 치는 리소스. c7n 이 돌려주는 필드 이름을 그대로 쓴다.
# 뒤에 주석이 붙은 것은 sample-findings 에 없는 리소스다 (초과 조치 관찰용).
INVENTORY = {
    "aws.s3": [
        {"Name": "example-app-bucket",
         "BucketArn": "arn:aws:s3:::example-app-bucket"},
        {"Name": "aws-cloudtrail-logs-123456789012-a1b2c3d4",
         "BucketArn": "arn:aws:s3:::aws-cloudtrail-logs-123456789012-a1b2c3d4"},
        {"Name": "team-terraform-state",              # findings 에 없음
         "BucketArn": "arn:aws:s3:::team-terraform-state"},
        {"Name": "marketing-static-site",             # findings 에 없음
         "BucketArn": "arn:aws:s3:::marketing-static-site"},
    ],
    "aws.ec2": [
        {"InstanceId": "i-0abc", "MetadataOptions": {"HttpTokens": "optional"}},
        {"InstanceId": "i-0def", "MetadataOptions": {"HttpTokens": "optional"}},  # findings 에 없음
    ],
    "aws.cloudtrail": [
        {"Name": "example-trail",
         "TrailARN": f"arn:aws:cloudtrail:{REGION}:{ACCOUNT_ID}:trail/example-trail",
         "LogFileValidationEnabled": False},
    ],
    # 계정 단위 체크는 리소스가 "계정 설정 하나" 다
    "aws.account": [
        {"account_id": ACCOUNT_ID, "account_name": "stub-account"},
    ],
}


def parse_args(argv):
    """-s <out_dir> <policy.yml> 과 --dryrun 유무를 읽는다."""
    out_dir, policy_path, dry_run = None, None, False
    for i, arg in enumerate(argv):
        if arg == "-s":
            out_dir = argv[i + 1]
        elif arg == "--dryrun":
            dry_run = True
        elif arg.endswith(".yml"):
            policy_path = arg
    return out_dir, policy_path, dry_run


def scope_filter(policy):
    """정책 맨 앞의 범위 제한 필터를 꺼낸다. 반환: (key, [값]) / 없으면 (None, None).

    scoping.build_scoped_policy() 가 넣는 필터를 찾는 것이다.
    """
    for f in policy.get("filters") or []:
        if isinstance(f, dict) and f.get("type") == "value" and f.get("op") == "in":
            return f.get("key"), f.get("value") or []
    return None, None


def identify(policy_name, resource):
    """상태 파일에 적을 식별자. 리소스 종류마다 있는 필드가 다르다.

    **정책 이름을 함께 넣는다.** 같은 버킷이라도 정책마다 보는 항목이 다르다 -
    전송 암호화를 고쳤다고 KMS 암호화까지 해결된 것은 아니다.
    """
    for field in ("BucketArn", "TrailARN", "InstanceId", "Name", "account_id"):
        if resource.get(field):
            return f"{policy_name}|{resource[field]}"
    return f"{policy_name}|{json.dumps(resource, sort_keys=True)}"


def load_state(out_dir):
    """이미 조치된 것으로 표시된 식별자 집합."""
    path = os.path.join(out_dir, "_state.json")
    if not os.path.isfile(path):
        return set()
    with open(path, encoding="utf-8") as fh:
        return set(json.load(fh))


def save_state(out_dir, done):
    with open(os.path.join(out_dir, "_state.json"), "w", encoding="utf-8") as fh:
        json.dump(sorted(done), fh, indent=2)


def main(argv):
    out_dir, policy_path, dry_run = parse_args(argv)
    if not out_dir or not policy_path:
        print("usage: custodian run -s <dir> <policy.yml> [--dryrun]", file=sys.stderr)
        return 1

    with open(policy_path, encoding="utf-8") as fh:
        policy = (yaml.safe_load(fh) or {})["policies"][0]

    name = policy["name"]
    resource_type = policy.get("resource", "aws.s3")
    candidates = INVENTORY.get(resource_type, [])

    key, values = scope_filter(policy)
    if key is None:
        # 범위 제한이 없다 -> 계정 전체가 대상
        hits = list(candidates)
        matched = ["(범위 제한 없음)"]
    else:
        hits = [r for r in candidates if r.get(key) in values]
        matched = [key]

    # 이미 조치된 리소스는 더 이상 위반이 아니므로 결과에서 뺀다
    os.makedirs(out_dir, exist_ok=True)
    done = load_state(out_dir)
    hits = [r for r in hits if identify(name, r) not in done]

    if not dry_run:
        # --dryrun 이 없다 = 실조치. 걸린 리소스를 고쳐진 것으로 표시한다
        save_state(out_dir, done | {identify(name, r) for r in hits})

    policy_dir = os.path.join(out_dir, name)
    os.makedirs(policy_dir, exist_ok=True)

    with open(os.path.join(policy_dir, "resources.json"), "w", encoding="utf-8") as fh:
        json.dump([dict(r, **{"c7n:MatchedFilters": matched}) for r in hits], fh, indent=2)

    with open(os.path.join(policy_dir, "metadata.json"), "w", encoding="utf-8") as fh:
        json.dump({"config": {"account_id": ACCOUNT_ID, "region": REGION}}, fh, indent=2)

    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(os.path.join(policy_dir, "custodian-run.log"), "a", encoding="utf-8") as fh:
        fh.write(f"{stamp} - custodian.policy - INFO - policy:{name} "
                 f"resource:{resource_type} count:{len(hits)}\n")

    mode = "dryrun" if dry_run else "APPLY"
    print(f"[stub/{mode}] policy:{name} resource:{resource_type} count:{len(hits)}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
