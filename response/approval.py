"""승인 프롬프트 - mode=approve 인 건을 사람에게 묻는다.

dryrun 으로 대상을 확인한 뒤에 묻는다. 무엇을 고칠지 보여줘야 판단할 수 있기 때문이다.

물을 때는 네 가지를 보여준다.
    무엇이 문제인가   체크 제목 · severity · 위험 설명
    무엇을 할 것인가   정책이 실행할 액션
    왜 확인이 필요한가 risk_note (자동으로 돌리지 않는 이유)
    어느 리소스인가   ARN · 리전 · 리소스별 FAIL 사유

비대화형(파이프·CI)에서는 묻지 않고 approval_pending 으로 남긴다.
자동 실행 중에 입력을 기다리며 멈추면 안 된다.
"""

import os
import sys

import yaml

from .scoping import policy_file

# 프롬프트 없이 일괄 처리할 때 쓰는 값. run.py 가 CLI 인자로 설정한다.
#   None  - 물어본다 (기본)
#   True  - 전부 승인
#   False - 전부 거부
AUTO_ANSWER = None


def set_auto_answer(value):
    """--yes / --no 플래그를 반영한다."""
    global AUTO_ANSWER
    AUTO_ANSWER = value


def is_interactive():
    """사람이 답할 수 있는 환경인가."""
    try:
        return sys.stdin.isatty()
    except (AttributeError, ValueError):
        return False


def describe_actions(policy_name):
    """정책이 실행할 액션을 사람이 읽을 수 있게 요약한다.

    승인자가 "무엇을 할 것인지" 알아야 판단할 수 있다.
    정책 파일을 읽지 못하면 빈 리스트를 돌려주고 프롬프트에서 생략한다.
    """
    path = policy_file(policy_name)
    if not os.path.isfile(path):
        return []

    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = yaml.safe_load(f) or {}
        policies = doc.get("policies") or []
        if not policies:
            return []
        actions = policies[0].get("actions") or []
    except (OSError, yaml.YAMLError):
        return []

    summary = []
    for action in actions:
        if isinstance(action, str):
            summary.append(action)
            continue
        if not isinstance(action, dict):
            continue
        name = action.get("type", "?")
        # 액션 이름만으로는 무엇이 바뀌는지 모르니 주요 파라미터를 붙인다
        params = [
            f"{k}={v}" for k, v in action.items()
            if k != "type" and not isinstance(v, (dict, list))
        ]
        summary.append(f"{name}({', '.join(params)})" if params else name)
    return summary


def _print_request(policy_name, findings):
    """승인 요청 내용을 출력한다."""
    head = findings[0]
    remediation = head.get("remediation") or {}

    print("")
    print("  " + "─" * 66)
    print(f"  승인 요청  ·  {head.get('check_id')}  ({head.get('severity') or '?'})")
    print("  " + "─" * 66)

    title = head.get("title")
    if title:
        print(f"  문제   {title}")

    risk = head.get("risk_details") or head.get("description")
    if risk:
        print(f"         {_trim(risk)}")

    actions = describe_actions(policy_name)
    if actions:
        print(f"  조치   {'; '.join(actions)}")
    else:
        print(f"  조치   정책 {policy_name} 실행")

    note = remediation.get("risk_note")
    if note:
        print(f"  주의   {note}")

    disruption = remediation.get("disruption")
    blast = remediation.get("blast_radius")
    if disruption or blast:
        print(f"  영향   중단={disruption or '?'} · 범위={blast or '?'}")

    print("")
    print(f"  대상 {len(findings)}건")
    for finding in findings:
        region = finding.get("region") or "-"
        print(f"     · {finding.get('resource_uid')}  [{region}]")
        detail = finding.get("status_detail")
        if detail:
            print(f"       {_trim(detail, 100)}")
    print("")


def _trim(text, limit=160):
    """긴 설명을 한 줄로 줄인다."""
    flat = " ".join(str(text).split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def confirm(policy_name, findings):
    """조치 여부를 묻는다.

    반환: True(승인) / False(거부) / None(물을 수 없어 보류)
    """
    if AUTO_ANSWER is not None:
        answer = "승인" if AUTO_ANSWER else "거부"
        print(f"      [{policy_name}] 대상 {len(findings)}건 - 플래그로 일괄 {answer}")
        return AUTO_ANSWER

    if not is_interactive():
        print(f"      [{policy_name}] 대상 {len(findings)}건 - 비대화형이라 승인 보류")
        return None

    _print_request(policy_name, findings)

    try:
        answer = input("  조치하시겠습니까? (y/N) ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("")
        print("      입력이 중단되어 승인을 보류합니다")
        return None

    return answer in ("y", "yes")


def print_guidance(findings):
    """거부했을 때 조치 방법을 출력한다."""
    for finding in findings:
        print(f"     · {finding.get('resource_uid')}")
        if finding.get("reason"):
            print(f"       {_trim(finding['reason'])}")
        for ref in finding.get("remediation_refs") or []:
            print(f"       참고: {ref}")
