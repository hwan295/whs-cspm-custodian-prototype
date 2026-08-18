#!/usr/bin/env python3
"""CSPM 자동 대응 - 진입점.

Prowler findings 를 읽어 조치 대상 범위를 거르고, 각 체크에 대응하는 Custodian
정책을 찾아 대상 리소스로 범위를 좁힌 뒤 dryrun 실행한다. 결과를 대조해
조치 여부를 판정하고, 승인이 필요한 건은 사람에게 묻는다.

Custodian 은 findings 를 입력으로 받지 않고 AWS 를 직접 조회하는 도구이므로,
두 도구의 연결점은 "Prowler 의 event_code ↔ Custodian 정책 이름" 매핑뿐이다.

사용법
    python -m response <prowler-output.ocsf.json>       CLI
    python -m response --yes <파일>                      승인 프롬프트를 전부 승인
    python -m response --no  <파일>                      전부 거부
    python -m response --apply <파일>                    승인된 건을 실제로 조치
    from response import run; run(findings)             라이브러리

환경변수
    CSPM_SCOPE_ACCOUNTS   조치 대상 계정 (쉼표 구분). scope.yml 보다 우선한다
    CSPM_SCOPE_REGIONS    조치 대상 리전 (쉼표 구분)
    CSPM_WORK_DIR         out/ · logs/ 를 만들 위치. 기본값은 현재 디렉토리

주의: --apply 를 주지 않으면 실제 조치는 나가지 않는다. 정책에 actions 가 있어도
      --dryrun 으로만 돌리므로 "무엇이 바뀔지"만 출력된다.

      --apply 는 **AWS 리소스를 실제로 바꾼다.** 승인한 건에 한해서만 나가고
      실행 직전에 한 번 더 묻지만, 되돌리는 것은 자동화되어 있지 않다.
"""

import os
import sys

from .approval import is_interactive, set_auto_answer
from .executor import execute_policies
from .findings import parse_findings, parse_raw_findings
from .mapping import group_by_policy, load_mapping
from .remediation import IDENTITY_FIELDS, remediate
from .reporter import build_log_records, print_summary, write_log
from .scope import filter_findings, load_scope


def run(findings, mapping_path=None):
    """파싱된 findings 를 받아 조치 결과 레코드를 돌려준다.

    파일 읽기와 로그 저장은 하지 않는다. 입력을 어디서 얻고 결과를 어디에 쓸지는
    호출부가 정한다 - 통합 파이프라인에서 DB·API 로 바꿔 끼울 수 있어야 하기 때문이다.

    반환: 조치 로그 레코드 리스트 (범위 밖으로 제외된 건도 포함)
    """
    if not findings:
        return []

    # 범위 밖 건은 status 가 채워진 채 findings 에 남는다. 로그에는 나와야 하기 때문이다
    in_scope_findings = filter_findings(findings, load_scope())

    mapping = load_mapping(mapping_path) if mapping_path else load_mapping()
    findings_by_policy = group_by_policy(in_scope_findings, mapping)

    if findings_by_policy:
        execute_policies(findings_by_policy)
    else:
        print("[3/4] 실행할 정책이 없어 건너뜁니다.")

    return build_log_records(findings)


def run_raw(raw_findings, mapping_path=None):
    """OCSF 원본 리스트를 받아 파싱부터 수행한다. DB·API 로 받은 경우에 쓴다."""
    return run(parse_raw_findings(raw_findings), mapping_path)


def _identity(record):
    """같은 finding 인지 가리는 키. Phase 1 레코드와 Phase 2 결과를 잇는다."""
    return tuple(record.get(field) for field in IDENTITY_FIELDS)


def _merge(records, results):
    """Phase 2 결과로 Phase 1 레코드를 덮어쓴다.

    로그는 하나만 남긴다. 두 벌을 남기면 같은 finding 이 approved 와 remediated
    두 줄로 나와 어느 쪽이 최종인지 알 수 없다.
    """
    updated = {_identity(r): r for r in results}
    return [updated.get(_identity(r), r) for r in records]


def _final_gate(approved):
    """실조치 직전의 마지막 확인.

    건별 승인은 Phase 1 에서 이미 받았다. 여기서 한 번 더 묻는 이유는
    **--yes 와 --apply 를 같이 주면 확인 없이 전부 나가기 때문이다.**
    비대화형이면 묻지 못하므로 실행하지 않는다 - 자동 실행은 opt-in 이 붙을
    때까지 열지 않는다.

    반환: 진행해도 되는가
    """
    print("")
    print("  " + "!" * 66)
    print(f"  실조치 {len(approved)}건을 AWS 에 적용합니다. 되돌리는 것은 수동입니다.")
    for record in approved[:10]:
        print(f"    · {record.get('check_id')}  {record.get('resource_uid')}")
    if len(approved) > 10:
        print(f"    · ... 외 {len(approved) - 10}건")
    print("  " + "!" * 66)

    if not is_interactive():
        print("  비대화형이라 실조치를 중단합니다. 터미널에서 다시 실행하세요.")
        return False

    try:
        answer = input("  정말 실행할까요? (apply 를 그대로 입력) ")
    except (EOFError, KeyboardInterrupt):
        print("")
        return False
    return answer.strip() == "apply"


def _apply_phase(records):
    """승인된 건을 Phase 2 로 넘겨 실제로 조치한다. 반환: 갱신된 레코드."""
    approved = [r for r in records if r.get("status") == "approved"]
    if not approved:
        print("\n[*] 승인된 건이 없어 실조치를 건너뜁니다.")
        return records

    if not _final_gate(approved):
        print("  실조치를 취소했습니다. 승인 결과는 그대로 로그에 남습니다.")
        return records

    print("")
    return _merge(records, remediate(approved, apply=True))


def _parse_args(argv):
    """플래그와 파일 경로를 가른다. 반환: (경로, 자동응답, 실조치) / 오류면 (None, ...)."""
    auto_answer = None
    apply_changes = False
    paths = []
    for arg in argv[1:]:
        if arg == "--yes":
            auto_answer = True
        elif arg == "--no":
            auto_answer = False
        elif arg == "--apply":
            apply_changes = True
        elif arg.startswith("-"):
            print(f"[!] 알 수 없는 옵션: {arg}", file=sys.stderr)
            return None, None, False
        else:
            paths.append(arg)

    if len(paths) != 1:
        return None, None, False
    return paths[0], auto_answer, apply_changes


def main(argv):
    """CLI 진입점. 파일을 읽어 run() 에 넘기고 결과를 로그로 저장한다."""
    findings_path, auto_answer, apply_changes = _parse_args(argv)
    if findings_path is None:
        print(__doc__.strip())
        return 1

    if not os.path.isfile(findings_path):
        print(f"[!] 파일을 찾을 수 없습니다: {findings_path}", file=sys.stderr)
        return 1

    set_auto_answer(auto_answer)

    findings = parse_findings(findings_path)
    if not findings:
        print("[*] 처리할 FAIL finding 이 없습니다.")
        return 0

    records = run(findings)
    if apply_changes:
        records = _apply_phase(records)
    print_summary(records, write_log(records))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
