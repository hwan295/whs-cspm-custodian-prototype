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
    from response import run; run(findings)             라이브러리

환경변수
    CSPM_SCOPE_ACCOUNTS   조치 대상 계정 (쉼표 구분). scope.yml 보다 우선한다
    CSPM_SCOPE_REGIONS    조치 대상 리전 (쉼표 구분)
    CSPM_WORK_DIR         out/ · logs/ 를 만들 위치. 기본값은 현재 디렉토리

주의: 실제 조치(actions)는 실행하지 않는다. 정책에 actions 가 있지만 --dryrun 으로만
      돌리므로 "무엇이 바뀔지"만 출력된다.
"""

import os
import sys

from .approval import set_auto_answer
from .executor import execute_policies
from .findings import parse_findings, parse_raw_findings
from .mapping import group_by_policy, load_mapping
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


def _parse_args(argv):
    """플래그와 파일 경로를 가른다. 반환: (경로, 자동응답) / 오류면 (None, None)."""
    auto_answer = None
    paths = []
    for arg in argv[1:]:
        if arg == "--yes":
            auto_answer = True
        elif arg == "--no":
            auto_answer = False
        elif arg.startswith("-"):
            print(f"[!] 알 수 없는 옵션: {arg}", file=sys.stderr)
            return None, None
        else:
            paths.append(arg)

    if len(paths) != 1:
        return None, None
    return paths[0], auto_answer


def main(argv):
    """CLI 진입점. 파일을 읽어 run() 에 넘기고 결과를 로그로 저장한다."""
    findings_path, auto_answer = _parse_args(argv)
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
    print_summary(records, write_log(records))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
