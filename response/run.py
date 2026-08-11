#!/usr/bin/env python3
"""CSPM 자동 대응 - 진입점.

Prowler findings 를 읽어 각 체크에 대응하는 Custodian 정책을 찾고,
대상 리소스로 범위를 좁혀 dryrun 실행한 뒤, 결과를 대조해 조치 로그를 남긴다.

Custodian 은 findings 를 입력으로 받지 않고 AWS 를 직접 조회하는 도구이므로,
두 도구의 연결점은 "Prowler 의 event_code ↔ Custodian 정책 이름" 매핑뿐이다.

사용법
    python -m response <prowler-output.ocsf.json>      CLI
    from response import run; run(findings)            라이브러리

주의: 실제 조치(actions)는 실행하지 않는다. dryrun 전용이다.
"""

import sys

from .executor import execute_policies
from .findings import parse_findings, parse_raw_findings
from .mapping import group_by_policy, load_mapping
from .reporter import build_log_records, print_summary, write_log


def run(findings, mapping_path=None):
    """파싱된 findings 를 받아 조치 결과 레코드를 돌려준다.

    파일 읽기와 로그 저장은 하지 않는다. 입력을 어디서 얻고 결과를 어디에 쓸지는
    호출부가 정한다 — 통합 파이프라인에서 DB·API 로 바꿔 끼울 수 있어야 하기 때문이다.

    반환: 조치 로그 레코드 리스트
    """
    if not findings:
        return []

    mapping = load_mapping(mapping_path) if mapping_path else load_mapping()
    findings_by_policy = group_by_policy(findings, mapping)

    if findings_by_policy:
        execute_policies(findings_by_policy)
    else:
        print("[3/4] 실행할 정책이 없어 건너뜁니다.")

    return build_log_records(findings)


def run_raw(raw_findings, mapping_path=None):
    """OCSF 원본 리스트를 받아 파싱부터 수행한다. DB·API 로 받은 경우에 쓴다."""
    return run(parse_raw_findings(raw_findings), mapping_path)


def main(argv):
    """CLI 진입점. 파일을 읽어 run() 에 넘기고 결과를 로그로 저장한다."""
    if len(argv) != 2:
        print(__doc__.strip())
        return 1

    findings_path = argv[1]
    import os
    if not os.path.isfile(findings_path):
        print(f"[!] 파일을 찾을 수 없습니다: {findings_path}", file=sys.stderr)
        return 1

    findings = parse_findings(findings_path)
    if not findings:
        print("[*] 처리할 FAIL finding 이 없습니다.")
        return 0

    records = run(findings)
    print_summary(records, write_log(records))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
