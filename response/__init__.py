"""Prowler findings 를 Custodian 정책에 매핑해 조치하는 모듈.

통합 파이프라인에서는 이렇게 쓴다.

    from response import run, remediate

    # Phase 1 - 무엇을 조치해야 하는지 판정한다. 조치는 하지 않는다
    records = run(findings)          # findings = 파싱된 dict 리스트
    records = run_raw(raw_findings)  # raw = OCSF 원본 리스트

    # Phase 2 - 사람이 승인한 건만 다시 검증하고 조치한다
    results = remediate(approvals)   # approvals = 승인된 건 목록

비대화형(웹·CI)에서 Phase 1 을 돌리면 approve 건이 approval_pending 으로 남는다.
그 목록을 사람에게 보여주고, 승인된 것만 Phase 2 로 넘기면 된다.
"""

from .remediation import remediate
from .run import main, run, run_raw

__all__ = ["run", "run_raw", "remediate", "main"]
