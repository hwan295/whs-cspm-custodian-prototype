"""Prowler findings 를 Custodian 정책에 매핑해 조치하는 모듈.

통합 파이프라인에서는 이렇게 쓴다.

    from response import run
    records = run(findings)          # findings = 파싱된 dict 리스트
    records = run_raw(raw_findings)  # raw = OCSF 원본 리스트
"""

from .run import main, run, run_raw

__all__ = ["run", "run_raw", "main"]
