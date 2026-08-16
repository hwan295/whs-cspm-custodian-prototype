"""자동 실행 opt-in 조회 - DB 연결 전까지의 스텁.

**아직 아무것도 자동으로 실행되지 않는다.** 이 모듈은 항상 False 를 돌려준다.

설계상 흐름은 이렇다.
    조치 가능한 체크는 전부 approve 로 시작한다
    -> 사용자가 승인하고 조치가 정상 해결되면
    -> 대시보드에서 "앞으로 자동 실행" 을 켠다 (opt-in)
    -> 다음 finding 부터 승인 없이 실행된다

opt-in 은 계정마다·체크마다·범위마다 다르므로 파일이 아니라 DB 에 있어야 한다
(auto_opt_in 테이블). 그 테이블은 통합 파이프라인 쪽에서 만들 예정이라,
지금은 호출 지점만 만들어 두고 본문은 비워둔다.

**연결할 때 고칠 곳은 이 파일 두 함수뿐이다.** 실행 분기는 이미 executor 에
들어가 있으므로, is_opted_in() 이 True 를 돌려주기 시작하면 그때부터 auto 가
동작한다. describe_source() 도 함께 고쳐야 한다 - 실행 로그에 "미연결" 이라고
찍히는데 실제로는 자동 실행이 나가는 상황이 되면 안 된다.
"""


def is_opted_in(account_uid, check_id, scope=None, scope_value=None):
    """사용자가 이 체크의 자동 실행을 켜 두었는가.

    나중에 auto_opt_in 테이블을 이렇게 조회하게 된다.
        SELECT active FROM auto_opt_in
         WHERE account_id = ? AND check_id = ? AND active = true

    scope / scope_value 는 "이 리소스만" 또는 "이 리전만" 처럼 범위를 좁혀
    허용한 경우를 위해 미리 받아둔다. 지금은 쓰지 않는다.

    반환: 항상 False (DB 연결 전)
    """
    return False


def describe_source():
    """opt-in 정보를 어디서 읽었는지. 실행 로그에 남겨 오해를 막는다."""
    return "미연결(스텁) - 모든 조치가 승인을 거칩니다"
