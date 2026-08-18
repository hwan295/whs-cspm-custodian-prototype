# AWS 없이 돌려보기

이 저장소의 코드는 Cloud Custodian 의 실행 결과를 읽어 판정한다. 진짜 Custodian 은
AWS 자격증명을 요구하므로, **자격증명이 없으면 코드가 도는 것조차 볼 수 없다.**
여기 있는 스텁이 그 자리를 대신한다.

```bash
pip install pyyaml

sh tests/run.sh --yes            # Phase 1 - 판정까지
sh tests/run.sh --yes --apply    # Phase 2 - 조치 후 재확인까지 (대화형 터미널 필요)
```

`--yes` 는 승인 프롬프트를 일괄 승인한다. 빼면 리소스마다 물어본다.

`tests/bin` 이 `PATH` 앞에 붙어 `custodian` 이 `fake_custodian.py` 로 바뀐다.
실제 AWS 는 어떤 경우에도 호출되지 않는다.

## Phase 1 결과

```
=== 요약 ===
  approved                  4건
  manual_required           2건
```

## Phase 2 결과

`--apply` 는 실행 직전에 `apply` 를 그대로 입력받는 확인을 거친다.
비대화형(파이프·CI)이면 실행하지 않는다.

```
=== 최종 status ===
  manual_required           2건
  remediated                4건
```

## 이 스텁으로 확인할 수 있는 것

| | 어디를 보나 |
|---|---|
| **범위 제한(④)이 걸리는가** | `대상 N건으로 범위 제한 (Name)` 이 찍히는지 |
| **범위 제한이 빠지면 어떻게 되는가** | 인벤토리에 findings 에 없는 버킷이 섞여 있다. 필터가 빠지면 그것들까지 걸린다 |
| **계정 단위 체크의 판정 단위** | `s3-account-level-public-access-blocks` 는 범위 제한 없이 돈다 |
| **실조치와 dryrun 의 차이** | 스텁은 `--dryrun` 유무를 보고 상태를 바꾼다. 명령줄에 `--dryrun` 이 있는지 로그로 확인할 수 있다 |
| **조치 후 재확인** | 조치한 리소스가 다음 조회에서 빠져 `remediated` 로 떨어진다 |
| **승인 게이트** | `--apply` 없이는 아무리 승인해도 `approved` 에서 멈춘다 |

## 스텁이 하지 않는 것

**필터를 평가하지 않는다.** 정책 맨 앞의 범위 제한 필터(`op: in`)만 읽고,
나머지 필터는 무시한 채 인벤토리를 돌려준다. 따라서 **정책 필터가 맞는지는
이걸로 검증할 수 없다** - 그건 실제 AWS 가 필요하다.

**액션을 실행하지 않는다.** `--dryrun` 이 없으면 "고쳐진 것으로 표시" 할 뿐이다.
액션이 실제로 동작하는지는 별개 문제다.

상태는 `tests/_work/out/_state.json` 에 쌓인다. `run.sh` 가 매번 지운다.
