# 레이어별 읽기 그룹 v1 — 2026-09-09

이번 기본 입력은 `traces/prefill_w4_decode_mixed_v1/`이다. 기존 `traces/smoke/`는 DRAM 적용 전의 별도 수집이며 그대로 보존했다. 모델 payload는 기존 C(일반 4-bit BCQ + 공유 FP16 scale, MRE 없음)를 사용한다.

**2026-09-09 QLC mapper용 파생 trace를 추가했다.** 기존 `layer_groups_lru_2147483648B/`는 scale 별도 상주 조건이고, 새 `layer_groups_lru_2147483648B_scales_on_demand/`는 plane과 요청된 scale column이 같은 2 GiB LRU를 공유한다. QLC-aligned 실험은 새 파생 trace를 사용한다. 배치 규격과 결과는 [QLC_ALIGNED_LAYOUT_V1.md](QLC_ALIGNED_LAYOUT_V1.md)에 있다.

## 실행 조건

- 모델별 WikiText-2의 128-token 입력 2개, batch=1, 입력마다 32-token greedy 생성. 첫 생성 token은 prefill에서 나오므로 요청당 decode forward는 31회다. 모델별 tokenizer 및 생성 결과가 달라 동일한 token 경로를 비교하는 실험은 아니다.
- Prefill: 실제로 선택된 expert만 W4로 실행. Decode: gate score 기반 W2/W3/W4, 임계값 0.16/0.075. 변경된 정책으로 실제 모델을 다시 실행해 수집했다.
- Host DRAM plane-cache: **2 GiB = 2,147,483,648 B**, projection별 plane 단위 LRU. 각 요청은 빈 캐시에서 시작하고 prefill 이후 상태를 decode까지 유지한다. 두 요청 사이에는 초기화한다.
- 동일 레이어의 token들이 요구하는 expert-plane을 중복 제거한다. 현재 레이어가 요구한 항목은 해당 그룹 처리 중 퇴출하지 않는다. 같은 그룹 내 LRU 순서는 item ID 사전순으로 정하며 실제 GPU 실행 순서를 뜻하지 않는다.
- Scale은 별도 DRAM 상주: Qwen 778,567,680 B, DeepSeek 899,678,208 B. **2 GiB에 포함되지 않는다.** 비양자화 가중치, KV cache, 관리 인덱스, allocator, 전송 staging 및 GPU 작업 공간도 이 plane 예산 밖이다.
- QLC mapper용 파생 trace에서는 위 scale 상주 가정을 해제했다. Wp가 요구하는 공유 `alpha_4` column 1…p를 SSD 대상에 포함하고 plane과 scale을 합쳐 2 GiB LRU를 적용했다.
- xPU의 지속적인 routed weight cache와 prefetch는 가정하지 않는다. 읽기 완료 후 cache에 적재하고, 현재 그룹의 읽기와 계산이 완료된 다음 그룹을 진행하는 순서만 표현한다. 시간·지연 측정은 없다.

## 결과와 파일

| 모델 | Prefill 그룹 | Decode 그룹 | Decode byte hit 비율 | Decode 읽기 없는 그룹 |
|---|---:|---:|---:|---:|
| Qwen | 48 | 1,488 | 55.07% | 228 |
| DeepSeek | 52 | 1,612 | 58.99% | 185 |

이 수치는 짧은 입력에서의 캐시 시뮬레이션 결과이며 성능 벤치마크나 SSD 측정값이 아니다. Byte hit 비율은 `hit_bytes / demand_bytes`다. 요청마다 초기화하므로 prefill의 routed plane hit는 0이다.

- [Qwen 요약](qwen_C/traces/prefill_w4_decode_mixed_v1/layer_groups_lru_2147483648B/summary.json)
- [DeepSeek 요약](deepseek_C/traces/prefill_w4_decode_mixed_v1/layer_groups_lru_2147483648B/summary.json)
- [Qwen scale 포함 요약](qwen_C/traces/prefill_w4_decode_mixed_v1/layer_groups_lru_2147483648B_scales_on_demand/summary.json)
- [DeepSeek scale 포함 요약](deepseek_C/traces/prefill_w4_decode_mixed_v1/layer_groups_lru_2147483648B_scales_on_demand/summary.json)

각 모델의 위 요약과 같은 디렉터리에 다음 두 파일이 있다.

| 파일 | 의미 |
|---|---|
| `layer_demands.jsonl` | 레이어 실행에 필요한 전체 plane 집합. DRAM 정책 적용 전 입력 |
| `layer_reads.jsonl` | DRAM miss로 남은 읽기 구간과 hit·eviction·cache byte 기록 |
| `summary.json` | 정책, 단계별 통계, 원본과 출력의 SHA256. 이 파일이 있어야 변환 완료 |
| `validation.json` | 출력 파일을 다시 읽어 캐시 상태·그룹 순서·통계를 독립적으로 확인한 결과. `verify_layer_groups.py`가 만든다 |

이 표는 `validation.json`을 오래 전부터 적어 두었지만 실제로 만드는 코드는 없었다. 그동안
캐시 시뮬레이션은 파이프라인에서 유일하게 검사받지 않는 단계였다. FEMU 카운터 일치는 이
단계를 덮지 못한다. `layer_reads.jsonl`이 mapper의 **입력**이라 캐시가 틀린 항목을 miss로
판정해도 매핑·재생·집계가 그대로 일관되게 따라가기 때문이다. 자기일관성은 정확성이 아니다.

`verify_layer_groups.py`는 쓰여진 파일만 다시 읽어 네 가지를 확인한다.

| 확인 | 내용 |
|---|---|
| 순서 | group id, layer 주기, forward 번호, 요청 경계와 decode 위치를 `layer_reads.jsonl`만으로 재유도 |
| 수요 | `layer_demands.jsonl`과 `layer_reads.jsonl`이 그룹마다 일치 |
| 캐시 | 모든 hit·miss·eviction·점유량을 `online_cache.py`의 `ReferenceLRU`가 재현. 이 구현은 숫자를 쓴 `LayerLRU`와 코드를 공유하지 않는다 |
| 통계 | `summary.json`의 단계별·요청별 합계와 최대 점유량을 그룹 줄에서 다시 누적 |

`ReferenceLRU`가 검사로서 힘이 있는지는 무작위 차등 시험으로 확인했다. 300회 × 120단계
동안 두 구현은 miss 집합·바이트·eviction·recency 순서까지 일치했고, 캐시에 넣은 세 가지
결함(현재 레이어 항목을 evict, 삽입 순서를 item_id 대신 수요 순서로, hit의 recency 미갱신)은
모두 잡혔다.

원본 `logical_trace.jsonl`, `trace_meta.json`, `inputs.json`, `generations.json`, `code/`는 한 단계 위 디렉터리에 있다. token별 선택과 실행 당시 코드까지 확인할 수 있다.

JSONL 한 줄은 `(request, forward, layer)` 하나다. `group_id`와 `release_after_group_id`가 순서를 나타낸다. 새 요청 첫 그룹은 `cache_reset=true`, 이전 그룹 ID는 null이다. 전부 hit인 그룹도 `reads=[]`로 남겨 계산 순서를 보존한다. 각 read의 `file, offset, nbytes`는 원본 payload 파일 구간이며 `item_id`는 projection/plane 식별자다.

## FEMU에 넘기기 전 남은 주소 매핑

원본 `layer_reads.jsonl`은 LBA를 부여하기 전의 DRAM miss trace다. `lba_start`와 `sector_count`는 null, `address_status`는 `unmapped`다. QLC-aligned mapper가 이를 변환한 `layouts/.../mapped_reads.jsonl`에는 LBA와 NVMe command가 들어 있지만, 실제 FEMU replay는 아직 수행하지 않았다.

다음 단계에서 각 SSD 레이아웃의 실제 image extent map을 만든 뒤 원본 파일 구간을 LBA로 변환한다. 이때 sector 크기, 정렬·padding, 요청 분할·병합, 최대 요청 크기를 명시하고 image/layout 체크섬을 연결해야 한다. 원본 offset을 곧바로 LBA로 간주하지 않는다. 하나의 logical read가 여러 NVMe 요청으로 나뉘거나 인접 read와 합쳐질 수 있다. Scale 초기 적재 I/O는 현재 trace에 없으므로 필요하면 별도 초기화 단계로 측정한다.

같은 DRAM 정책과 논리 요청에서 레이아웃만 비교하려면 이 miss trace를 공통 입력으로 쓴다. 페이지 단위 caching이나 layout별 read-ahead로 cache admission이 바뀌는 실험이라면 `layer_demands.jsonl`부터 해당 정책으로 다시 시뮬레이션해야 한다.

## 재현

`packages/`에 `layer_read_groups.py`, `test_layer_groups.py`와 의존 도구 `bundle.py`, `logical_reads.py`를 함께 넣었다. 변환 자체는 CPU와 NumPy만 필요하고 GPU나 체크포인트는 필요 없다. 다른 용량의 예:

```bash
python layer_read_groups.py qwen_C --trace prefill_w4_decode_mixed_v1 --cache-bytes 1073741824
```

제공된 2 GiB 출력은 이미 존재한다. 같은 경로 재실행은 덮어쓰지 않고 실패한다. 현재 레이어의 전체 작업 집합이 용량보다 크면 도구가 실패한다. 그런 용량에서는 먼저 그룹 내 streaming 순서를 정의해야 한다.

캐시 fixture 검증:

```bash
python -m unittest discover -s . -p 'test_layer_groups.py'
```

새 GPU 수집은 원래 저장소의 `collect_trace.py`에 `--mode generate --prefill-policy w4 --window 128 --samples 2 --max-new-tokens 32`를 지정한다. Qwen은 `models/Qwen1.5-MoE-A2.7B`와 `exp/moe_bcq/results/model/qwen_plain4_state.pt`, DeepSeek은 해당 모델 디렉터리와 `exp/moe_bcq/results/model/deepseek_plain4_state.pt`를 사용했다. 수집 정책과 코드·입력 식별자는 `trace_meta.json`, 원본 state 식별자는 manifest에도 기록되어 있다.
