# QLC-aligned expert plane-major mapper v1 — 2026-09-09

이 산출물은 C arm(일반 4-bit BCQ, 공유 `alpha_4` prefix, MRE 없음)의 routed expert plane과 scale을 QLC page class에 맞춘 LBA 주소표다. 아직 FEMU 장치에 적재하거나 latency를 측정하지 않았다.

## 고정한 FEMU geometry

```text
sector_bytes       = 512
sectors_per_page   = 32       # 16 KiB
pages_per_block    = 512      # patched pairing table 필수
blocks_per_plane   = 1024
planes_per_lun     = 1
luns_per_channel   = 4
channels           = 2       # 총 8 LUN
op_percent         = 7
nand_cell_type     = 4
gc_threshold       = 75
```

Raw capacity는 64 GiB이고 명목상 7% OP 적용 후 공간은 약 59.52 GiB다. 실제 FEMU가 노출하는 namespace 크기는 부팅 후 반드시 확인한다.

이 mapper는 수정된 512-row QLC pairing을 전제로 한다. pg 0–5는 class 0, pg 6–7은 class 1인 특수 prologue라 사용하지 않는다. pg 8–511에서는 다음 주기가 반복되어야 한다.

```text
page index mod 8:  0 1 2 3 4 5 6 7
QLC class:         0 0 1 1 2 2 3 3
```

원본 FEMU의 `rows-1` 문제를 고치지 않으면 pg 496–511이 class 0으로 남는다. 이 상태에서는 mapper 예측과 실제 장치가 다르므로 실험하면 안 된다.

## Plane과 scale 배치

배치 순서는 `layer → expert → tier → gate/up/down`이고, 대응은 다음과 같다.

| 정밀도 구성요소 | QLC class |
|---|---:|
| B1와 alpha1 | 0 |
| B2와 alpha2 | 1 |
| B3와 alpha3 | 2 |
| B4와 alpha4 | 3 |

여기서 alpha1은 별도 최적화된 scale 세트가 아니라 공유 `alpha_4`의 첫 번째 column이다. Wp는 B1…Bp와 `alpha_4` column 1…p를 요구한다.

총 8 LUN에서 class 하나의 slot은 `2 pages × 8 LUN = 16 LPN`이다. 현재 expert 한 개의 tier별 크기는 다음과 같다.

```text
gate/up/down plane = 22 + 22 + 22 = 66 pages
gate/up/down scale = ceil(2.75) × 3 = 9 allocated pages
합계               = 75 pages
필요한 class cycle = ceil(75 / 16) = 5
```

따라서 한 expert는 5개의 8-page pairing cycle, 즉 `5 × 8 page-index × 8 LUN = 320 LPN = 5 MiB`의 주소 공간을 사용한다. 각 tier의 자료는 같은 다섯 cycle에서 대응되는 class slot에 놓인다. 66-page plane은 같은 class의 여러 slot으로 나뉘므로 한 logical item이 `extent_map.json`에서 여러 fragment를 가질 수 있다.

Scale extent 하나는 45,056 B로 sector에는 정확히 맞지만 NAND page에는 맞지 않는다. 각 projection scale column을 page 경계에서 시작하도록 3 pages를 할당하고 마지막 4 KiB는 filler로 둔다. 실제 read는 유효한 45,056 B만 요청한다.

## 생성 결과

| 모델 | 실제 plane+scale | 순차 image 크기 | filler | payload 비율 |
|---|---:|---:|---:|---:|
| Qwen | 7,007,109,120 B | 7,717,519,360 B (7.19 GiB) | 710,410,240 B | 90.79% |
| DeepSeek | 8,097,103,872 B | 8,925,478,912 B (8.31 GiB) | 828,375,040 B | 90.72% |

- [Qwen layout summary](qwen_C/layouts/qlc_aligned_epm_aif_2ch4lun/layout_summary.json)
- [DeepSeek layout summary](deepseek_C/layouts/qlc_aligned_epm_aif_2ch4lun/layout_summary.json)

각 layout 디렉터리에는 다음 파일이 있다.

| 파일 | 역할 |
|---|---|
| `extent_map.json` | 전체 plane·scale item의 원본 구간, target LPN/LBA, fragment와 목표 class |
| `mapped_reads.jsonl` | 2 GiB LRU miss를 LBA로 바꾼 레이어 그룹과 병합된 NVMe command |
| `layout_summary.json` | geometry, 용량, 입력·출력 SHA256, QD=32 권장값 |
| `layout_validation.json` | catalog·fragment·class·주소 중복·trace byte 보존 검증 결과 |
| `replay_qd32.bin` | strict group barrier와 QD=32 기본값을 담은 compact replay 입력 |
| `replay_qd32.bin.json` | binary hash, 원본 hash, record 총계와 request index 표 |

현재 mapped trace는 plane과 scale column이 **같은 2 GiB LRU cache를 공유**한 결과를 사용한다.

```text
traces/prefill_w4_decode_mixed_v1/
  layer_groups_lru_2147483648B_scales_on_demand/
```

Mapper는 같은 class에서 LBA가 바로 이어진 fragment만 최대 4 MiB까지 하나의 command로 병합한다. 서로 다른 class를 가로질러 병합하지 않는다. Replayer는 이 command에 QD=32를 적용한다. 게스트의 실제 최대 request 크기가 4 MiB보다 작으면 block layer가 다시 나눌 수 있으므로 `max_sectors_kb`와 실제 NVMe command 수를 기록해야 한다.

Binary 생성과 실제 실행 방법, rolling QD와 timestamp 의미는 [REPLAYER_V1.md](REPLAYER_V1.md)를 따른다.

## 도구 사용

주소표와 mapped trace 생성:

```bash
python qlc_aligned_mapper.py plan qwen_C \
  --layer-reads qwen_C/traces/prefill_w4_decode_mixed_v1/layer_groups_lru_2147483648B_scales_on_demand/layer_reads.jsonl \
  --output qwen_C/layouts/qlc_aligned_epm_aif_2ch4lun
```

검증:

```bash
python qlc_aligned_mapper.py validate qwen_C \
  --layer-reads qwen_C/traces/prefill_w4_decode_mixed_v1/layer_groups_lru_2147483648B_scales_on_demand/layer_reads.jsonl \
  qwen_C/layouts/qlc_aligned_epm_aif_2ch4lun
```

실제 image가 필요할 때만 materialize한다. 제공된 package에는 image가 없다.

```bash
python qlc_aligned_mapper.py materialize qwen_C \
  qwen_C/layouts/qlc_aligned_epm_aif_2ch4lun --image qwen_C.img
```

생성된 image는 filler를 포함한다. FEMU 재시작 직후 host write가 0인지 확인한 다음, **LPN 0부터 끝까지 빠짐없이 순차 write**해야 한다. 최종 device command의 분할 경계도 16 KiB NAND page에 정렬되어야 한다. page 중간에서 나뉘면 같은 LPN이 두 번 program되어 후속 PPA가 밀릴 수 있다. 현재 guest에서는 `dd bs=256K`로 적재한다. 기존 `bs=4M`은 이 조건을 보장하지 못했다. queue 제한과 적재 후 FEMU WRITE 로그의 LPN→PPA class 규칙을 검증하고, 데이터를 되읽어 원본 SHA와 별도로 비교한 뒤 replay한다.

## 아직 측정되지 않은 것

- FEMU에서 실제 PPA/page class 일치 여부
- materialized image의 byte-for-byte read-back
- QD=32 replay의 제출·완료 timestamp와 latency
- OS/NVMe 계층의 실제 요청 split·merge
- GPU 전송 및 BCQ 연산을 포함한 end-to-end latency

따라서 현재 결과는 **검증된 주소 계획과 replay 입력**이며 FEMU 성능 결과가 아니다.
