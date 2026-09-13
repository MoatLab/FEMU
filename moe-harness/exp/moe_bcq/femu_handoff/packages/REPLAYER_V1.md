# Binary trace compiler와 FEMU replayer v1 — 2026-09-09

`mapped_reads.jsonl`은 사람이 주소와 cache 결과를 감사하는 기준 파일이고, `replay_qd32.bin`은 게스트가 재생하는 입력이다. Qwen JSONL 101.6 MB는 2.14 MB, DeepSeek JSONL 124.4 MB는 2.59 MB의 고정 길이 binary record로 줄었다. 두 형식은 binary header의 `mapped_reads_sha256`으로 묶인다.

현재 binary는 실제 C 모델에서 수집한 **WikiText-2 pilot generation trace**를 2 GiB LRU와 QLC-aligned mapper에 통과시킨 결과다. 정식 WikiText-2 전체, GSM8K, MMLU trace는 아니다.

## 포함된 파일

| 파일 | 역할 |
|---|---|
| `trace_compiler.py` | 검증된 layout의 mapped JSONL을 binary로 컴파일하거나 binary를 정적으로 검사 |
| `replay_v1.c` | Linux native AIO로 binary trace를 재생하는 게스트 프로그램 |
| `test_trace_replayer.py` | compiler, O_DIRECT, rolling QD, 빈 그룹 barrier를 검사하는 작은 통합 테스트 |
| `{model}/layouts/.../replay_qd32.bin` | QD=32 기본값을 담은 실제 pilot replay 입력 |
| `replay_qd32.bin.json` | 요청 index 표, 원본 hash, record 크기와 총계 |

replayer는 `linux/aio_abi.h`의 syscall을 직접 사용하므로 `libaio`나 `liburing`에 링크하지 않는다.

## Binary 형식

모든 정수는 little-endian이고 record에는 포인터나 가변 길이 문자열이 없다.

| record | 크기 | 핵심 내용 |
|---|---:|---|
| header | 136 B | magic/version, sector·alignment, 기본 QD, group/command/byte 총계, extent map과 mapped JSONL SHA256 |
| group | 40 B | group ID, 이전 group dependency, request index, forward/layer/phase, cache reset, command 수 |
| command | 16 B | LBA, sector 수, QLC page class |

group record 뒤에 그 group의 command record가 바로 온다. command가 0개인 group도 record를 남긴다. 따라서 DRAM hit로 SSD read가 없어진 레이어도 순서에서 사라지지 않는다. 문자열 `request_id`는 sidecar JSON의 `requests[]`가 `request_index`로 복원한다.

Compiler는 다음을 실패 조건으로 둔다.

- `extent_map.json`, `mapped_reads.jsonl`의 hash가 layout summary와 다름
- `layout_validation.json`이 통과 상태가 아님
- group ID·dependency·command ID가 연속 규칙과 다름
- 4 KiB O_DIRECT 정렬, 512 B sector, 4 MiB 최대 command 규칙 위반
- JSONL과 layout summary의 group·command·byte 총계 불일치

## 컴파일과 정적 검사

전달 폴더 `packages/`에서 실행한다. 제공된 output은 이미 있으므로 재생성할 때는 새 이름을 쓴다.

```bash
python trace_compiler.py compile \
  qwen_C/layouts/qlc_aligned_epm_aif_2ch4lun \
  --output qwen_C/layouts/qlc_aligned_epm_aif_2ch4lun/replay_check.bin \
  --queue-depth 32

python trace_compiler.py inspect \
  qwen_C/layouts/qlc_aligned_epm_aif_2ch4lun/replay_qd32.bin
```

게스트에서 replayer를 빌드하고 trace만 먼저 검사한다.

```bash
cc -O2 -std=c11 -Wall -Wextra -Werror -o replay_v1 replay_v1.c

./replay_v1 \
  --trace qwen_C/layouts/qlc_aligned_epm_aif_2ch4lun/replay_qd32.bin \
  --dry-run
```

Qwen은 1,536 groups, 130,090 commands, 22,608,650,240 requested bytes이고 DeepSeek은 1,664 groups, 157,515 commands, 27,372,060,672 bytes여야 한다.

## Image 적재와 실제 replay

먼저 payload와 filler를 합친 image를 생성한다. 이 파일은 패키지에 미리 넣지 않았다.

```bash
python qlc_aligned_mapper.py materialize qwen_C \
  qwen_C/layouts/qlc_aligned_epm_aif_2ch4lun \
  --image qwen_C.img
```

요청한 FEMU geometry와 patched 512-row pairing으로 새 장치를 부팅한다. namespace를 마운트하지 않고 LBA 0부터 image 끝까지 한 번의 순차 stream으로 적재한다.

```bash
sudo dd if=qwen_C.img of=/dev/nvme0n1 bs=256K \
  iflag=fullblock oflag=direct conv=fsync status=progress
```

2026-09-09 실장 검증에서 기존 `bs=4M` fill이 NAND page 중간에서 분할되어 같은 LPN을 두 번 프로그램하고 PPA 순서를 밀어내는 현상이 확인됐다. 따라서 fill 크기를 256 KiB로 수정했다. 관측된 guest는 4 KiB 메모리 page, `max_segments=127`이며 256 KiB는 page-aligned buffer에서 64개 메모리 page다. 이 설정에서 여유를 둔 크기이지 모든 장치에서 무분할을 보장하는 상수는 아니다. `getconf PAGESIZE`와 queue의 `max_segments`, `max_segment_size`, `max_sectors_kb`, `max_hw_sectors_kb`를 기록하고 실제 program 순서를 확인한다. `max_sectors_kb=4096`만으로 무분할을 판정하지 않는다.

적재 전후에 다른 host write가 없어야 한다. 최종 device command도 NAND page 경계에서 나뉘고 각 LPN이 정확히 한 번씩 program되어야 mapper의 순차 배치 가정이 성립한다. WRITE log의 LPN→PPA class와 image read-back을 각각 확인한 다음 replay한다. byte hash 일치는 page class 일치를 보장하지 않는다. output 파일은 덮어쓰지 않으므로 run마다 새 디렉터리나 이름을 사용한다.

```bash
sudo ./replay_v1 \
  --trace qwen_C/layouts/qlc_aligned_epm_aif_2ch4lun/replay_qd32.bin \
  --device /dev/nvme0n1 --controller /dev/nvme0 \
  --qd 32 \
  --group-log run01.groups.jsonl \
  --summary run01.summary.json
```

기본 동작은 O_DIRECT다. `--buffered`는 작은 개발용 파일에만 쓰는 fallback이다.
`--skip-qlc-counters`는 stock NVMe나 unit test용이며 논문 측정에서는 쓰지 않는다. 기본
실행은 vendor admin command `0xef/cdw10=8`로 적재 후 QLC counter를 초기화한다.

각 group은 barrier이므로 phase가 바뀌는 시점에는 직전 phase의 I/O가 모두 완료되어 있다.
replayer는 이 경계와 replay 끝에서 `cdw10=10/11/12`를 보내 직전 physical-counter 차분을
각각 prefill/decode/teacher-forced bank에 누적한 후, 마지막에 `cdw10=9`로 snapshot한다.
요청마다 `prefill→decode`가 반복돼도 각 bank에 합산된다.

최종 CSV의 기존 total 열 뒤에는 phase별 `n_read`, `bytes_read`, `e_nand_uj`가 추가된다.
모든 class에서 `total = prefill + decode + teacher_forced`가 성립해야 한다. 명령 중 하나라도
실패하면 run을 실패 처리한다. plain FEMU가 알 수 없는 selector를 성공으로 돌려줄 수 있으므로
실행 스크립트에서도 phase 열과 위 closure를 검사해야 한다.

## 제출과 timestamp 의미

그룹 사이에는 strict barrier가 있다. 이전 그룹의 모든 command가 완료된 뒤 다음 그룹으로 이동한다. 그룹 안에서는 outstanding read를 최대 QD까지 채우고, 하나 이상 완료될 때마다 다시 채우는 rolling QD를 쓴다. QD=32는 동시에 완료되는 수가 아니라 host가 아직 completion을 받지 않은 command의 상한이다.

`group-log`의 시간은 `CLOCK_MONOTONIC_RAW`이며 replay 시작을 0으로 둔다.

| 필드 | 의미 |
|---|---|
| `group_ready_ns` | command record를 읽어 준비했고 이전 barrier도 끝난 시점 |
| `first_submit_ns` | 첫 `io_submit` 호출 직전 |
| `last_submit_ns` | 마지막 `io_submit`가 반환된 직후 |
| `last_complete_ns` | 마지막 completion을 `io_getevents`에서 관찰한 시점 |
| `group_io_ns` | 첫 submit 직전부터 마지막 completion 관찰까지 |
| `peak_outstanding` | 실제 host-side 최대 outstanding command 수 |

빈 그룹은 submit 시점이 `null`이고 `group_io_ns=0`이다. `summary`의 `sum_group_io_ns`를 SSD service 구간 합으로 사용한다. `wall_ns_including_log_overhead`에는 binary 해석과 group JSON 기록 비용도 들어간다.

`--io-log`는 command별 submit과 completion 관찰 시점을 남기는 진단 옵션이다. 한 번의 `io_getevents`로 여러 completion을 받으면 같은 관찰 timestamp가 기록되며 실제 device completion 순간과는 다를 수 있다. 이 로그 자체도 timing을 교란하므로 주 측정에는 group log만 사용한다.

group log는 제공된 pilot 전체가 메모리 buffer에 머물도록 4 MiB buffering한 뒤 replay 후 flush한다. 그래도 결과 파일은 측정 대상 namespace가 아닌 root disk나 `/dev/shm`에 둔다. target namespace에 로그를 쓰면 순차 적재 계약과 QLC counter가 모두 오염된다.

## 검증 범위

로컬 fixture에서 C11 `-Werror` 빌드, binary dry-run, 실제 O_DIRECT native-AIO read, QD=2 rolling 제출, 빈 그룹 barrier, 총 command/byte 보존을 검사했다. 실제 Qwen과 DeepSeek binary도 Python inspector와 C preflight를 모두 통과했다.

FEMU에서는 먼저 class가 알려진 작은 LBA 집합을 fio와 replayer에서 QD=1/4/32로 각각 읽어 bytes, command 수, group makespan, QLC counter가 맞는지 교차 확인해야 한다. 현재 패키지에는 **FEMU에서 얻은 latency 결과가 아직 없다.**
