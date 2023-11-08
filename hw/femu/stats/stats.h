#include "../nvme.h"
#include <pthread.h>

// 통계 데이터를 위한 구조체
typedef struct statistics {
    uint64_t read_count;       // 읽기 요청 횟수
    uint64_t write_count;      // 쓰기 요청 횟수
} statistics;

// 통계 데이터를 위한 전역 변수
extern statistics stats;

// 통계 데이터 접근을 위한 뮤텍스
extern pthread_mutex_t stats_mutex;

// 통계 데이터를 업데이트하는 함수들
void increase_read_count(void);

void increase_write_count(void);

void print_and_reset_stats(unsigned long);

void *stats_thread_func(void*);