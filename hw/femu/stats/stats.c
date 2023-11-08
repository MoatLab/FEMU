#include "../nvme.h"
#include "./stats.h"

statistics stats = {0};
pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;

// 통계 데이터를 출력하고 리셋하는 함수
void print_and_reset_stats(unsigned long seconds) {
    pthread_mutex_lock(&stats_mutex);
    // 통계 데이터 출력
    printf("[%lu sec] Read Count: %lu, Write Count: %lu\r\n", 
           seconds, stats.read_count, stats.write_count);
    // 통계 데이터 리셋
    memset(&stats, 0, sizeof(stats));
    pthread_mutex_unlock(&stats_mutex);
}

// 1초마다 통계를 출력하고 초기화하는 스레드 함수
void *stats_thread_func(void *arg) {
    unsigned long elapsed_seconds = 0;  // 경과 시간
    while (1) {
        sleep(1); // 1초 대기
        print_and_reset_stats(++elapsed_seconds); // 통계 출력 및 초기화
    }
    return NULL;
}

void increase_read_count(void) {
    pthread_mutex_lock(&stats_mutex);
    stats.read_count++;
    pthread_mutex_unlock(&stats_mutex);
}

void increase_write_count(void) {
    pthread_mutex_lock(&stats_mutex);
    stats.write_count++;
    pthread_mutex_unlock(&stats_mutex);
}