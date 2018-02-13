// File: firm_buffer_manager.h
// Date: 2014. 12. 03.
// Author: Jinsoo Yoo (jedisty@hanyang.ac.kr)
// Copyright(c)2014
// Hanyang University, Seoul, Korea
// Embedded Software Systems Laboratory. All right reserved

#ifndef _SSD_BUFFER_MANAGER_H_
#define _SSD_BUFFER_MANAGER_H_

#ifdef SSD_THREAD
extern int r_queue_full;
extern int w_queue_full;
extern pthread_cond_t eq_ready;
extern pthread_mutex_t eq_lock;
extern pthread_mutex_t cq_lock;
#endif

typedef struct event_queue_entry
{
	int io_type;
	int valid;
	int64_t sector_nb;
	unsigned int length;
	void* buf;
	struct event_queue_entry* next;
}event_queue_entry;

typedef struct event_queue
{
	int entry_nb;
	event_queue_entry* head;
	event_queue_entry* tail;
}event_queue;

void INIT_IO_BUFFER(void);
void TERM_IO_BUFFER(void);
void INIT_WB_VALID_ARRAY(void);

void *SSD_THREAD_MAIN_LOOP(void *arg);
void ENQUEUE_IO(int io_type, int64_t sector_nb, unsigned int length);
void ENQUEUE_READ(int64_t sector_nb, unsigned int length);
void ENQUEUE_WRITE(int64_t sector_nb, unsigned int length);

void DEQUEUE_IO(void);
void DEQUEUE_COMPLETED_READ(void);

event_queue_entry* ALLOC_NEW_EVENT(int io_type, int64_t sector_nb, unsigned int length, void* buf);

void WRITE_DATA_TO_BUFFER(unsigned int length);
void READ_DATA_FROM_BUFFER_TO_HOST(event_queue_entry* c_e_q_entry);
void COPY_DATA_TO_READ_BUFFER(event_queue_entry* dst_entry, event_queue_entry* src_entry);
void FLUSH_EVENT_QUEUE_UNTIL(event_queue_entry* e_q_entry);

int EVENT_QUEUE_IS_FULL(int io_type, unsigned int length);
void SECURE_WRITE_BUFFER(void);
void SECURE_READ_BUFFER(void);

/* Check Event */
int CHECK_OVERWRITE(event_queue_entry* e_q_entry, int64_t sector_nb, unsigned int length);
int CHECK_SEQUENTIALITY(event_queue_entry* e_q_entry, int64_t sector_nb);
event_queue_entry* CHECK_IO_DEPENDENCY_FOR_READ(int64_t sector_nb, unsigned int length);
int CHECK_IO_DEPENDENCY_FOR_WRITE(event_queue_entry* e_q_entry, int64_t sector_nb, unsigned int length);

/* Manipulate Write Buffer Valid Array */
char GET_WB_VALID_ARRAY_ENTRY(void* buffer_pointer);
void UPDATE_WB_VALID_ARRAY(event_queue_entry* e_q_entry, char new_value);
void UPDATE_WB_VALID_ARRAY_ENTRY(void* buffer_pointer, char new_value);
void UPDATE_WB_VALID_ARRAY_PARTIAL(event_queue_entry* e_q_entry, char new_value, int length, int mode);

/* Move Buffer Frame Pointer */
void INCREASE_WB_SATA_POINTER(int entry_nb);
void INCREASE_RB_SATA_POINTER(int entry_nb);
void INCREASE_WB_FTL_POINTER(int entry_nb);
void INCREASE_RB_FTL_POINTER(int entry_nb);
void INCREASE_WB_LIMIT_POINTER(void);
void INCREASE_RB_LIMIT_POINTER(void);

/* Test IO BUFFER */
int COUNT_READ_EVENT(void);

#endif
