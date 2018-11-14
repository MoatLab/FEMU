// File: firm_buffer_manager.c
// Date: 2014. 12. 03.
// Author: Jinsoo Yoo (jedisty@hanyang.ac.kr)
// Copyright(c)2014
// Hanyang University, Seoul, Korea
// Embedded Software Systems Laboratory. All right reserved

#include "common.h"
#include <pthread.h>

#if 0

event_queue* e_queue;
event_queue* c_e_queue;

/* Global Variable for IO Buffer */
void* write_buffer;
void* read_buffer;
void* write_buffer_end;
void* read_buffer_end;

/* Globale Variable for Valid array */
char* wb_valid_array;

/* Pointers for Write Buffer */
void* ftl_write_ptr;
void* sata_write_ptr;
void* write_limit_ptr;

/* Pointers for Read Buffer */
void* ftl_read_ptr;
void* sata_read_ptr;
void* read_limit_ptr;
event_queue_entry* last_read_entry;

int empty_write_buffer_frame;
int empty_read_buffer_frame;

#ifdef SSD_THREAD
int r_queue_full = 0;
int w_queue_full = 0;
pthread_t ssd_thread_id;
pthread_cond_t eq_ready = PTHREAD_COND_INITIALIZER;
pthread_mutex_t eq_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t cq_lock = PTHREAD_MUTEX_INITIALIZER;
#endif

//TEMPs
int temp_count1 = 0;
int64_t temp_count2 = 0;
//TEMPe

void INIT_IO_BUFFER(void)
{
	/* Allocation event queue structure */
	e_queue = (event_queue*)calloc(1, sizeof(event_queue));
	if(e_queue == NULL){
		printf("ERROR [%s] Allocation event queue fail.\n",__FUNCTION__);
		return;
	}
	else{	/* Initialization event queue structure */
		e_queue->entry_nb = 0;
		e_queue->head = NULL;
		e_queue->tail = NULL;
	}

	/* Initialization valid array of event queue */
	INIT_WB_VALID_ARRAY();

	/* Allocation completed event queue structure */
	c_e_queue = (event_queue*)calloc(1, sizeof(event_queue));
	if(c_e_queue == NULL){
		printf("ERROR [%s] Allocation completed event queue fail.\n",__FUNCTION__);
		return;
	}
	else{	/* Initialization event queue structure */
		c_e_queue->entry_nb = 0;
		c_e_queue->head = NULL;
		c_e_queue->tail = NULL;
	}

	/* Allocation Write Buffer in DRAM */
	write_buffer = (void*)calloc(WRITE_BUFFER_FRAME_NB, SECTOR_SIZE);
	write_buffer_end = write_buffer + WRITE_BUFFER_FRAME_NB*SECTOR_SIZE;	

	/* Allocation Read Buffer in DRAM */
	read_buffer = (void*)calloc(READ_BUFFER_FRAME_NB, SECTOR_SIZE);
	read_buffer_end = read_buffer + READ_BUFFER_FRAME_NB*SECTOR_SIZE;	

	if(write_buffer == NULL || read_buffer == NULL){
		printf("ERROR [%s] Allocation IO Buffer Fail.\n",__FUNCTION__);
		return;
	}
	
	/* Initialization Buffer Pointers */
	ftl_write_ptr = write_buffer;
	sata_write_ptr = write_buffer;
	write_limit_ptr = write_buffer;

	ftl_read_ptr = read_buffer;
	sata_read_ptr = read_buffer;
	read_limit_ptr = read_buffer;
	last_read_entry = NULL;

	/* Initialization Other Global Variable */
	empty_write_buffer_frame = WRITE_BUFFER_FRAME_NB;
	empty_read_buffer_frame = READ_BUFFER_FRAME_NB; 

#ifdef SSD_THREAD
	pthread_create(&ssd_thread_id, NULL, SSD_THREAD_MAIN_LOOP, NULL);
    printf("Creating SSD Main Loop Thread ..\n");
    sleep(5);
#endif
}

void TERM_IO_BUFFER(void)
{
	/* Flush all event in event queue */
	FLUSH_EVENT_QUEUE_UNTIL(e_queue->tail);

	/* Deallocate Buffer & Event queue */
	free(write_buffer);
	free(read_buffer);
	free(e_queue);
	free(c_e_queue);
}

void INIT_WB_VALID_ARRAY(void)
{
	int i;
	wb_valid_array = (char*)calloc(WRITE_BUFFER_FRAME_NB , sizeof(char));
	if(wb_valid_array == NULL){
		printf("[%s] Calloc write buffer valid array fail. \n",__FUNCTION__);
		return;
	}

	for(i=0;i<WRITE_BUFFER_FRAME_NB;i++){
		wb_valid_array[i] = '0';
	}
}

#ifdef SSD_THREAD
void *SSD_THREAD_MAIN_LOOP(void *arg)
{
	while(1){
		pthread_mutex_lock(&eq_lock);

#if defined SSD_THREAD_MODE_1
		while(e_queue->entry_nb == 0){
#ifdef SSD_THREAD_DEBUG
			printf("[%s] wait signal..\n",__FUNCTION__);
#endif
			pthread_cond_wait(&eq_ready, &eq_lock);
		}
#ifdef SSD_THREAD_DEBUG
		printf("[%s] Get up! \n",__FUNCTION__);
#endif
		DEQUEUE_IO();
#elif defined SSD_THREAD_MODE_2
		while(r_queue_full == 0 && w_queue_full == 0){
			pthread_cond_wait(&eq_ready, &eq_lock);
		}
		if(r_queue_full == 1){
			SECURE_READ_BUFFER();
			r_queue_full = 0;
		}
		else if(w_queue_full == 1){
			SECURE_WRITE_BUFFER();
			w_queue_full = 0;
		}
		else{
			printf("ERROR[%s] Wrong signal \n",__FUNCTION__);
		}
#endif

		pthread_mutex_unlock(&eq_lock);
	}
}
#endif

void ENQUEUE_IO(int io_type, int64_t sector_nb, unsigned int length)
{
#ifdef FIRM_IO_BUF_DEBUG
	printf("[%s] Start.\n",__FUNCTION__);
#endif

#ifdef GET_FIRM_WORKLOAD
	FILE* fp_workload = fopen("./data/workload_firm.txt","a");
	struct timeval tv;
	struct tm *lt;
	double curr_time;
	gettimeofday(&tv, 0);
	lt = localtime(&(tv.tv_sec));
	curr_time = lt->tm_hour*3600 + lt->tm_min*60 + lt->tm_sec + (double)tv.tv_usec/(double)1000000;
	if(io_type == READ){
		fprintf(fp_workload,"%lf %d %u %x R\n",curr_time, sector_nb, length, 1);
	}
	else if(io_type == WRITE){
		fprintf(fp_workload,"%lf %d %u %x W\n",curr_time, sector_nb, length, 0);
	}
	fclose(fp_workload);
#endif

/* Check event queue depth */
#ifdef GET_QUEUE_DEPTH
	FILE* fp_workload = fopen("./data/queue_depth.txt","a");
        struct timeval tv;
        struct tm *lt;
        double curr_time;
        gettimeofday(&tv, 0);
        lt = localtime(&(tv.tv_sec));
        curr_time = lt->tm_hour*3600 + lt->tm_min*60 + lt->tm_sec + (double)tv.tv_usec/(double)1000000;
        
	int n_read_event = COUNT_READ_EVENT();
	int n_write_event = e_queue->entry_nb - n_read_event;
	if(io_type == READ)
		fprintf(fp_workload,"%lf\tR\t%d\t%d\t%d\t%d\t%u\n",curr_time, e_queue->entry_nb, n_read_event, n_write_event, sector_nb, length);
	else if(io_type == WRITE)
		fprintf(fp_workload,"%lf\tW\t%d\t%d\t%d\t%d\t%u\n",curr_time, e_queue->entry_nb, n_read_event, n_write_event, sector_nb, length);

        fclose(fp_workload);
#endif

	if(io_type == READ){
		ENQUEUE_READ(sector_nb, length);
	}
	else if(io_type == WRITE){
		ENQUEUE_WRITE(sector_nb, length);
	}
	else{
		printf("ERROR[%s] Wrong IO type.\n", __FUNCTION__);
	}

#ifdef FIRM_IO_BUF_DEBUG
	printf("[%s] End.\n",__FUNCTION__);
#endif
}

void DEQUEUE_IO(void)
{
#ifdef FIRM_IO_BUF_DEBUG
	printf("[%s] Start.\n",__FUNCTION__);
#endif
	if(e_queue->entry_nb == 0 || e_queue->head == NULL){
		printf("ERROR[%s] There is no event. \n", __FUNCTION__);
		return;
	}

	event_queue_entry* e_q_entry = e_queue->head;

	int io_type = e_q_entry->io_type;
	int valid = e_q_entry->valid;
	int64_t sector_nb = e_q_entry->sector_nb;
	unsigned int length = e_q_entry->length;
	void* buf = e_q_entry->buf;

	/* Deallocation event queue entry */
	e_queue->entry_nb--;
	if(e_queue->entry_nb == 0){
		e_queue->head = NULL;
		e_queue->tail = NULL;
	}
	else{
		e_queue->head = e_q_entry->next;
	}

	if(e_q_entry->io_type == WRITE){
		free(e_q_entry);
	}
	else{
		if(e_q_entry == last_read_entry){
			last_read_entry = NULL;
		}
	}

	if(valid == VALID){	

		/* Call FTL Function */
		if(io_type == READ){
			if(buf != NULL){
				/* The data is already read from write buffer */
			}
			else{
				/* Allocate read pointer */
				e_q_entry->buf = ftl_read_ptr;

				FTL_READ(sector_nb, length);
			}
		}
		else if(io_type == WRITE){
			FTL_WRITE(sector_nb, length);
		}
		else{
			printf("ERROR[%s] Invalid IO type. \n",__FUNCTION__);
		}
	}

#ifdef SSD_THREAD
	pthread_mutex_lock(&cq_lock);
#endif
	if(io_type == READ){
		/* Move event queue entry to completed event queue */
		e_q_entry->next = NULL;
		if(c_e_queue->entry_nb == 0){
			c_e_queue->head = e_q_entry;
			c_e_queue->tail = e_q_entry;
		}
		else{
			c_e_queue->tail->next = e_q_entry;
			c_e_queue->tail = e_q_entry;
		}
		c_e_queue->entry_nb++;
	}

#ifdef SSD_THREAD
	pthread_mutex_unlock(&cq_lock);
#endif

#ifdef FIRM_IO_BUF_DEBUG
	printf("[%s] End.\n",__FUNCTION__);
#endif
}

void DEQUEUE_COMPLETED_READ(void)
{
#ifdef FIRM_IO_BUF_DEBUG
	printf("[%s] Start.\n",__FUNCTION__);
#endif
	
	if(c_e_queue->entry_nb == 0 || c_e_queue->head == NULL){
#ifdef FIRM_IO_BUF_DEBUG
		printf("[%s] There is no completed read event. \n",__FUNCTION__);
#endif
		return;
	}

	event_queue_entry* c_e_q_entry = c_e_queue->head;
	event_queue_entry* temp_c_e_q_entry = NULL;

#ifdef FIRM_IO_BUF_DEBUG
	printf("[%s] entry number %d\n",__FUNCTION__, c_e_queue->entry_nb);
#endif

	while(c_e_q_entry != NULL){

		/* Read data from buffer to host */
		READ_DATA_FROM_BUFFER_TO_HOST(c_e_q_entry);

		/* Remove completed read IO from queue */
		temp_c_e_q_entry = c_e_q_entry;
		c_e_q_entry = c_e_q_entry->next;

		/* Update completed event queue data */
		c_e_queue->entry_nb--;

		/* Deallication completed read IO */
		free(temp_c_e_q_entry);
	}

	if(c_e_queue->entry_nb != 0){
		printf("ERROR[%s] The entry number should be 0.\n",__FUNCTION__);
	}
	else{
		c_e_queue->head = NULL;
		c_e_queue->tail = NULL;
	}

#ifdef FIRM_IO_BUF_DEBUG
	printf("[%s] End.\n",__FUNCTION__);
#endif
}

void ENQUEUE_READ(int64_t sector_nb, unsigned int length)
{
#ifdef FIRM_IO_BUF_DEBUG
	printf("[%s] Start.\n",__FUNCTION__);
#endif
	void* p_buf = NULL;
	event_queue_entry* ret_e_q_entry = NULL;
	event_queue_entry* new_e_q_entry = NULL;
	event_queue_entry* temp_e_q_entry = calloc(1, sizeof(event_queue_entry));

	/* Make New Read Event */
	new_e_q_entry = ALLOC_NEW_EVENT(READ, sector_nb, length, p_buf);

	if(e_queue->entry_nb == 0){
		e_queue->head = new_e_q_entry;
		e_queue->tail = new_e_q_entry;
		last_read_entry = new_e_q_entry;
	}
	else{
		ret_e_q_entry = CHECK_IO_DEPENDENCY_FOR_READ(sector_nb, length);

		if(ret_e_q_entry != NULL){

			temp_e_q_entry->sector_nb = ret_e_q_entry->sector_nb;
			temp_e_q_entry->length = ret_e_q_entry->length;
			temp_e_q_entry->buf = ret_e_q_entry->buf;

			/* If the data can be read from write buffer, */
			FLUSH_EVENT_QUEUE_UNTIL(ret_e_q_entry);

			if(temp_e_q_entry->sector_nb <= sector_nb && \
				(sector_nb + length) <= (temp_e_q_entry->sector_nb + temp_e_q_entry->length)){

				new_e_q_entry->buf = ftl_read_ptr;
				COPY_DATA_TO_READ_BUFFER(new_e_q_entry, temp_e_q_entry);
			}

			ret_e_q_entry = NULL;
		}	

		/* If there is no read event */
		if(last_read_entry == NULL){
			if(e_queue->entry_nb == 0){
				e_queue->head = new_e_q_entry;
				e_queue->tail = new_e_q_entry;
			}
			else{
				new_e_q_entry->next = e_queue->head;
				e_queue->head = new_e_q_entry;
			}
		}
		else{
			if(last_read_entry == e_queue->tail){
				e_queue->tail->next = new_e_q_entry;
				e_queue->tail = new_e_q_entry;
			}
			else{
				new_e_q_entry->next = last_read_entry->next;
				last_read_entry->next = new_e_q_entry;
			}
		}
		last_read_entry = new_e_q_entry;
	}
	e_queue->entry_nb++;


	/* Update empry read buffer frame number */
	empty_read_buffer_frame -= length;

	free(temp_e_q_entry);
#ifdef FIRM_IO_BUF_DEBUG
	printf("[%s] End.\n",__FUNCTION__);
#endif
}

void ENQUEUE_WRITE(int64_t sector_nb, unsigned int length)
{
#ifdef FIRM_IO_BUF_DEBUG
	printf("[%s] Start.\n",__FUNCTION__);
#endif
	event_queue_entry* e_q_entry;
	event_queue_entry* new_e_q_entry = NULL;

	void* p_buf = NULL;
	int invalid_len;

	int flag_allocated = 0;

	/* Write SATA data to write buffer */
	p_buf = sata_write_ptr;
	WRITE_DATA_TO_BUFFER(length);

	if(last_read_entry != NULL)
		e_q_entry = last_read_entry->next;
	else
		e_q_entry = e_queue->head;

	/* Check pending write event */
	while(e_q_entry != NULL){

		/* Check if there is overwrited event */
		if(e_q_entry->valid == VALID && CHECK_OVERWRITE(e_q_entry, sector_nb, length)==SUCCESS){
			
			/* Update event entry validity */
			e_q_entry->valid = INVALID;

			/* Update write buffer valid array */
			UPDATE_WB_VALID_ARRAY(e_q_entry, 'I');
		}

		e_q_entry = e_q_entry->next;
	}
	
	/* Check if the event is prior sequential event */
	if(CHECK_SEQUENTIALITY(e_queue->tail, sector_nb)==SUCCESS){
		/* Update the last write event */
		e_queue->tail->length += length;

		/* Do not need to allocate new event */
		flag_allocated = 1;
	}
	else if(CHECK_IO_DEPENDENCY_FOR_WRITE(e_queue->tail, sector_nb, length)==SUCCESS){
				
		/* Calculate Overlapped length */
		invalid_len = e_queue->tail->sector_nb + e_queue->tail->length - sector_nb;

		/* Invalidate the corresponding write buffer frame */
		UPDATE_WB_VALID_ARRAY_PARTIAL(e_queue->tail, 'I', invalid_len, 1);

		/* Update the last write event */
		e_queue->tail->length += (length - invalid_len);			

		/* Do not need to allocate new event */
		flag_allocated = 1;
	}

	/* If need to allocate new event */
	if(flag_allocated == 0){
		/* Allocate new event at the tail of the event queue */
		new_e_q_entry = ALLOC_NEW_EVENT(WRITE, sector_nb, length, p_buf);	

		/* Add New IO event entry to event queue */
		if(e_queue->entry_nb == 0){
			e_queue->head = new_e_q_entry;
			e_queue->tail = new_e_q_entry;
		}
		else{
			e_queue->tail->next = new_e_q_entry;
			e_queue->tail = new_e_q_entry;
		}
		e_queue->entry_nb++;
	}

#ifdef FIRM_IO_BUF_DEBUG
	printf("[%s] End.\n",__FUNCTION__);
#endif
}

event_queue_entry* ALLOC_NEW_EVENT(int io_type, int64_t sector_nb, unsigned int length, void* buf)
{
#ifdef FIRM_IO_BUF_DEBUG
	printf("[%s] Start.\n",__FUNCTION__);
#endif
	event_queue_entry* new_e_q_entry = calloc(1, sizeof(event_queue_entry));
	if(new_e_q_entry == NULL){
		printf("[%s] Allocation new event fail.\n", __FUNCTION__);
		return NULL;
	}

	new_e_q_entry->io_type = io_type;
	new_e_q_entry->valid = VALID;
	new_e_q_entry->sector_nb = sector_nb;
	new_e_q_entry->length = length;
	new_e_q_entry->buf = buf;
	new_e_q_entry->next = NULL;

#ifdef FIRM_IO_BUF_DEBUG
	printf("[%s] End.\n",__FUNCTION__);
#endif
	return new_e_q_entry;
}

void WRITE_DATA_TO_BUFFER(unsigned int length)
{
#ifdef FIRM_IO_BUF_DEBUG
	printf("[%s] Start.\n",__FUNCTION__);
#endif

	/* Write Data to Write Buffer Frame */
	INCREASE_WB_SATA_POINTER(length);

#ifdef FIRM_IO_BUF_DEBUG
	printf("[%s] End.\n",__FUNCTION__);
#endif
}

void READ_DATA_FROM_BUFFER_TO_HOST(event_queue_entry* c_e_q_entry)
{
#ifdef FIRM_IO_BUF_DEBUG
	printf("[%s] Start.\n",__FUNCTION__);
#endif
	if(sata_read_ptr != c_e_q_entry->buf){
		printf("ERROR [%s] sata pointer is different from entry pointer.\n",__FUNCTION__);
	}

	/* Read the buffer data and increase SATA pointer */
	INCREASE_RB_SATA_POINTER(c_e_q_entry->length);

#ifdef FIRM_IO_BUF_DEBUG
	printf("[%s] End.\n",__FUNCTION__);
#endif
}

void COPY_DATA_TO_READ_BUFFER(event_queue_entry* dst_entry, event_queue_entry* src_entry)
{
#ifdef FIRM_IO_BUF_DEBUG
	printf("[%s] Start.\n",__FUNCTION__);
#endif
	if(dst_entry == NULL || src_entry == NULL){
		printf("[%s] Null pointer error.\n",__FUNCTION__);
		return;
	}

	int count = 0;
	int offset;
	void* dst_buf;	// new read entry
	void* src_buf;  // write entry

	int64_t dst_sector_nb = dst_entry->sector_nb;
	int64_t src_sector_nb = src_entry->sector_nb;
	unsigned int dst_length = dst_entry->length;

	/* Update read entry buffer pointer */	
	dst_buf = dst_entry->buf; 

	/* Calculate write buffer frame address */
	src_buf = src_entry->buf;
	offset = dst_sector_nb - src_sector_nb;


	while(count != offset){

		if(GET_WB_VALID_ARRAY_ENTRY(src_buf)!='I'){
			count++;
		}

		src_buf = src_buf + SECTOR_SIZE;
		if(src_buf == write_buffer_end){
			src_buf = write_buffer;
		}
	}

	count = 0;
	while(count != dst_length){
		if(GET_WB_VALID_ARRAY_ENTRY(src_buf)=='I'){
			src_buf = src_buf + SECTOR_SIZE;
			if(src_buf == write_buffer_end){
				src_buf = write_buffer;
			}
			continue;
		}

		/* Copy Write Buffer Data to Read Buffer */
		memcpy(dst_buf, src_buf, SECTOR_SIZE);

		/* Increase offset */
		dst_buf = dst_buf + SECTOR_SIZE;
		src_buf = src_buf + SECTOR_SIZE;

		ftl_read_ptr = ftl_read_ptr + SECTOR_SIZE;

		if(dst_buf == read_buffer_end){
			dst_buf = read_buffer;
			ftl_read_ptr = read_buffer;
		}
		if(src_buf == write_buffer_end){
			src_buf = write_buffer;
		}
		count++;
	}

	INCREASE_RB_LIMIT_POINTER();

#ifdef FIRM_IO_BUF_DEBUG
	printf("[%s] End.\n",__FUNCTION__);
#endif
}

void FLUSH_EVENT_QUEUE_UNTIL(event_queue_entry* e_q_entry)
{
#ifdef FIRM_IO_BUF_DEBUG
	printf("[%s] Start.\n",__FUNCTION__);
#endif
	int i;
	int count = 1;
	event_queue_entry* temp_e_q_entry = e_queue->head;
	
	if(e_q_entry == NULL || temp_e_q_entry == NULL){
		printf("ERROR[%s] Invalid event pointer\n",__FUNCTION__);
		return;
	}

	/* Count how many event should be flushed */
	if(e_q_entry == e_queue->tail){
		count = e_queue->entry_nb;
	}
	else{
		while(temp_e_q_entry != e_q_entry){
			count++;
			temp_e_q_entry = temp_e_q_entry->next;
		}
	}

	/* Dequeue event */
	for(i=0; i<count; i++){
		DEQUEUE_IO();
	}

#ifdef FIRM_IO_BUF_DEBUG
	printf("[%s] End.\n",__FUNCTION__);
#endif
}

int CHECK_OVERWRITE(event_queue_entry* e_q_entry, int64_t sector_nb, unsigned int length)
{
#ifdef FIRM_IO_BUF_DEBUG
	printf("[%s] Start.\n",__FUNCTION__);
#endif
	int ret = 0;
	int64_t temp_sector_nb = e_q_entry->sector_nb;
	unsigned int temp_length = e_q_entry->length;

	if(e_q_entry->io_type == WRITE){
		if( sector_nb <= temp_sector_nb && \
			(sector_nb + length) >= (temp_sector_nb + temp_length)){
				
			ret = 1;
		}
	}
#ifdef FIRM_IO_BUF_DEBUG
	printf("[%s] End.\n",__FUNCTION__);
#endif
	if(ret == 0)
		return FAIL;
	else
		return SUCCESS;
}

int CHECK_SEQUENTIALITY(event_queue_entry* e_q_entry, int64_t sector_nb)
{
#ifdef FIRM_IO_BUF_DEBUG
	printf("[%s] Start.\n",__FUNCTION__);
#endif
	if(e_q_entry == NULL){
		return FAIL;
	}

	int ret = 0;
	int64_t temp_sector_nb = e_q_entry->sector_nb;
	unsigned int temp_length = e_q_entry->length;

	if((e_q_entry->io_type == WRITE) && \
			(e_q_entry->valid == VALID) && \
			(temp_sector_nb + temp_length == sector_nb)){
		ret = 1;	
	}

#ifdef FIRM_IO_BUF_DEBUG
	printf("[%s] End.\n",__FUNCTION__);
#endif
	if(ret == 0)
		return FAIL;
	else
		return SUCCESS;
}

event_queue_entry* CHECK_IO_DEPENDENCY_FOR_READ(int64_t sector_nb, unsigned int length)
{
#ifdef FIRM_IO_BUF_DEBUG
	printf("[%s] Start.\n",__FUNCTION__);
#endif
	int64_t last_sector_nb = sector_nb + length - 1;
	int64_t temp_sector_nb;
	int64_t temp_last_sector_nb;

	event_queue_entry* ret_e_q_entry = NULL;
	event_queue_entry* e_q_entry = NULL;

	if(last_read_entry == NULL){
		e_q_entry = e_queue->head;
	}
	else{
		e_q_entry = last_read_entry->next;
	}

	while(e_q_entry != NULL){
		if(e_q_entry->valid == VALID){
			temp_sector_nb = e_q_entry->sector_nb;
			temp_last_sector_nb = temp_sector_nb + e_q_entry->length - 1; 

			/* Find the last IO event which has dependency */		
			if(temp_sector_nb <= last_sector_nb && \
				sector_nb <= temp_last_sector_nb){
				
				ret_e_q_entry = e_q_entry;
			}
		}
		e_q_entry = e_q_entry->next;
	}

#ifdef FIRM_IO_BUF_DEBUG
	printf("[%s] End.\n",__FUNCTION__);
#endif
	return ret_e_q_entry;
}

int CHECK_IO_DEPENDENCY_FOR_WRITE(event_queue_entry* e_q_entry, int64_t sector_nb, unsigned int length)
{
#ifdef FIRM_IO_BUF_DEBUG
	printf("[%s] Start.\n",__FUNCTION__);
#endif
	if(e_q_entry == NULL){
		return FAIL;
	}

	int ret = 0;
	int64_t last_sector_nb = sector_nb + length - 1;
	int64_t temp_sector_nb = e_q_entry->sector_nb;
	int64_t temp_last_sector_nb = temp_sector_nb + e_q_entry->length - 1;

	if(e_q_entry->io_type == WRITE && e_q_entry->valid == VALID){

		/* Find the last IO event which has dependency */		
		if(temp_sector_nb < sector_nb && \
			sector_nb < temp_last_sector_nb && \
			temp_last_sector_nb < last_sector_nb ){
			
			ret = 1;
		}
	}

#ifdef FIRM_IO_BUF_DEBUG
	printf("[%s] End.\n",__FUNCTION__);
#endif
	if(ret == 1)
		return SUCCESS;
	else
		return FAIL;
}

int EVENT_QUEUE_IS_FULL(int io_type, unsigned int length)
{
	int ret = FAIL;
	if(io_type == WRITE){	
		if(empty_write_buffer_frame < length)
			ret = SUCCESS;
	}
	else if(io_type == READ){
		if(empty_read_buffer_frame < length)
			ret = SUCCESS;
	}

	return ret;
}

void SECURE_WRITE_BUFFER(void)
{
	FLUSH_EVENT_QUEUE_UNTIL(e_queue->tail);
}

void SECURE_READ_BUFFER(void)
{
	if(c_e_queue->entry_nb != 0){
		DEQUEUE_COMPLETED_READ();
	}

	if(last_read_entry != NULL){
		FLUSH_EVENT_QUEUE_UNTIL(last_read_entry);
		DEQUEUE_COMPLETED_READ();
	}
}

char GET_WB_VALID_ARRAY_ENTRY(void* buffer_pointer)
{
	/* Calculate index of write buffer valid array */
	int index = (int)(buffer_pointer - write_buffer)/SECTOR_SIZE;

#ifdef FIRM_IO_BUF_DEBUG
	printf("[%s] index: %d\n",__FUNCTION__, index);
#endif
	
	/* Update write buffer valid array */
	return wb_valid_array[index];
}

void UPDATE_WB_VALID_ARRAY(event_queue_entry* e_q_entry, char new_value)
{
#ifdef FIRM_IO_BUF_DEBUG
	printf("[%s] Start. \n",__FUNCTION__);
#endif
	void* p_buf = e_q_entry->buf;
	if(p_buf == NULL){
		printf("ERROR[%s] Null pointer!\n",__FUNCTION__);
		return;
	}

	int index = (int)(p_buf - write_buffer)/SECTOR_SIZE;
	int count = 0;
	int length = e_q_entry->length;

	while(count != length){
		if(GET_WB_VALID_ARRAY_ENTRY(p_buf)=='V'){
			wb_valid_array[index] = new_value;	
			count++;
		}

		/* Increase index and buffer pointer */
		p_buf = p_buf + SECTOR_SIZE;
		index++;
		if(index == WRITE_BUFFER_FRAME_NB){
			p_buf = write_buffer;
			index = 0;
		} 
	}

#ifdef FIRM_IO_BUF_DEBUG
	printf("[%s] End. \n",__FUNCTION__);
#endif
}

void UPDATE_WB_VALID_ARRAY_ENTRY(void* buffer_pointer, char new_value)
{
	/* Calculate index of write buffer valid array */
	int index = (int)(buffer_pointer - write_buffer)/SECTOR_SIZE;
	if(index >= WRITE_BUFFER_FRAME_NB){
		printf("ERROR[%s] Invlald index. \n",__FUNCTION__);
		return;
	}
	
	/* Update write buffer valid array */
	wb_valid_array[index] = new_value;
}

void UPDATE_WB_VALID_ARRAY_PARTIAL(event_queue_entry* e_q_entry, char new_value, int length, int mode)
{
	// mode 0: change valid value of the front array
	// mode 1: change valid value of the rear array

	int count = 0;
	int offset = 0;
	void* p_buf = e_q_entry->buf;

	if(mode == 1){
		offset = e_q_entry->length - length;

		while(count != offset){
			if(GET_WB_VALID_ARRAY_ENTRY(p_buf)!='I'){
				count++;
			}
			p_buf = p_buf + SECTOR_SIZE;
			if(p_buf == write_buffer_end){
				p_buf = write_buffer;
			}
		}
	}

	count = 0;
	while(count != length){
		if(GET_WB_VALID_ARRAY_ENTRY(p_buf)!='I'){
			UPDATE_WB_VALID_ARRAY_ENTRY(p_buf, new_value);
			count++;
		}

		/* Increase index and buffer pointer */
		p_buf = p_buf + SECTOR_SIZE;
		if(p_buf == write_buffer_end){
			p_buf = write_buffer;
		}
	}
}

void INCREASE_WB_SATA_POINTER(int entry_nb)
{
	int i;
#ifdef FIRM_IO_BUF_DEBUG
	int index = (int)(sata_write_ptr - write_buffer)/SECTOR_SIZE;
	printf("[%s] Start: %d -> ",__FUNCTION__, index);
#endif
	for(i=0; i<entry_nb; i++){
		/* Decrease the # of empty write buffer frame */
		empty_write_buffer_frame--;

		/* Update write buffer valid array */
		UPDATE_WB_VALID_ARRAY_ENTRY(sata_write_ptr, 'V');

		/* Increase sata write pointer */
		sata_write_ptr = sata_write_ptr + SECTOR_SIZE;
		
		if(sata_write_ptr == write_buffer_end){
			sata_write_ptr = write_buffer;
		}
	}
#ifdef FIRM_IO_BUF_DEBUG
	index = (int)(sata_write_ptr - write_buffer)/SECTOR_SIZE;
	printf("%d End.\n",index);
#endif
}

void INCREASE_RB_SATA_POINTER(int entry_nb)
{
#ifdef FIRM_IO_BUF_DEBUG
	int index = (int)(sata_read_ptr - read_buffer)/SECTOR_SIZE;
	printf("[%s] Start: %d -> ",__FUNCTION__, index);
#endif
	int i;

	for(i=0; i<entry_nb; i++){
		empty_read_buffer_frame++;

		sata_read_ptr = sata_read_ptr + SECTOR_SIZE;

		if(sata_read_ptr == read_buffer_end){
			sata_read_ptr = read_buffer;
		}
	}
#ifdef FIRM_IO_BUF_DEBUG
	index = (int)(sata_read_ptr - read_buffer)/SECTOR_SIZE;
	printf("%d End.\n",index);
#endif
}

void INCREASE_WB_FTL_POINTER(int entry_nb)
{
#ifdef FIRM_IO_BUF_DEBUG
	int index = (int)(ftl_write_ptr - write_buffer)/SECTOR_SIZE;
	printf("[%s] Start: %d -> ",__FUNCTION__, index);
#endif
	int count = 0;
	char validity;

	while(count != entry_nb){
		/* Get write buffer frame status */
		validity = GET_WB_VALID_ARRAY_ENTRY(ftl_write_ptr);

		if(validity == 'V'){
			/* Update write buffer valid array */
			UPDATE_WB_VALID_ARRAY_ENTRY(ftl_write_ptr, 'F');

			count++;
		}

		/* Increase ftl pointer by SECTOR_SIZE */
		ftl_write_ptr = ftl_write_ptr + SECTOR_SIZE;
		if(ftl_write_ptr == write_buffer_end){
			ftl_write_ptr = write_buffer;
		}
	}
#ifdef FIRM_IO_BUF_DEBUG
	index = (int)(ftl_write_ptr - write_buffer)/SECTOR_SIZE;
	printf("%d End.\n",index);
#endif
}

void INCREASE_RB_FTL_POINTER(int entry_nb)
{
#ifdef FIRM_IO_BUF_DEBUG
	int index = (int)(ftl_read_ptr - read_buffer)/SECTOR_SIZE;
	printf("[%s] Start: %d -> ",__FUNCTION__, index);
#endif
	int i;

	for(i=0;i<entry_nb;i++){

		/* Increase ftl read pointer by SECTOR_SIZE */
		ftl_read_ptr = ftl_read_ptr + SECTOR_SIZE;
		if(ftl_read_ptr == read_buffer_end){
			ftl_read_ptr = read_buffer;
		}
	}
#ifdef FIRM_IO_BUF_DEBUG
	index = (int)(ftl_read_ptr - read_buffer)/SECTOR_SIZE;
	printf("%d End.\n",index);
#endif
}

void INCREASE_WB_LIMIT_POINTER(void)
{
#ifdef FIRM_IO_BUF_DEBUG
	int index = (int)(write_limit_ptr - write_buffer)/SECTOR_SIZE;
	printf("[%s] Start: %d -> ",__FUNCTION__, index);
#endif
	/* Increase write limit pointer until ftl write pointer */
	do{
		/* Update write buffer valid array */
		UPDATE_WB_VALID_ARRAY_ENTRY(write_limit_ptr, '0');

		/* Incrase write limit pointer by SECTOR_SIZE */
		write_limit_ptr = write_limit_ptr + SECTOR_SIZE;
		if(write_limit_ptr == write_buffer_end){
			write_limit_ptr = write_buffer;
		}

		empty_write_buffer_frame++;
	
	}while(write_limit_ptr != ftl_write_ptr);

#ifdef FIRM_IO_BUF_DEBUG
	index = (int)(write_limit_ptr - write_buffer)/SECTOR_SIZE;
	printf("%d. End.\n",index);
#endif
}

void INCREASE_RB_LIMIT_POINTER(void)
{
#ifdef FIRM_IO_BUF_DEBUG
	int index = (int)(read_limit_ptr - read_buffer)/SECTOR_SIZE;
	printf("[%s] Start: %d -> ",__FUNCTION__, index);
#endif
	/* Increase read limit pointer until ftl read pointer */
	do{

		/* Increase read lmit pointer by SECTOR_SIZE */
		read_limit_ptr = read_limit_ptr + SECTOR_SIZE;
		if(read_limit_ptr == read_buffer_end){
			read_limit_ptr = read_buffer;
		}
	}while(read_limit_ptr != ftl_read_ptr);
#ifdef FIRM_IO_BUF_DEBUG
	index = (int)(read_limit_ptr - read_buffer)/SECTOR_SIZE;
	printf("%d End.\n",index);
#endif
}

int COUNT_READ_EVENT(void)
{
	int count = 1;
	event_queue_entry* e_q_entry = NULL;

	if(last_read_entry == NULL){
		return 0;
	}
	else{
		e_q_entry = e_queue->head;
		while(e_q_entry != last_read_entry){
			count++;

			e_q_entry = e_q_entry->next;
		}
	}
	return count;
}

#endif
