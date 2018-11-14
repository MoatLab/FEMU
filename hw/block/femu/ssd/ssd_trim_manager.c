// File: ssd_trim_manager.c
// Date: 2014. 12. 03.
// Author: Jinsoo Yoo (jedisty@hanyang.ac.kr)
// Copyright(c)2014
// Hanyang University, Seoul, Korea
// Embedded Software Systems Laboratory. All right reserved

#include "ssd_trim_manager.h"
#include <stdio.h>
#include <malloc.h>
#include <memory.h>

#ifdef SSD_EVALUATION
typedef struct trim_test
{
	long time_usec;
	int time_sec;
	int time_min;
	int64_t sector_nb;
	unsigned int length;
	struct trim_test* next;
	struct trim_test* prev;
}trim_test;

trim_test* trim_list = NULL;
trim_test* trim_list_tail = NULL;
#endif

typedef struct trimmed_sector_entry
{
	int64_t sector_nb;
	unsigned int length;
	struct trimmed_sector_entry* next;
	struct trimmed_sector_entry* prev;

}trimmed_sector_entry;


typedef struct trimmed_sector_entry_index
{
	int		index;
	trimmed_sector_entry* pTSE;
	trimmed_sector_entry* pTSE_tail;
	struct trimmed_sector_entry_index* next;
	struct trimmed_sector_entry_index* prev;
}trimmed_sector_entry_index;


trimmed_sector_entry_index*			g_TSEI = NULL;

trimmed_sector_entry* find_in_trimmed_sector_list(int64_t sector_nb);

void	remove_trimmed_sector_entry(trimmed_sector_entry* pTSE);
void	release_trimmed_sector_entry(void);
trimmed_sector_entry* get_trimmed_sector_entry(sector_entry* pSE);
trimmed_sector_entry_index* get_trimmed_sector_entry_index(trimmed_sector_entry* pTSE);
int overlap_trimmed_sector(trimmed_sector_entry* pTSE1, trimmed_sector_entry* pTSE2);
void free_trimmed_sector_entry(trimmed_sector_entry* pTSE);

void INIT_TRIM(void)
{	
}
void TERM_TRIM(void)
{
#ifdef SSD_EVALUATION
/*
	if(trim_list != NULL)
	{
		trim_test* pTT;
		trim_test* pTT_T;

		FILE* pfData = fopen("./data/trim_test.dat", "w");

		if(pfData != NULL)
		{
			pTT = trim_list;
			while(pTT != NULL)
			{
				fprintf(pfData, "[%ld, %d, %02d:%02d:%06ld]\n", pTT->sector_nb, pTT->length, pTT->time_min, pTT->time_sec, pTT->time_usec);
				pTT_T = pTT;
				pTT = pTT->next;
				free(pTT_T);
			}

			fclose(pfData);
		}

	}
*/
#endif
	
}
int EXIST_IN_TRIM_LIST(int64_t sector_nb){ 	
/*
	if(DSM_TRIM_ENABLE == 0)
		return SSD_FALSE;

	int interval = TRIM_INDEX_INTERVAL;
	int index = sector_nb / interval;
	
	trimmed_sector_entry_index* pTSEI = g_TSEI;

	while(pTSEI != NULL)
	{
		if(pTSEI->index == index)
			break;

		pTSEI = pTSEI->next;
	}	
	
	if(pTSEI == NULL || pTSEI->index != index)
		return SSD_FALSE;

	trimmed_sector_entry* pTSE = pTSEI->pTSE;

	while(pTSE!=NULL)
	{
		if(pTSE->sector_nb <= sector_nb && pTSE->sector_nb + pTSE->length > sector_nb)
		{
				return SSD_TRUE;
		}
		pTSE = pTSE->next;
	}

    return SSD_FALSE; 
*/
}

int REMOVE_TRIM_SECTOR(int64_t sector_nb) 
{ 	
/*
	if(DSM_TRIM_ENABLE == 0)
		return SSD_FALSE;

	int interval = TRIM_INDEX_INTERVAL;
	int index = sector_nb / interval;
	
	trimmed_sector_entry_index* pTSEI = g_TSEI;

	while(pTSEI != NULL)
	{
		if(pTSEI->index == index)
			break;

		pTSEI = pTSEI->next;
	}	
	
	
	if(pTSEI == NULL || pTSEI->index != index)
		return SSD_FALSE;

	trimmed_sector_entry* pTSE = pTSEI->pTSE;

	while(pTSE!=NULL)
	{
		if(pTSE->sector_nb <= sector_nb && pTSE->sector_nb + pTSE->length > sector_nb)
		{
			if(pTSE->sector_nb == sector_nb)
			{
				pTSE->sector_nb++;
				pTSE->length--;
			}
			else if(pTSE->sector_nb < sector_nb && pTSE->sector_nb + pTSE->length -1 > sector_nb)
			{
				
				trimmed_sector_entry* pTSE_T = (trimmed_sector_entry*)malloc(sizeof(trimmed_sector_entry));
				memset(pTSE_T, 0x00, sizeof(trimmed_sector_entry));
				pTSE_T->sector_nb = sector_nb + 1;
				pTSE_T->length = pTSE->sector_nb + pTSE->length - 1 - sector_nb;
				pTSE->length = sector_nb - pTSE->sector_nb;

				if(pTSE->next != NULL)
				{
					pTSE->next->prev = pTSE_T;
					pTSE_T->next = pTSE->next;
				}
				pTSE_T->prev = pTSE;
				pTSE->next = pTSE_T;

			}
			else if(pTSE->sector_nb + pTSE->length - 1 == sector_nb)
			{
				pTSE->length --;
			}

			if(pTSE->length == 0)
			{

				if(pTSEI->pTSE == pTSE && pTSEI->pTSE_tail == pTSE)
				{
					pTSEI->pTSE = NULL;
					pTSEI->pTSE_tail = NULL;
				}
				else if(pTSE == pTSEI->pTSE)
				{
					pTSEI->pTSE = pTSE->next;
				}
				else if(pTSE == pTSEI->pTSE_tail)
				{
					pTSEI->pTSE_tail = pTSE->prev;
				}

				if(pTSE->prev != NULL)
					pTSE->prev->next = pTSE->next;
				if(pTSE->next != NULL)
					pTSE->next->prev = pTSE->prev;

				free(pTSE);
			}

			return SSD_TRUE;
		}
		pTSE = pTSE->next;
	}

    return SSD_FALSE; 
*/
} 

int overlap_trimmed_sector(trimmed_sector_entry* pTSE1, trimmed_sector_entry* pTSE2)
{
/*
	int64_t start1, end1, start2, end2;

	start1 = pTSE1->sector_nb;
	end1 = pTSE1->sector_nb + pTSE1->length -1;
	start2 = pTSE2->sector_nb;
	end2 = pTSE2->sector_nb + pTSE2->length -1;

	if(start2 >= start1 && start2<=end1+1 && end2 > end1)
		return 1;

	if(start2 >= start1 && end2 <= end1)
		return 2;

	if(start2 < start1 && end2+1 >= start1 && end2 <= end1)
		return 3;

	if(start2 <= start1 && end2 >= end1)
		return 4;

	return 0;
*/
}

void free_trimmed_sector_entry(trimmed_sector_entry* pTSE)
{
/*
	if(pTSE == NULL)
		return;

	if(pTSE->prev!=NULL)
		pTSE->prev->next = pTSE->next;							
	if(pTSE->next != NULL)
		pTSE->next->prev = pTSE->prev;

	if(pTSE == g_TSEI->pTSE_tail)
	{
		g_TSEI->pTSE_tail = pTSE->prev;
	}
	if(pTSE == g_TSEI->pTSE)
	{
		g_TSEI->pTSE = pTSE->next;
	}

	free(pTSE);
*/
}

void INSERT_TRIM_SECTORS(sector_entry* pSE) 
{ 
#ifdef SSD_EVALUATION
/*	int64_t start_time =get_usec();
	int64_t trimmed_sector_count=0;
	int		trimmed_sector=0;
*/
#endif
/*
	printf("insert trim==============================================================\n");
	sector_entry* pSE_T = pSE;
	while(pSE_T!=NULL)
	{
		if(pSE_T->sector_nb + pSE_T->length < SECTOR_NB)
		{
			REMOVE_MAPPING(pSE_T->sector_nb, pSE_T->length);
#ifdef SSD_EVALUATION
			struct timeval val;
			gettimeofday(&val, NULL);
			
			//time_t t_now;
			//time(&t_now);
			struct tm* now;
			trim_test *pTT = NULL;
			pTT = (trim_test*)malloc(sizeof(trim_test));
			memset(pTT, 0x00, sizeof(trim_test));
			pTT->sector_nb = pSE_T->sector_nb;
			pTT->length = pSE_T->length;

			now= localtime(&val.tv_sec);
			//now = localtime(&t_now);

			pTT->time_min = now->tm_min;
			pTT->time_sec = now->tm_sec;
			pTT->time_usec = val.tv_usec;

			if(trim_list == NULL)
			{
				trim_list = pTT;
				trim_list_tail = pTT;
			}
			else
			{
				trim_list_tail->next = pTT;
				pTT->prev = trim_list_tail;
				trim_list_tail = pTT;
			}
			trimmed_sector_count+=(int64_t)pSE->length;
#endif
		}
		pSE_T = pSE_T->next;
#ifdef SSD_EVALUATION
		trimmed_sector++;
#endif
	}
#ifdef SSD_EVALUATION
	int64_t end_time = get_usec();
	char szTemp[1024];
	sprintf(szTemp, "TRIM INSERT %ld %lld %d %ld", end_time - start_time, pSE->length, trimmed_sector, trimmed_sector_count);
	WRITE_LOG(szTemp);
#endif
*/
} 

sector_entry* new_sector_entry(void)
{
/*
	sector_entry* pTemp;
	
	pTemp = NULL;
	
	pTemp = (sector_entry*)malloc(sizeof(sector_entry));
	memset(pTemp, 0x00, sizeof(sector_entry));
	pTemp->next = NULL;
	pTemp->prev = NULL;

	return pTemp;
*/
}

void add_sector_list(sector_entry* pList, sector_entry* pSE)
{
/*
	sector_entry* pTail = NULL;
	
	if(pSE == NULL || pList == NULL)
		return;
	
	pTail = pList;
	while(pTail->next != NULL)
		pTail = pTail->next;

	pTail->next = pSE;
	pSE->prev = pTail;
*/
}

void release_sector_list(sector_entry* pSE)
{
/*
	sector_entry* pHead = NULL;
	sector_entry* pTemp = NULL;

	if(pSE == NULL)
		return;

	pHead = pSE;
	while(pHead->prev != NULL)
		pHead = pHead->prev;
	
	
	while(pHead != NULL)
	{		
		pTemp = pHead;
		pHead = pHead->next;
		free(pTemp);
	}	
*/
}

void remove_sector_entry(sector_entry* pSE)
{
/*
	if(pSE == NULL)
		return;

	if(pSE->prev != NULL)
		pSE->prev->next = pSE->next;
	if(pSE->next != NULL)
		pSE->next->prev = pSE->prev;

	free(pSE);
	pSE = NULL;
*/
}

trimmed_sector_entry* get_trimmed_sector_entry(sector_entry* pSE)
{
/*
	if(pSE == NULL)
		return NULL;

	//sector_entry* pSE_T = pSE;

	trimmed_sector_entry* pTSE = NULL;
	trimmed_sector_entry* pTSE_tail = NULL;
	trimmed_sector_entry* pTSE_T = NULL;
	int64_t end_sector_nb = pSE->sector_nb + pSE->length -1;

	int interval = TRIM_INDEX_INTERVAL;

	int part_nb = pSE->sector_nb / interval;
	int64_t current_sector_nb = pSE->sector_nb; //(pSE->sector_nb / interval) * interval;

	while(part_nb * interval < end_sector_nb)
	{
		pTSE_T = (trimmed_sector_entry*)malloc(sizeof(trimmed_sector_entry));
		memset(pTSE_T, 0x00, sizeof(trimmed_sector_entry));
		pTSE_T->sector_nb = current_sector_nb;
		
		if((part_nb+1) * interval > end_sector_nb)
			pTSE_T->length = end_sector_nb - current_sector_nb + 1;
		else
			pTSE_T->length = (part_nb+1) * interval - pTSE_T->sector_nb;

		if(pTSE == NULL)
		{
			pTSE = pTSE_T;
			pTSE_tail = pTSE_T;
		}
		else
		{
			pTSE_tail->next = pTSE_T;
			pTSE_T->prev = pTSE_tail;
			pTSE_tail = pTSE_T;
		}
		
		part_nb ++;
		current_sector_nb = part_nb * interval;
	}

	return pTSE;
*/
}

trimmed_sector_entry_index* get_trimmed_sector_entry_index(trimmed_sector_entry* pTSE)
{
/*	if(pTSE == NULL)
		return NULL;
	int interval = TRIM_INDEX_INTERVAL;
	int part_nb = pTSE->sector_nb / interval;

	trimmed_sector_entry_index* pTSEI = g_TSEI;

	while(pTSEI!=NULL)
	{
		if(pTSEI->index == part_nb)
			return pTSEI;
		pTSEI = pTSEI->next;
	}

	return NULL;
*/
}
