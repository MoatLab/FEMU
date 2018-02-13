// File: ssd_log_manager.c
// Date: 2014. 12. 03.
// Author: Jinsoo Yoo (jedisty@hanyang.ac.kr)
// Copyright(c)2014
// Hanyang University, Seoul, Korea
// Embedded Software Systems Laboratory. All right reserved

#include "ssd_log_manager.h"
#include "common.h"

#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>

int servSock;
int clientSock;

pthread_t thread_ID;

int g_server_create = 0;
int g_init_log_server = 0;

//TEMP
int send_fail_cnt = 0;
double send_cnt = 0;

void INIT_LOG_MANAGER(void)
{
	if(g_init_log_server == 0){
		popen("./ssd_monitor", "r");
		THREAD_SERVER(NULL);

		g_init_log_server = 1;
	}
}
void TERM_LOG_MANAGER(void)
{
	close(servSock);
	close(clientSock);
}

void WRITE_LOG(char* szLog)
{
	int ret1, ret2;
	if(g_server_create == 0){
		printf(" write log is failed\n");
		return;
	}
	ret1 = send(clientSock, szLog, strlen(szLog), 0);
	ret2 = send(clientSock, "\n", 1, MSG_DONTWAIT);

	send_cnt +=2;
#ifdef MNT_DEBUG
/*
	if(ret1 == -1 || ret2 == -1){
		if(ret1 == -1 && ret2 == -1)
			send_fail_cnt+=2;
		else
			send_fail_cnt++;
	}
	printf("[%s] send fail!! %d/%lf\n", __FUNCTION__, send_fail_cnt, send_cnt);
*/
#endif
}

void THREAD_SERVER(void* arg)
{
#ifdef MNT_DEBUG
	printf("[SSD_MONITOR] SERVER THREAD CREATED!!!\n");
#endif	
	unsigned int len;
	struct sockaddr_in serverAddr;
	struct sockaddr_in clientAddr;

	if((servSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0){
#ifdef MNT_DEBUG
		printf("[SSD_MONITOR] Server Socket Creation error!!!\n");
#endif
	}

	int flags = fcntl(servSock, F_GETFL, 0);

	fcntl(servSock, F_SETFL, flags | O_APPEND);

	int option = 1;
	setsockopt(servSock, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));
	memset(&serverAddr, 0x00, sizeof(serverAddr));
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	serverAddr.sin_port = htons(9995);
	
	if(bind(servSock, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0)
	{
#ifdef MNT_DEBUG
		printf("[SSD_MONITOR] Server Socket Bind Error!!!\n");
		return;
#endif
	}

	if(listen(servSock, 100)<0){
#ifdef MNT_DEBUG
		printf("[SSD_MONITOR] Server Socket Listen Error!!!\n");
#endif
	}
#ifdef MNT_DEBUG
	printf("[SSD_MONITOR] Wait for client....[%d]\n", servSock);
#endif
	clientSock = accept(servSock, (struct sockaddr*) &clientAddr, &len);
#ifdef MNT_DEBUG
	printf("[SSD_MONITOR] Connected![%d]\n", clientSock);
	printf("[SSD_MONITOR] Error No. [%d]\n", errno);
#endif	
	g_server_create = 1;
}

void THREAD_CLIENT(void* arg)
{
	int a = *(int*)arg;
	//	int a = (int)arg;
#ifdef MNT_DEBUG
	printf("[SSD_MONITOR] ClientSock[%d]\n", a);
#endif
	send(a, "test\n", 5, 0);
}

