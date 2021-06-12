#include "EpollServer.h"
#ifndef ____WIN32_
#include <sys/socket.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <string.h>
#include <cstring>

#include <netinet/tcp.h>
using namespace net;

ITcpServer* net::NewTcpServer()
{
	return new EpollServer();
}


net::EpollServer::EpollServer()
{
	m_isRunning = false;
	m_ConnectCount = 0;//��ǰ������
    m_SercurityCount = 0;//��ȫ������
	m_ThreadNum = 0;
	m_LinkIndex = 0;
	listenfd = -1;
	epollfd = -1;

	onAcceptEvent = NULL;
	onSecurityEvent = NULL;
	onTimeoutEvent = NULL;
	onDisconnectEvent = NULL;
	onExceptEvent = NULL;
}

net::EpollServer::~EpollServer()
{
}




void net::EpollServer::runServer(s32 num)
{
	for (int i = 0; i < 10; i++)
		recvBuf[i] = new char[func::__ServerInfo->ReceOne];

	Linkers = new HashArray<S_CLIENT_BASE>(func::__ServerInfo->MaxConnect);
	for (int i = 0; i < Linkers->length; i++)
	{
		S_CLIENT_BASE* c = Linkers->Value(i);
		c->Init();
	}
	LinkersIndex = new HashArray<S_CLIENT_BASE_INDEX>(MAX_USER_SOCKETFD);
	for (int i = 0; i < LinkersIndex->length; i++)
	{
		S_CLIENT_BASE_INDEX* cindex = LinkersIndex->Value(i);
		cindex->Reset();
	}
	//��ʼ��socket
	initSocket();
	//���ó�ʼ���߳�
	runThread(num);
	//��ʼ��ָ��
	initCommands();
}

void net::EpollServer::stopServer()
{
}



bool setNonbocking(int fd)
{
	int flags = fcntl(fd, F_GETFL);
	if (flags < 0) return false;
	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) < 0) return false;
	return true;
}
int net::EpollServer::add_event(int epollfd, int sockfd, int events)
{
	struct epoll_event ev;
	ev.events = events;
	ev.data.fd = sockfd;
	int value = epoll_ctl(epollfd, EPOLL_CTL_ADD, sockfd, &ev);

	return value;
}
int net::EpollServer::delete_event(int epollfd, int sockfd, int events)
{
	struct epoll_event ev;
	ev.events = events;
	ev.data.fd = sockfd;
	int value = epoll_ctl(epollfd, EPOLL_CTL_DEL, sockfd, &ev);

	return value;
}

//1. ���� socket �������� socket������socket�� 
//2. ���� bind ���� �� socket�󶨵�ĳ��ip�Ͷ˿ڵĶ�Ԫ���� 
//3. ���� listen ���� �������� 
//4. ���пͻ����������������󣬵��� accept �����������ӣ�����һ���µ�socket 
//5. �����²����� socket ���� send �� recv ������ʼ��ͻ��˽������ݽ��� 6
//6. ͨ�Ž����󣬵��� close �����ر����� socket

int net::EpollServer::initSocket()
{
	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	setNonbocking(listenfd);
	int rece = 0;
	int send = 0;
	setsockopt(listenfd, SOL_SOCKET, SO_RCVBUF, (const int*)& rece, sizeof(int));
	setsockopt(listenfd, SOL_SOCKET, SO_SNDBUF, (const int*)& send, sizeof(int));

	//�����˿ں��ظ���
	int flag = 1;
	int ret = setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(int));
	
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(func::__ServerInfo->Port);
	addr.sin_addr.s_addr = INADDR_ANY;

	//��
	ret = bind(listenfd, (struct sockaddr*) & addr, sizeof(addr));
	if (ret == -1)
	{
		perror("bind error:");
		exit(1);
	}
	//����
	listen(listenfd, SOMAXCONN);

	//����epoll ��ע��
	epollfd = epoll_create(1111);
	add_event(epollfd, listenfd, EPOLLIN);

	return 0;
}




//�����µ�����
void net::EpollServer::onAccept()
{
	struct sockaddr_in addr;
	socklen_t client_len = sizeof(addr);
	int clientfd = accept(listenfd, (struct sockaddr*) & addr, &client_len);
	if (clientfd == -1)
	{
		perror("accept error:");
		return;
	}
	//���˵�IP �������
	//int count = addConnectIP(inet_ntoa(addr.sin_addr));
	//if (count > MAX_IP_ONE_COUNT) return;
	//5������ngle�㷨
	const char chOpt = 1;
	int   nErr = setsockopt(clientfd, IPPROTO_TCP, TCP_NODELAY, &chOpt, sizeof(char));

	net::S_CLIENT_BASE* c = getFreeLinker();
	net::S_CLIENT_BASE_INDEX* cindex = getClientIndex(clientfd);
	if (c == NULL)
	{
		deleteConnectIP(inet_ntoa(addr.sin_addr));
		closeSocket(clientfd, nullptr, 3004);
		return;
	}
	if (cindex == NULL)
	{
		deleteConnectIP(inet_ntoa(addr.sin_addr));
		c->Reset();
		closeSocket(clientfd, nullptr, 3004);
		return;
	}
	cindex->index = c->ID;
	c->socketfd = clientfd;
	c->time_Connet = (int)time(NULL);
	c->port = ntohs(addr.sin_port);
	c->time_Heart = (int)time(NULL);
	c->state = func::S_Connect;
	memcpy(c->ip, inet_ntoa(addr.sin_addr), MAX_IP_LEN);

	setNonbocking(clientfd);
	add_event(this->epollfd, c->socketfd, EPOLLIN | EPOLLET);

	this->updateConnectCount(true);

	srand(time(NULL));
	u8 rcode = rand() % 100 + 1;
	begin(c->ID, CMD_RCODE);
	sss(c->ID, rcode);
	end(c->ID);
	c->rCode = rcode;
	if (onAcceptEvent != nullptr) this->onAcceptEvent(this, c, 0);

}
//��������
void net::EpollServer::onRecv(int socketfd, int threadid)
{
	if (threadid >= 10) return;
	auto c = client(socketfd, true);
	if (c == nullptr) return;

	memset(recvBuf[threadid], 0, func::__ServerInfo->ReceOne);

	while (true)
	{
		int len = recv(socketfd, recvBuf[threadid], func::__ServerInfo->ReceOne, 0);
		if (len < 0)
		{
			if (errno == EINTR) continue;
			else if (errno == EAGAIN) break;
			else
			{
				shutDown(socketfd, 0, c, 1001);
				return;
			}
		}
		else if (len == 0)
		{
			shutDown(socketfd, 0, c, 3003);
			return;
		}

		int error = onRecv_SaveData(c, recvBuf[threadid], len);
		if (error < 0)
		{
			shutDown(socketfd, 0, c, 1002);
			return;
		}
		if (len < func::__ServerInfo->ReceOne) break;

	}

}

//��������
int net::EpollServer::onRecv_SaveData(S_CLIENT_BASE* c, char* buf, int recvBytes)
{
	if (buf == nullptr) return -1;
	if (c->recv_Tail == c->recv_Head)
	{
		c->recv_Tail = 0;
		c->recv_Head = 0;
	}

	if (c->recv_Tail + recvBytes > func::__ServerInfo->ReceMax) return -1;

	memcpy(&c->recvBuf[c->recv_Tail], buf, recvBytes);
	c->recv_Tail += recvBytes;
	c->is_RecvCompleted = true;
	return 0;
}
//��������
int net::EpollServer::onSend(S_CLIENT_BASE* c)
{
	if (c->ID < 0 || c->state == func::S_Free || c->socketfd == -1) return -1;
	if (c->send_Tail <= c->send_Head) return 0;
	int sendlen = c->send_Tail - c->send_Head;
	if (sendlen <= 0) return 0;

	int send_bytes = send(c->socketfd, c->sendBuf + c->send_Head, sendlen, 0);
	if (send_bytes < 0)
	{
		if (errno == EINTR) return 0;
		else if (errno == EAGAIN) return 1;
		else
		{
			shutDown(c->socketfd, 0, c, 1006);
			return -2;
		}
	}
	else if (send_bytes == 0)
	{
		shutDown(c->socketfd, 0, c, 3005);
		return -3;
	}
	c->send_Head += send_bytes;
	c->is_SendCompleted = true;

	//while (true)
	//{
	//	int send_bytes = send(c->socketfd, c->sendBuf + c->send_Head, sendlen, 0);
	//	if (send_bytes < 0)
	//	{
	//		if (errno == EINTR) continue;
	//		else if (errno == EAGAIN) return 1;
	//		else
	//		{
	//			shutDown(c->socketfd, 0, c, 1006);
	//			return -2;
	//		}
	//	}
	//	else if (send_bytes == 0)
	//	{
	//		shutDown(c->socketfd, 0, c, 3005);
	//		return -3;
	//	}
	//	c->send_Head += send_bytes;
	//	if (c->send_Head == c->send_Tail) break;

	//	sendlen = c->send_Tail - c->send_Head;
	//}
	//c->is_SendCompleted = true;

	return 0;   
}



int net::EpollServer::closeSocket(int socketfd, S_CLIENT_BASE* c, int kind)
{
	LOG_MSG("kind %d\n", kind);
	if (socketfd == -1) return -1;
	if (c != nullptr)
	{
		if (c->state == func::S_Free) return 0;
		if (c->state == func::S_ConnectSecure)
		{
			this->updateSercurityCount(false);
		}
		auto cindex = getClientIndex(socketfd);
		//if (cindex != nullptr) cindex->Reset();

		deleteConnectIP(c->ip);
	}

	this->updateConnectCount(false);
	delete_event(epollfd, socketfd, EPOLLIN | EPOLLET);
	close(socketfd);
	if (onDisconnectEvent != nullptr) this->onDisconnectEvent(this, c, kind);

	//��ʼ��
	if (c->state == func::S_Connect || c->state == func::S_ConnectSecure)
	c->Reset();
	return 0;
}
//���Źر�socket
void net::EpollServer::shutDown(int socketfd, const int mode, S_CLIENT_BASE* c, int kind)
{
	if (c != nullptr)
	{
		if (c->state == func::S_Free) return;
		if (c->closeState == func::S_CLOSE_SHUTDOWN) return;

		c->shutdown_kind = kind;
		c->time_Close = (int)time(NULL);
		c->closeState = func::S_CLOSE_SHUTDOWN;
		shutdown(socketfd, SHUT_RDWR);

		if (onExceptEvent != nullptr) this->onExceptEvent(this, c, kind);
		return;
	}

	auto c2 = client(socketfd, true);
	if (c2 == nullptr) return;


	if (c2->state == func::S_Free) return;
	if (c2->closeState == func::S_CLOSE_SHUTDOWN) return;

	c2->shutdown_kind = kind;
	c2->time_Close = (int)time(NULL);
	c2->closeState = func::S_CLOSE_SHUTDOWN;
	shutdown(socketfd, SHUT_RDWR);

	if (onExceptEvent != nullptr) this->onExceptEvent(this, c2, kind);
}



#endif
