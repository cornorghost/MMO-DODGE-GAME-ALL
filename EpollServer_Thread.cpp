#include "EpollServer.h"
#ifndef ____WIN32_
#include <sys/socket.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <fcntl.h>
using namespace net;

void net::EpollServer::runThread(int num)
{
	m_isRunning = true;
	m_ManagerThread.reset(new std::thread(EpollServer::run_manager, this));
	m_AcceptThread.reset(new std::thread(EpollServer::run_accept, this,0));
	m_RecvThread.reset(new std::thread(EpollServer::run_recv, this,0));

	m_ManagerThread->detach();
	m_AcceptThread->detach();
	m_RecvThread->detach();
}


void EpollServer::run_manager(EpollServer* epoll)
{
	LOG_MSG("run manager...\n");

	struct epoll_event events[2048];

	for (; ; )
	{
		int num = epoll_wait(epoll->epollfd, events, 2048, -1);
		if (num == -1)
		{
			if (errno == EINTR) continue;
			LOG_MSG("return run manager...\n");
			break;
		}
		for (int i = 0; i < num; i++)
		{
			int socketfd = events[i].data.fd;
			if (socketfd == epoll->listenfd)
			{
				//有新的连接
				epoll->m_Aceeptcond.notify_one();
			}
			else if (events[i].events & EPOLLIN)
			{
				//有新的数据到来...
				{
					std::unique_lock<std::mutex> guard(epoll->m_RecvMutex);
					epoll->m_Socketfds.push_back(socketfd);
				}
				epoll->m_Recvcond.notify_one();
			}
		}
	}

	LOG_MSG("exit manager...\n");
}
void EpollServer::run_accept(EpollServer* epoll, int tid)
{
	LOG_MSG("run_accept...\n");

	while (epoll->m_isRunning)
	{
		{
			std::unique_lock<std::mutex> guard(epoll->m_AcceptMutex);
			epoll->m_Aceeptcond.wait(guard);
		}
		epoll->onAccept();
	}

	LOG_MSG("exit_accept...\n");
}
void EpollServer::run_recv(EpollServer* epoll, int tid)
{
	LOG_MSG("run_recv...\n");

	int socketfd = -1;

	while (epoll->m_isRunning)
	{
		{
			std::unique_lock<std::mutex> guard(epoll->m_RecvMutex);
			while (epoll->m_Socketfds.empty())
			{
				epoll->m_Recvcond.wait(guard);
			}
			
			socketfd = epoll->m_Socketfds.front();
			epoll->m_Socketfds.pop_front();
		}
		
		epoll->onRecv(socketfd, tid);
	}

	LOG_MSG("exit_recv...\n");
}

#endif