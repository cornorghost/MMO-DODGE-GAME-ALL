#include "TcpClient.h"

#ifndef ____WIN32_

#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#endif


namespace net
{
	//********************************************************************
	//********************************************************************
	void TcpClient::runThread()
	{
		m_workthread.reset(new std::thread(TcpClient::run, this));
		m_workthread->detach();

	}
	//工作线程
	void TcpClient::run(TcpClient* tcp)
	{
		auto c = tcp->getData();
		auto socketfd = tcp->getSocket();
		//LOG_MSG("run client...%d:%d \n", c->serverID, c->ID);

		int sleep_time = 10 * 1000;
#ifdef ____WIN32_
		sleep_time = 10;
#endif

		while (true)
		{
			//1、尝试连接
			if (c->state == func::C_Free)
			{
				tcp->onAutoConnect();
				socketfd = tcp->getSocket();
			}
			else if (c->state == func::C_ConnectTry)
			{
				tcp->connectServer();
				socketfd = tcp->getSocket();
			}
			if (c->state < func::C_Connect)
			{
#ifdef ____WIN32_
				Sleep(sleep_time);
#else
				usleep(sleep_time);
#endif
				continue;
			}
			//2、连接成功 这是个坑 必须每次重新设置超时时间
			struct timeval tv;
			tv.tv_sec = 10;
			tv.tv_usec = 1000;
			fd_set f_read;
			FD_ZERO(&f_read);
			FD_SET(socketfd, &f_read);
			int errcode = select(socketfd + (u32)1, &f_read, NULL, NULL, &tv);
			if (errcode > 0)
			{
				//有数据可以读
				if (FD_ISSET(socketfd, &f_read))
				{
					int ret = tcp->onRecv();
				}
			}
			else if (errcode == 0)
			{
			}
			else
			{
#ifdef ____WIN32_
				int err = WSAGetLastError();
				switch (err)
				{
				case WSAEINTR:
					break;
				default:
					tcp->disconnectServer(1001, "select -1");
					break;
				}
#else 
				switch (errno)
				{
				case EINTR:
					break;
				default:
					tcp->disconnectServer(1001, "select -1");
					break;
				}
#endif
			}
		}

		LOG_MSG("client thread exit。。。\n");
		return;
	}


}