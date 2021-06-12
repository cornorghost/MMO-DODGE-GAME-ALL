#include "TcpClient.h"

#ifndef ____WIN32_
#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#include <string.h>


namespace net
{
	ITcpClient* NewTcpClient()
	{
		return new TcpClient();
	}

	TcpClient::TcpClient()
	{
#ifdef ____WIN32_
		socketfd = INVALID_SOCKET;
#else
		socketfd = -1;
#endif

		onAcceptEvent = nullptr;
		onSecureEvent = nullptr;
		onDisconnectEvent = nullptr;
		onExceptEvent = nullptr;
	}

	TcpClient::~TcpClient()
	{
#ifdef ____WIN32_
		RELEASE_SOCKET(socketfd);
		WSACleanup(); //释放套接字资源;  
#else
		close(socketfd);
#endif

		
	}

	//运行客户端
	void TcpClient::runClient(u32 sid, char* ip, int port)
	{
		m_data.init(sid);
		//设置ip 端口
		m_data.time_AutoConnect = 0;
		if (ip != NULL)  strcpy(m_data.ip, ip);
		if (port > 0)    m_data.port = port;

		s32 err = initSocket();
		if (err < 0)
		{
			LOG_MSG("--------------client is error:%d...", err);
			return;
		}

		runThread();
		initCommands();
	}

	//设置非阻塞
	bool TcpClient::setNonblockingSocket()
	{
#ifdef ____WIN32_
		unsigned long ul = 1;
		s32 errorcode = ioctlsocket(socketfd, FIONBIO, (unsigned long*)& ul);
		if (errorcode == SOCKET_ERROR)
		{
			LOG_MSG("--------------client errorcode is error..%d line:%d", errorcode, __LINE__);
			return -1;
		}
#else
		//fcntl系统调用可以用来对已打开的文件描述符进行各种控制操作以改变已打开文件的的各种属性
		int flags = fcntl(socketfd, F_GETFL);//获取文件打开方式的标志，标志值含义与open调用一致
		if (flags < 0)
			return false;
		flags |= O_NONBLOCK;
		if (fcntl(socketfd, F_SETFL, flags) < 0) //设置文件状态标志
			return false;
		return true;
#endif
	}

//客户端编程的步骤：
//(1)：加载套接字库，创建套接字(WSAStartup() / socket())；
//(2)：向服务器发出连接请求(connect())；
//(3)：和服务器端进行通信(send() / recv())；
//(4)：关闭套接字，关闭加载的套接字库(closesocket() / WSACleanup())。

	s32 TcpClient::initSocket()
	{
#ifdef ____WIN32_
		//1、初始化Windows Sockets DLL
		WSADATA  wsData;
		s32 errorcode = WSAStartup(MAKEWORD(2, 2), &wsData);
		if (errorcode != 0) 
		{
			WSACleanup();
			return -1;
		}
#endif
		//1、创建套接字  
		socketfd = socket(AF_INET, SOCK_STREAM, 0);
		if (socketfd < 0)
		{
			int fd = socketfd;
			LOG_MSG("--------------client socket is error..%d line:%d", fd, __LINE__);
			return -1;
		}
		//2、设置套接字非阻塞模式
		setNonblockingSocket();
		//3、设置发送接受缓冲区
		int rece = func::__ClientInfo->ReceOne;
		int send = func::__ClientInfo->SendOne;
		setsockopt(socketfd, SOL_SOCKET, SO_SNDBUF, (char*)& rece, sizeof(rece));
		setsockopt(socketfd, SOL_SOCKET, SO_RCVBUF, (char*)& send, sizeof(send));

		return 0;
	}




	//select函数返回值：负值：select错误 正值：某些文件可读写或出错 0：等待超时，没有可读写或错误的文件
	void TcpClient::connect_Select()
	{
		struct timeval tv;
		tv.tv_sec  = 5;
		tv.tv_usec = 0;

		fd_set wset;
		FD_ZERO(&wset);
		FD_SET(socketfd, &wset);

		int error = select(socketfd + 1, NULL, &wset, NULL, &tv);
		if (error <= 0)
		{
			this->disconnectServer(1008, "select timeout");
			return;
		}
		
		if (FD_ISSET(socketfd, &wset)) connectServer();
	}

	bool TcpClient::connectServer()
	{
		if (m_data.port < 1000) return false;

		m_data.state = func::C_ConnectTry;
		//1、需要连接的服务端套接字结构信息  
		struct sockaddr_in addrServer;
#ifdef ____WIN32_
		addrServer.sin_addr.S_un.S_addr = inet_addr(m_data.ip);
#else
		addrServer.sin_addr.s_addr = inet_addr(m_data.ip);
#endif
		addrServer.sin_family = AF_INET;
		addrServer.sin_port = htons(m_data.port);//使用网络字节序

		//2、连接服务器
		int value = connect(socketfd, (struct sockaddr*)&addrServer, sizeof(addrServer));
		if (value == 0)//连接成功
		{
			m_data.state = func::C_Connect;
			if (onAcceptEvent != nullptr) onAcceptEvent(this, 1);
			//LOG_MSG("--------------client connect success...%d-%d\n", m_data.serverID, m_data.port);
			return true;
		}
		//处理连接错误
		if (value < 0)
		{
#ifdef ____WIN32_
			int err = WSAGetLastError();

			//指定了一个无效参数
			if (WSAEINVAL == err)
			{
				LOG_MSG("--------------client 指定了一个无效参数.%d-%d\n", m_data.serverID, m_data.port);
				return false;
			}
			//意思是这个操作不能马上完成，正在连接中
			if (WSAEWOULDBLOCK == err)
			{
				connect_Select();
				return false;
			}
			//连接已经完成
			if (WSAEISCONN == err)
			{
				m_data.state = func::C_Connect;
				//LOG_MSG("--------------client connect success2...%d-%d\n", m_data.serverID, m_data.port);
				if (onAcceptEvent != nullptr)  onAcceptEvent(this, 2);
				return true;
			}
#else
			//LOG_MSG("connect socket error:%d \n", errno);

			//EINTR 表示被什么信号中断
			//当应用程序在socket中设置O_NONBLOCK属性后，如果发送缓存被占满，
			//send就会返回EAGAIN或EWOULDBLOCK的错误。
			//在将socket设置O_NONBLOCK属性后，通过socket发送一个100K大小的数据，
			//第一次成功发送了10K数据，之后继续发送并未成功，errno数值为EAGAIN错误。
			//或者recv 接收数据没接收完 还有数据
			//
			if (errno == EINTR || errno == EAGAIN)
			{
				return false;
			}
			//意思是这个操作不能马上完成，正在连接中
			if (errno == EINPROGRESS)
			{
				connect_Select();
				return false;
			}
			if (errno == EISCONN)
			{
				m_data.state = func::C_Connect;
				if (onAcceptEvent != nullptr)  onAcceptEvent(this, 2);
				return true;
			}
#endif

			this->disconnectServer(1009, "[connect fail]");
			return false;
		}

		return false;
	}
	void TcpClient::disconnectServer(const s32 errcode, const char* err)
	{
		if (m_data.state == func::C_Free) return;
		if (socketfd == -1) return;
#ifdef ____WIN32_
		if (socketfd == INVALID_SOCKET) return;
		RELEASE_SOCKET(socketfd);
#else
		close(socketfd);
		socketfd = -1;
#endif
		m_data.reset();
		initSocket();
		//LOG_MSG("---------client disconnectServer %d-%s \n", errcode, err);
		if (onDisconnectEvent != nullptr) onDisconnectEvent(this, errcode);
	}

	//自动重连
	void  TcpClient::onAutoConnect()
	{
		if (m_data.port < 1000) return;

		auto c = getData();
		s32 tempTime = (s32)time(NULL) - m_data.time_AutoConnect;
		if (tempTime >= func::__ClientInfo->AutoTime)
		{
			c->reset();

			int fd = socketfd;
			LOG_MSG("----------client autoConnect...%d threadid:%d \n", fd, getData()->ID);
			connectServer();
			m_data.time_AutoConnect = (s32)time(NULL);
		}
	}


	//接受数据
	int TcpClient::onRecv()
	{
		auto c = this->getData();
		memset(c->recvBuf_Temp, 0, func::__ClientInfo->ReceOne);
		int receBytes = recv(socketfd, c->recvBuf_Temp, func::__ClientInfo->ReceOne, 0);
		if (receBytes > 0)
		{
			//保存数据
			int err = onSaveData(receBytes);
			if (err < 0)
			{
				this->disconnectServer(1007, "recvFull...");
				return err;
			}
			return 0;
		}
		if (receBytes == 0) //服务器关闭连接
		{
			this->disconnectServer(1003, "receBytes=0...");
			return -1;
		}

#ifdef ____WIN32_
		//接受数据出错
		if (receBytes < 0)
		{
			int err = WSAGetLastError();
			switch (err)
			{
			case WSAEINTR:
			case WSAEWOULDBLOCK:
				return 0;
			default:
				LOG_MSG("recv error...%d-%d \n", (int)c->socketfd, err);
				this->disconnectServer(1001, "[recv error]");
				return -1;
			}
		}
#else
		//接受数据出错
		if (receBytes < 0)
		{
			switch (errno)
			{
			case EINTR://信号   
			case EAGAIN:
				return 0;
			default:
				this->disconnectServer(1001, "server close-1");
				return -1;
			}
		}
#endif
	}
	//生产者 保存数据
	int TcpClient::onSaveData(int recvBytes)
	{
		auto c = this->getData();
		if (c->recv_Tail == c->recv_Head)
		{
			c->recv_Tail = 0;
			c->recv_Head = 0;
		}
		if (c->recv_Tail + recvBytes >= func::__ClientInfo->ReceMax)
		{
			printf("----------client .rece full %d-%d.. \n", c->recv_Head, c->recv_Tail);
			return -1;
		}
		if (c->recv_Head > c->recv_Tail)
		{
			printf("----------client .B>E %d-%d.. \n", c->recv_Head, c->recv_Tail);
		}

		memcpy(&c->recvBuf[c->recv_Tail], c->recvBuf_Temp, recvBytes);
		c->recv_Tail += recvBytes;
		return 0;
	}
	//消费者 发送数据
	int TcpClient::onSend()
	{
		auto c = this->getData();

		if (c->send_Tail <= c->send_Head) return 0;
		if (c->state < func::C_Connect) return -1;

		int sendlen = c->send_Tail - c->send_Head;
		if (sendlen < 1) return -1;

		//发送数据
		int sendbytes = send(socketfd, &c->sendBuf[c->send_Head], sendlen, 0);
		if (sendbytes > 0)
		{
			c->send_Head += sendbytes;
			return 0;
		}
#ifdef ____WIN32_
		if (sendbytes < 0)
		{
			int errcode = WSAGetLastError();
			switch (errcode)
			{
			case WSAEINTR:
			case WSAEWOULDBLOCK:
				return 0;
			default:
				this->disconnectServer(4002, "send close-1");
				return -1;
			}
		}
#else
		if (sendbytes < 0)
		{
			switch (errno)
			{
			case EINTR://信号   
			case EAGAIN:
				return 0;
			default:
				this->disconnectServer(4002, "send close-1");
				return -1;
			}
		}
#endif
	}



}

