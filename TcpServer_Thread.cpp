
#include "TcpServer.h"
#ifdef ____WIN32_
#include "IOPool.h"
using namespace net;


void net::TcpServer::runThread(int num)
{
	m_IsRunning = true;
	m_ThreadNum = num;
	if (num > 10) m_ThreadNum = 10;

	for (int i = 0; i < m_ThreadNum; i++)
		m_workthread[i].reset(new std::thread(TcpServer::run, this, i));
	//m_sendthread.reset(new std::thread(TcpServer::run_send, this));

	//分离线程
	for (int i = 0; i < m_ThreadNum; i++)
		m_workthread[i]->detach();
	//m_sendthread->detach();

}

void pushContext(IOContext* context)
{
	switch (context->m_Mode)
	{
	case func::SC_WAIT_ACCEPT:
		AcceptContext::push((AcceptContext*)context);
		break;
	case func::SC_WAIT_RECV:
		RecvContext::push((RecvContext*)context);
		break;
	case func::SC_WAIT_SEND:
		SendContext::push((SendContext*)context);
		break;
	}
}
//工作线程
void  net::TcpServer::run(TcpServer* tcp, int id)
{
	LOG_MSG("run workthread...%d\n", id);
	ULONG_PTR    key = 1;//完成端口绑定的字段
	OVERLAPPED*  overlapped = nullptr;//连入Socket的时候建立的那个重叠结构  
	DWORD        recvBytes = 0;//操作完成返回字节数

	while (tcp->m_IsRunning)
	{
		bool iscomplete = GetQueuedCompletionStatus(tcp->getCompletePort(), &recvBytes, &key, &overlapped, INFINITE);


		IOContext* context = CONTAINING_RECORD(overlapped, IOContext, m_OverLapped);
		if (context == nullptr) continue;

		if (iscomplete == false)
		{
			DWORD dwErr = GetLastError();
			// 如果是超时了，就再继续等吧  
			if (WAIT_TIMEOUT == dwErr) continue;

			if (overlapped != NULL)
			{
				tcp->shutDown(context->m_Socket, context->m_Mode, NULL, 3001);
				pushContext(context);
				continue;
			}

			tcp->shutDown(context->m_Socket, context->m_Mode, NULL, 3002);
			pushContext(context);
			continue;
		}
		else
		{
			if (overlapped == NULL)
			{
				LOG_MSG("overlapped == NULL \n");
				break;
			}
			if (key != 0)
			{
				LOG_MSG("key != 0 \n");
				continue;
			}

			// 判断是否有客户端断开了
			if ((recvBytes == 0) && (context->m_Mode == func::SC_WAIT_RECV || context->m_Mode == func::SC_WAIT_SEND))
			{
				tcp->shutDown(context->m_Socket, context->m_Mode, NULL, 3003);
				pushContext(context);
				continue;
			}

			switch (context->m_Mode)
			{
			case func::SC_WAIT_ACCEPT:
				{
					auto acc = (AcceptContext*)context;
					int err = tcp->onAccpet(acc);
					if (err != 0)
					{
						tcp->closeSocket(acc->m_Socket, NULL, 3004);
						AcceptContext::push(acc);
						tcp->postAccept();
					}
				}
				break;
			case func::SC_WAIT_RECV:
				tcp->onRecv(context, (int)recvBytes, id);
				break;
			case func::SC_WAIT_SEND:
				tcp->onSend(context, (int)recvBytes);
				break;
			}
		}
	}


	LOG_MSG("exit workthread...%d\n", id);
}

//消费者 发送线程 
//void net::TcpServer::run_send(TcpServer* tcp)
//{
//	//LOG_MSG("run sendthread...\n");
//
//	//while (tcp->m_IsRunning)
//	//{
//	//	for (s32 i = 0; i < func::__ServerInfo->MaxConnect; i++)
//	//	{
//	//		auto c = tcp->client(i);
//	//		if (c == nullptr) continue;
//	//		if (c->ID == -1)   continue;
//	//		if (c->state == func::S_Free) continue;
//	//		if (c->closeState == func::S_CLOSE_SHUTDOWN) continue;
//	//		if (!c->is_SendCompleted) continue;
//
//	//		tcp->postSend(c);
//	//	}
//
//	//	Sleep(10);
//	//}
//
//	//LOG_MSG("exit sendthread...\n");
//}


#endif