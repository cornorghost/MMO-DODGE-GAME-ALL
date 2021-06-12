#ifndef  ____TCPSERVER_H
#define  ____TCPSERVER_H

#ifdef ____WIN32_

#include "INetBase.h"
#include "IContainer.h"
#include <mutex>
#include <thread> 
#include <map>
#include <MSWSock.h>
#pragma comment(lib,"mswsock")

namespace net
{
	class TcpServer :public ITcpServer
	{
	public:
		TcpServer();
		virtual ~TcpServer();
	private:
		s32      m_ConnectCount; //��ǰ������
		s32      m_SecurityCount;//��ȫ������
		bool     m_IsRunning;
		s32      m_ThreadNum;//�߳�����
		SOCKET   listenfd;   //�����׽��־��
		HANDLE   m_Completeport;//��ɶ˿ھ��
		LPFN_ACCEPTEX m_AcceptEx;	//AcceptEx������ַ
		LPFN_GETACCEPTEXSOCKADDRS  m_GetAcceptEx;//��ȡ�ͻ�����Ϣ������ַ

		std::shared_ptr<std::thread> m_workthread[10];
		//std::shared_ptr<std::thread> m_sendthread;

		std::mutex		 m_findlink_mutex;
		std::mutex       m_ConnectMutex;
		std::mutex       m_SecurityMutex;
		
		HashArray<S_CLIENT_BASE>* Linkers;//�������
		HashArray<S_CLIENT_BASE_INDEX>* LinkersIndexs;//���������������

		//5������ָ�� ����ҵ���֪ͨ�¼�
		TCPSERVERNOTIFY_EVENT      onAcceptEvent;
		TCPSERVERNOTIFY_EVENT      onSecureEvent;
		TCPSERVERNOTIFY_EVENT      onTimeOutEvent;
		TCPSERVERNOTIFY_EVENT      onDisconnectEvent;
		TCPSERVERNOTIFY_EVENT      onExceptEvent;

		//���˵�IP N������ 
		std::map<std::string, s32>   m_LimitsIPs;
		std::mutex                   m_LimitIPMutex;
	private:
		//Ͷ��accept
		s32 postAccept();//Ͷ������
		s32 onAccpet(void* context);//�����¼�
		//Ͷ��recv
		s32 postRecv(SOCKET s);
		s32 onRecv(void* context, s32 recvBytes, u32 tid);
		s32 onRecv_SaveData(S_CLIENT_BASE* c, char* buf, s32 recvBytes);
		//Ͷ��send
		s32 postSend(S_CLIENT_BASE* c);
		s32 onSend(void* context, s32 sendBytes);

		s32 closeSocket(SOCKET socketfd, S_CLIENT_BASE* c, int kind);
		void shutDown(SOCKET s, const s32 mode, S_CLIENT_BASE* c, int kind);
		int setHeartCheck(SOCKET s);
		S_CLIENT_BASE* getFreeLinker();

		//***********************************************************
		//�Ƿ���Ҫ����IP
		inline int  addConnectIP(char* ip)
		{
			return 0;
			std::string  key(ip);
			auto it = m_LimitsIPs.find(key);
			if (it == m_LimitsIPs.end())
			{
				m_LimitsIPs.insert(std::make_pair(key, 1));
				return 1;
			}

			s32 count = it->second;
			if (count >= MAX_IP_ONE_COUNT)
			{
				count++;
				LOG_MSG("ip limits: %s -- count-%d\n", key.c_str(), count);
				return count;
			}
			//���� �޸�����
			{
				std::lock_guard<std::mutex> guard(this->m_LimitIPMutex);
				count++;
				m_LimitsIPs[key] = count;
			}

			return count;
		}
		inline int  deleteConnectIP(char* ip)
		{
			std::string  key(ip);
			auto it = m_LimitsIPs.find(key);
			if (it == m_LimitsIPs.end()) return 0;

			s32 count = it->second;
			if (count <= 1)
			{
				//���� �޸�����
				{
					std::lock_guard<std::mutex> guard(this->m_LimitIPMutex);
					m_LimitsIPs.erase(it);
				}

				LOG_MSG("delete limitsIP  %s \n", key.c_str());
				return 0;
			}

			//���� �޸�����
			{
				std::lock_guard<std::mutex> guard(this->m_LimitIPMutex);
				count--;
				m_LimitsIPs[key] = count;
			}

			LOG_MSG("leave limitsIP %s -- count-%d \n", key.c_str(), count);
			return count;
		}


		inline HANDLE getCompletePort()
		{
			return m_Completeport;
		}
		//��ȫ��������
		inline void updateRecurityConnect(bool isadd)
		{
			{
				std::lock_guard<std::mutex> guard(this->m_SecurityMutex);

				if (isadd) m_SecurityCount++;
				else m_SecurityCount--;
			}

		}
		//��������
		inline void updateConnect(bool isadd)
		{
			{
				std::lock_guard<std::mutex> guard(this->m_ConnectMutex);

				if (isadd) m_ConnectCount++;
				else m_ConnectCount--;
			}
		}
		inline S_CLIENT_BASE_INDEX* getClientIndex(const int socketfd)
		{
			if (socketfd < 0 || socketfd >= MAX_USER_SOCKETFD) return nullptr;
			S_CLIENT_BASE_INDEX * c = LinkersIndexs->Value(socketfd);
			return c;
		}



	private:
		s32   initSocket();
		void  initPost();
		void  initCommands();

		void  runThread(int num);
		void  parseCommand(S_CLIENT_BASE* c);
		void  parseCommand(S_CLIENT_BASE* c, u16 cmd);
		void  checkConnect(S_CLIENT_BASE* c);

		static void run(TcpServer * tcp, int id);
		//static void run_send(TcpServer * tcp);
	public:
		virtual void  runServer(s32 num);
		virtual void  stopServer();
		virtual S_CLIENT_BASE* client(SOCKET socketfd, bool isseriuty);
		virtual S_CLIENT_BASE* client(const int id);

		virtual bool  isID_T(const s32 id);
		virtual bool  isSecure_T(const s32 id, s32 secure);
		virtual bool  isSecure_F_Close(const s32 id, s32 secure);

		virtual void  parseCommand();
		virtual void  getSecurityCount(int& connum, int& securtiynum);

		virtual void  begin(const int id, const u16 cmd);
		virtual void  end(const int id);
		virtual void  sss(const int id, const s8 v);
		virtual void  sss(const int id, const u8 v);
		virtual void  sss(const int id, const s16 v);
		virtual void  sss(const int id, const u16 v);
		virtual void  sss(const int id, const s32 v);
		virtual void  sss(const int id, const u32 v);
		virtual void  sss(const int id, const s64 v);
		virtual void  sss(const int id, const u64 v);
		virtual void  sss(const int id, const bool v);
		virtual void  sss(const int id, const f32 v);
		virtual void  sss(const int id, const f64 v);
		virtual void  sss(const int id, void* v, const u32 len);

		virtual void  read(const int id, s8& v);
		virtual void  read(const int id, u8& v);
		virtual void  read(const int id, s16& v);
		virtual void  read(const int id, u16& v);
		virtual void  read(const int id, s32& v);
		virtual void  read(const int id, u32& v);
		virtual void  read(const int id, s64& v);
		virtual void  read(const int id, u64& v);
		virtual void  read(const int id, bool& v);
		virtual void  read(const int id, f32& v);
		virtual void  read(const int id, f64& v);
		virtual void  read(const int id, void* v, const u32 len);

		virtual void  setOnClientAccept(TCPSERVERNOTIFY_EVENT event);
		virtual void  setOnClientSecureConnect(TCPSERVERNOTIFY_EVENT event);
		virtual void  setOnClientDisconnect(TCPSERVERNOTIFY_EVENT event);
		virtual void  setOnClientTimeout(TCPSERVERNOTIFY_EVENT event);
		virtual void  setOnClientExcept(TCPSERVERNOTIFY_EVENT event);
		virtual void  registerCommand(int cmd, void* container);
	};
}

#endif 
#endif 