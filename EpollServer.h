#ifndef ____EPOLLSERVER_H
#define ____EPOLLSERVER_H

#ifndef  ____WIN32_
         
#include "INetBase.h"
#include "IContainer.h"
#include <condition_variable>
#include <thread>
#include <map>
#include <list>
#include <netinet/in.h>


namespace net
{
	class  EpollServer:public ITcpServer
	{
	public:
		EpollServer();
		virtual ~EpollServer();
	private:
		u32     m_ConnectCount;//当前连接数
		u32     m_SercurityCount;//安全连接数
		u32     m_ThreadNum;
		u32     m_LinkIndex;
		bool    m_isRunning;

		std::condition_variable   m_Aceeptcond;
		std::condition_variable   m_Recvcond;

		std::mutex   m_ConnectMutex;
		std::mutex   m_SecurityMutex;
		std::mutex   m_AcceptMutex;
		std::mutex   m_RecvMutex;
		std::mutex   m_FindLinkMutex;

		std::shared_ptr<std::thread>    m_ManagerThread;
		std::shared_ptr<std::thread>    m_AcceptThread;
		std::shared_ptr<std::thread>    m_RecvThread;

		std::list<int>                m_Socketfds;
		int  listenfd;
		int  epollfd;
		char* recvBuf[10];
		HashArray<S_CLIENT_BASE>*         Linkers;
		HashArray<S_CLIENT_BASE_INDEX>*   LinkersIndex;

		TCPSERVERNOTIFY_EVENT      onAcceptEvent;
		TCPSERVERNOTIFY_EVENT      onSecurityEvent;
		TCPSERVERNOTIFY_EVENT      onTimeoutEvent;
		TCPSERVERNOTIFY_EVENT      onDisconnectEvent;
		TCPSERVERNOTIFY_EVENT      onExceptEvent;

		//过滤单IP N个连接 
		std::map<std::string, s32>   m_LimitsIPs;
		std::mutex                   m_LimitIPMutex;
	private:
		int initSocket();
		void initCommands();
		int closeSocket(int socketfd, S_CLIENT_BASE* c, int kind);
		void shutDown(int socketfd, const int mode, S_CLIENT_BASE* c, int kind);

		int add_event(int epollfd, int sockfd, int events);
		int delete_event(int epollfd, int sockfd, int events); 

		void onAccept();
		void onRecv(int socketfd,int threadid);
		int onRecv_SaveData(S_CLIENT_BASE* c, char* buf, int recvBytes);
		int onSend(S_CLIENT_BASE* c);


		S_CLIENT_BASE* getFreeLinker();

		void runThread(int num);
		void parseCommand(S_CLIENT_BASE* c);
		void parseCommand(S_CLIENT_BASE* c,u16 cmd);
		void checkConnect(S_CLIENT_BASE* c);

		static void run_manager(EpollServer* epoll);
		static void run_accept(EpollServer* epoll,int tid);
		static void run_recv(EpollServer* epoll,int tid);
	public:
		//***********************************************************
//是否需要限制IP
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
			//上锁 修改数据
			{
				std::lock_guard<std::mutex> guard(this->m_LimitIPMutex);
				count++;
				m_LimitsIPs[key] = count;
			}

			return count;
		}
		inline int  deleteConnectIP(char* ip)
		{
			return 0;
			std::string  key(ip);
			auto it = m_LimitsIPs.find(key);
			if (it == m_LimitsIPs.end()) return 0;

			s32 count = it->second;
			if (count <= 1)
			{
				//上锁 修改数据
				{
					std::lock_guard<std::mutex> guard(this->m_LimitIPMutex);
					m_LimitsIPs.erase(it);
				}

				LOG_MSG("delete limitsIP  %s \n", key.c_str());
				return 0;
			}

			//上锁 修改数据
			{
				std::lock_guard<std::mutex> guard(this->m_LimitIPMutex);
				count--;
				m_LimitsIPs[key] = count;
			}

			LOG_MSG("leave limitsIP %s -- count-%d \n", key.c_str(), count);
			return count;
		}

		inline void updateSercurityCount(bool isadd)
		{
			{
				std::lock_guard<std::mutex> guard(m_SecurityMutex);
				if (isadd) m_SercurityCount++;
				else m_SercurityCount--;
			}
		}
		inline void updateConnectCount(bool isadd)
		{
			{
				std::lock_guard<std::mutex> guard(m_SecurityMutex);
				if (isadd) m_ConnectCount++;
				else m_ConnectCount--;
			}
		}
		inline S_CLIENT_BASE_INDEX* getClientIndex(const int socketfd)
		{
			if (socketfd < 0 || socketfd >= MAX_USER_SOCKETFD) return NULL;
			S_CLIENT_BASE_INDEX* c = LinkersIndex->Value(socketfd);
			return c;
		}
	public:
		virtual void  runServer(s32 num);
		virtual void  stopServer(); 
		virtual S_CLIENT_BASE* client(int socketfd, bool isseriuty);
		virtual S_CLIENT_BASE* client(const int id);
		virtual S_CLIENT_BASE* client(const int id, const u32 clientid);

		virtual bool  isID_T(const s32 id);
		virtual bool  isSecure_T(const s32 id, s32 secure);
		virtual bool  isSecure_F_Close(const s32 id, s32 secure);

		virtual void  parseCommand();
		virtual void  getSecurityCount(int& connum, int& securtiynum);
		//封装发送数据包
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
		//解析接收数据包
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


#endif // ! _____WIN32
#endif