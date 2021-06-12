#ifndef  ____TCPCLIENT_H
#define  ____TCPCLIENT_H

#include "INetBase.h"
#include <atomic>
#include <mutex>
#include  <thread>
namespace net
{
	class TcpClient :public ITcpClient
	{
	private:
#ifdef ____WIN32_
		SOCKET   socketfd;
#else
		int      socketfd;
#endif
		S_SERVER_BASE  m_data;
		std::shared_ptr<std::thread> m_workthread;

		TCPCLIENTNOTIFY_EVENT      onAcceptEvent;
		TCPCLIENTNOTIFY_EVENT      onSecureEvent;
		TCPCLIENTNOTIFY_EVENT      onDisconnectEvent;
		TCPCLIENTNOTIFY_EVENT      onExceptEvent;

		s32 initSocket();
		bool setNonblockingSocket();
		void connect_Select();
		void onAutoConnect();
		int onRecv();
		int onSend();
		int onSaveData(int recvBytes);
		
		void  onHeart();
		void  parseCommand(u16 cmd);
		void  initCommands();

		void runThread();
		static void run(TcpClient* tcp);
	public:
		TcpClient();
		virtual ~TcpClient();
		virtual inline S_SERVER_BASE* getData() { return &m_data; };
#ifdef ____WIN32_
		virtual inline SOCKET getSocket() { return socketfd; };
#else
		virtual inline int getSocket() { return socketfd; };
#endif 
		virtual void runClient(u32 sid,char* ip, int port);
		virtual bool connectServer();
		virtual void disconnectServer(const s32 errcode, const char* err);

		virtual void  begin(const u16 cmd);
		virtual void  end();
		virtual void  sss(const s8 v);
		virtual void  sss(const u8 v);
		virtual void  sss(const s16 v);
		virtual void  sss(const u16 v);
		virtual void  sss(const s32 v);
		virtual void  sss(const u32 v);
		virtual void  sss(const s64 v);
		virtual void  sss(const u64 v);
		virtual void  sss(const bool v);
		virtual void  sss(const f32 v);
		virtual void  sss(const f64 v);
		virtual void  sss(void* v, const u32 len);

		virtual void  read(s8& v);
		virtual void  read(u8& v);
		virtual void  read(s16& v);
		virtual void  read(u16& v);
		virtual void  read(s32& v);
		virtual void  read(u32& v);
		virtual void  read(s64& v);
		virtual void  read(u64& v);
		virtual void  read(bool& v);
		virtual void  read(f32& v);
		virtual void  read(f64& v);
		virtual void  read(void* v, const u32 len);

		virtual void  parseCommand();
		virtual void  registerCommand(int cmd, void* container);
		virtual void  setOnConnect(TCPCLIENTNOTIFY_EVENT event);
		virtual void  setOnConnectSecure(TCPCLIENTNOTIFY_EVENT event);
		virtual void  setOnDisconnect(TCPCLIENTNOTIFY_EVENT event);
		virtual void  setOnExcept(TCPCLIENTNOTIFY_EVENT event);

	};
}

#endif