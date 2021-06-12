#ifndef  ____INETBASE_H
#define  ____INETBASE_H 

#include "IDefine.h"

namespace net
{

#pragma pack(push,packing)
#pragma pack(1)


	struct S_CLIENT_BASE_INDEX
	{
		s32 index;
		inline void Reset() { index = -1; }
	};

	struct S_CLIENT_BASE
	{
		//固定数据
#ifdef ____WIN32_
		SOCKET       socketfd;
#else
		int          socketfd;
#endif 
		//动态变化 
		s8              state;//用户状态 0空闲 1连接 2登录
		s8              closeState;//关闭状态 必须完成端口队列 没有投递才安全关闭
		char            ip[MAX_IP_LEN];
		u16			    port;
		int				ID; //对应索引号
		u8              rCode;

		//游戏记录数据
		s32             clientID;   //各个功能服务器ID 
		u8              clientType; //0 1-DB 2-Center 3-Game 4-Gate 5-Login 
		//接收数据
		bool			is_RecvCompleted;
		char*           recvBuf;
		s32				recv_Head;//头 消费者使用
		s32				recv_Tail;//尾 生产者使用
		s32				recv_TempHead;//临时头
		s32				recv_TempTail;//临时尾

		//发送数据
		bool			is_Sending;
		bool            is_SendCompleted;
		char*           sendBuf;
		s32				send_Head;
		s32				send_Tail;
		s32				send_TempTail;
		//时间类
		s32             time_Connet;
		s32             time_Heart;
		s32             time_Close;
		u8              theadID;
		s32             shutdown_kind;
		char            md5[MAX_MD5_LEN];
		void Init();
		void Reset();


#ifdef ____WIN32_
		inline bool isT(SOCKET client)
		{
			if (socketfd == client) return true;
			return false;
		}
#else
		inline bool isT(int client)
		{
			if (socketfd == client) return true;
			return false;
		}
#endif

	};

	//************************************************************
    //************************************************************
    //************************************************************
    //客户端-结构体
	struct S_SERVER_BASE
	{
#ifdef ____WIN32_
		SOCKET       socketfd;
#else
		s32          socketfd;
#endif 
		s32				ID;   //客户端ID
		char			ip[16];
		u16		        port;
		s32             serverID;//0 1000-DB 2000-Center 3000-Game 4000-Gate 5000-Login 
		u8              serverType;//0 1-DB 2-Center 3-Game 4-Gate 5-Login
									//动态变化字段
		u8              state;//用户状态 0空闲 1尝试连接 2安全连接  3连接成功
		u8              rCode;

		char*           recvBuf_Temp;
		char*           recvBuf;
		s32				recv_Head;//头 消费者使用
		s32				recv_Tail;//尾 生产者使用
		s32				recv_TempHead;//临时头
		s32				recv_TempTail;//临时尾
		bool			is_Recved;

		char*           sendBuf;
		s32				send_Head;
		s32				send_Tail;
		s32				send_TempTail;
		bool			is_Sending;
		bool            is_SendCompleted;

		s32             time_Heart;
		s32             time_AutoConnect;
		char            md5[MAX_MD5_LEN];

		void init(int sid);
		void reset();
	};
#pragma pack(pop, packing)

	class ITcpServer;
	class ITcpClient;
	typedef void(*TCPSERVERNOTIFY_EVENT) (ITcpServer* tcp, S_CLIENT_BASE* c, const s32 code);
	typedef void(*TCPSERVERNOTIFYERRO_EVENT) (ITcpServer* tcp, S_CLIENT_BASE* c, const s32 code, const char* err);
	typedef void(*TCPCLIENTNOTIFY_EVENT)(ITcpClient* tcp, const s32 code);

	//定义我们的服务器接口 纯虚函数 
	class ITcpServer
	{
	public:
		virtual ~ITcpServer() {}
		virtual void  runServer(s32 num) = 0;
		virtual void  stopServer() = 0;
#ifdef ____WIN32_
		virtual S_CLIENT_BASE* client(SOCKET socketfd, bool isseriuty) = 0;
#else
		virtual S_CLIENT_BASE* client(int socketfd, bool isseriuty) = 0;
#endif
		virtual S_CLIENT_BASE* client(const int id) = 0;

		
		virtual bool  isID_T(const s32 id) = 0;
		virtual bool  isSecure_T(const s32 id, s32 secure) = 0;
		virtual bool  isSecure_F_Close(const s32 id, s32 secure) = 0;

		virtual void  parseCommand() = 0;
		virtual void  getSecurityCount(int& connum, int& securtiynum) = 0;
		//封装发送数据包
		virtual void  begin(const int id, const u16 cmd) = 0;
		virtual void  end(const int id) = 0;
		virtual void  sss(const int id, const s8 v) = 0;
		virtual void  sss(const int id, const u8 v) = 0;
		virtual void  sss(const int id, const s16 v) = 0;
		virtual void  sss(const int id, const u16 v) = 0;
		virtual void  sss(const int id, const s32 v) = 0;
		virtual void  sss(const int id, const u32 v) = 0;
		virtual void  sss(const int id, const s64 v) = 0;
		virtual void  sss(const int id, const u64 v) = 0;
		virtual void  sss(const int id, const bool v) = 0;
		virtual void  sss(const int id, const f32 v) = 0;
		virtual void  sss(const int id, const f64 v) = 0;
		virtual void  sss(const int id, void* v, const u32 len) = 0;
		//解析接收数据包
		virtual void  read(const int id, s8& v) = 0;
		virtual void  read(const int id, u8& v) = 0;
		virtual void  read(const int id, s16& v) = 0;
		virtual void  read(const int id, u16& v) = 0;
		virtual void  read(const int id, s32& v) = 0;
		virtual void  read(const int id, u32& v) = 0;
		virtual void  read(const int id, s64& v) = 0;
		virtual void  read(const int id, u64& v) = 0;
		virtual void  read(const int id, bool& v) = 0;
		virtual void  read(const int id, f32& v) = 0;
		virtual void  read(const int id, f64& v) = 0;
		virtual void  read(const int id, void* v, const u32 len) = 0;

		virtual void  setOnClientAccept(TCPSERVERNOTIFY_EVENT event) = 0;
		virtual void  setOnClientSecureConnect(TCPSERVERNOTIFY_EVENT event) = 0;
		virtual void  setOnClientDisconnect(TCPSERVERNOTIFY_EVENT event) = 0;
		virtual void  setOnClientTimeout(TCPSERVERNOTIFY_EVENT event) = 0;
		virtual void  setOnClientExcept(TCPSERVERNOTIFY_EVENT event) = 0;
		virtual void  registerCommand(int cmd, void* container) = 0;
	};



	class ITcpClient
	{
	public:
		virtual ~ITcpClient() {}

		virtual S_SERVER_BASE* getData() = 0;
#ifdef ____WIN32_
		virtual SOCKET getSocket() = 0;
#else
		virtual int getSocket() = 0;
#endif 
		virtual void runClient(u32 sid, char* ip, int por) = 0;
		virtual bool connectServer() = 0;
		virtual void disconnectServer(const s32 errcode, const char* err) = 0;

		virtual void  begin(const u16 cmd) = 0;
		virtual void  end() = 0;
		virtual void  sss(const s8 v) = 0;
		virtual void  sss(const u8 v) = 0;
		virtual void  sss(const s16 v) = 0;
		virtual void  sss(const u16 v) = 0;
		virtual void  sss(const s32 v) = 0;
		virtual void  sss(const u32 v) = 0;
		virtual void  sss(const s64 v) = 0;
		virtual void  sss(const u64 v) = 0;
		virtual void  sss(const bool v) = 0;
		virtual void  sss(const f32 v) = 0;
		virtual void  sss(const f64 v) = 0;
		virtual void  sss(void* v, const u32 len) = 0;

		virtual void  read(s8& v) = 0;
		virtual void  read(u8& v) = 0;
		virtual void  read(s16& v) = 0;
		virtual void  read(u16& v) = 0;
		virtual void  read(s32& v) = 0;
		virtual void  read(u32& v) = 0;
		virtual void  read(s64& v) = 0;
		virtual void  read(u64& v) = 0;
		virtual void  read(bool& v) = 0;
		virtual void  read(f32& v) = 0;
		virtual void  read(f64& v) = 0;
		virtual void  read(void* v, const u32 len) = 0;

		virtual void  parseCommand() = 0;
		virtual void  registerCommand(int cmd, void* container) = 0;
		virtual void  setOnConnect(TCPCLIENTNOTIFY_EVENT event) = 0;
		virtual void  setOnConnectSecure(TCPCLIENTNOTIFY_EVENT event) = 0;
		virtual void  setOnDisconnect(TCPCLIENTNOTIFY_EVENT event) = 0;
		virtual void  setOnExcept(TCPCLIENTNOTIFY_EVENT event) = 0;

	};

	extern ITcpServer* NewTcpServer();
	extern ITcpClient* NewTcpClient();

}

#endif