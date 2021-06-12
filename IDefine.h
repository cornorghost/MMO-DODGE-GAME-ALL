#ifndef __IDEFINE_H
#define __IDEFINE_H

#include <vector>
#include <cstring>

#ifdef ____WIN32_
#include <winsock2.h>
#pragma comment(lib,"ws2_32") 
#endif

//
#define MAX_USER_SOCKETFD   1000000 
#define MAX_EXE_LEN         200      
#define MAX_FILENAME_LEN    250     
#define SIO_KEEPALIVE_VALS  IOC_IN | IOC_VENDOR | 4 
#define MAX_MD5_LEN  35 
#define MAX_IP_LEN   20 
#define MAX_COMMAND_LEN     65535
#define MAX_IP_ONE_COUNT    20

#define LOG_MSG printf 

#define CMD_HEART     60000
#define CMD_RCODE     65001
#define CMD_SECURITY  65002


#ifdef ____WIN32_
#define RELEASE_POINTER(p)	{if(p != NULL) {delete p; p = NULL;}}
#define RELEASE_HANDLE(h)	{if(h != NULL && h != INVALID_HANDLE_VALUE) { CloseHandle(h); h = INVALID_HANDLE_VALUE; }}
#define RELEASE_SOCKET(s)	{if(s != INVALID_SOCKET) { closesocket(s); s = INVALID_SOCKET; }}
#endif

typedef signed char          s8;
typedef signed short         s16;
typedef signed int           s32;
typedef signed long long     s64;
typedef unsigned char        u8;
typedef unsigned short       u16;
typedef unsigned int         u32;
typedef unsigned long long   u64;
typedef float		f32;
typedef double		f64;




namespace func
{
	enum SOCKET_CLOSE
	{
		S_CLOSE_FREE = 0,
		S_CLOSE_ACCEPT = 1,   //连接出错关闭
		S_CLOSE_SHUTDOWN = 2, //关闭连接
		S_CLOSE_CLOSE = 3     //正式关闭
	};
	enum SOCKET_CONTEXT_STATE
	{
		SC_WAIT_ACCEPT = 0,
		SC_WAIT_RECV = 1,
		SC_WAIT_SEND = 2,
		SC_WAIT_RESET = 3,
	};
	//服务器
	enum S_SOCKET_STATE
	{
		S_Free = 0,
		S_Connect = 1,
		S_ConnectSecure = 2,
		S_Login = 3,
		S_NeedSave = 4,
		S_Saving = 5
	};
	//客户端SOCKET枚举状态
	enum C_SOCKET_STATE
	{
		C_Free = 0,
		C_ConnectTry = 1,
		C_Connect = 2,
		C_ConnectSecure = 3,
		C_Login = 4
	};

	//0 玩家 1-DB 2-中心服务器 3-游戏服务器 4-网关服务器 5-登录服务器
	enum E_SERVER_TYPE
	{
		S_TYPE_USER = 0x00,
		S_TYPE_DB,
		S_TYPE_CENTER,
		S_TYPE_GAME,
		S_TYPE_GATE,
		S_TYPE_LOGIN
	};

	struct ConfigXML
	{
		s32   ID;     //服务器ID
		u8    Type;   //服务器类型 1-DB 2-中心服务器 3-地图服务器 4-网关服务器 
		u16   Port;   //服务器端口号
		s32   MaxPlayer;//最大玩家数量
		s32   MaxConnect;//最大客户端连接数量
		u8    RCode;
		s32   Version;
		s32   ReceOne;
		s32   ReceMax;
		s32   SendOne;
		s32   SendMax;
		s32   HeartTime;//心跳时间
		s32   AutoTime;//自动重连时间
		s32   MaxAccpet; //最大投递连接数量
		s32   MaxRece;   //最大收到消息数量
		s32   MaxSend;   //最大发送信息数量
		char  SafeCode[20];
		char  Head[3];
		char  IP[MAX_IP_LEN];
	};
	struct ServerListXML
	{
		s32   ID;
		u16   Port;
		char  IP[MAX_IP_LEN];
	};

	extern char FileExePath[MAX_EXE_LEN];
	extern ConfigXML* __ServerInfo;
	extern ConfigXML* __ClientInfo;
	extern std::vector<ServerListXML*> __ServerListInfo;
	extern u8 GetServerType(s32 sid);
	extern void(*MD5str)(char* output, unsigned char* input, int len);
	extern bool InitData();

	extern const char* getShutDownError(int id);
	extern const char* getCloseSocketError(int id);
	extern void setConsoleColor(u16 index);
	
}
#endif 