#include "INetBase.h"


#include <time.h>
#include <string>

#ifdef ____WIN32_
#else
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#endif

namespace func
{
	//全局变量
	char FileExePath[MAX_EXE_LEN];//EXE执行路径
	ConfigXML* __ServerInfo = nullptr;//服务器配置信息
	ConfigXML* __ClientInfo = nullptr;//客户端配置信息
	std::vector<ServerListXML*> __ServerListInfo;//服务器列表信息
	void(*MD5str)(char* output, unsigned char* input, int len) = NULL;


	bool InitData()
	{
		memset(FileExePath, 0, MAX_EXE_LEN);
#ifdef ____WIN32_
		//1、初始化路径 win32_API
		GetModuleFileNameA(NULL, (LPSTR)FileExePath, MAX_EXE_LEN);

		std::string str(FileExePath);
		size_t pos = str.find_last_of("\\");
		str = str.substr(0, pos + 1);

		memcpy(FileExePath, str.c_str(), MAX_EXE_LEN);

		printf("FileExePath:%s \n", FileExePath);
#else
		int ret = readlink("/proc/self/exe", FileExePath, MAX_EXE_LEN);
		std::string str(FileExePath);
		size_t pos = str.find_last_of("/");
		str = str.substr(0, pos + 1);
		memcpy(FileExePath, str.c_str(), MAX_EXE_LEN);

		printf("FileExePath:%s \n", FileExePath);
#endif

		return true;
	}
	u8 GetServerType(s32 sid)
	{
		if (sid >= 1000 && sid < 2000)      return func::S_TYPE_DB;
		else if (sid >= 2000 && sid < 3000) return func::S_TYPE_CENTER;
		else if (sid >= 3000 && sid < 4000) return func::S_TYPE_GAME;
		else if (sid >= 4000 && sid < 5000) return func::S_TYPE_GATE;
		else if (sid >= 5000 && sid < 6000) return func::S_TYPE_LOGIN;
		return func::S_TYPE_USER;
	}
	const char* getShutDownError(int id)
	{
		switch (id)
		{
		case 1001:return  "onRecv c==NULL";
		case 1002:return  "onRecv savedata full";
		case 1003:return  "postRecv error";
		case 1004:return  "postSend error";
		case 1005:return  "onSend len != sendBytes";
		case 1006:return  "onSend c==NULL";

		case 2001:return  "head error";
		case 2002:return  "timeout security error";
		case 2003:return  "timeout heart error";
		case 2004:return  "b error";
		case 2005:return  "e error";
		case 2006:return  "closeclient error";

		case 3001:return  "iscomplete=false";
		case 3002:return  "iscomplete=false overlapped=NULL";
		case 3003:return  "recvBytes=0";
		case 3004:return  "onaccept";
		case 3005:return  "sendBytes=0";
		default:
			return "no";
		}
	}
	const char* getCloseSocketError(int id)
	{
		switch (id)
		{
		case 1001:return  "postAccept1";
		case 1002:return  "postAccept2";
		case 2001:return  "closeSocket";
		case 2002:return  "closeSocket5";
		case 3001:return  "onAccpet";
		default:
			return "no";
		}
	}
	void setConsoleColor(u16 index)
	{
#ifdef ____WIN32_
		//0 = 黑色   1 = 蓝色   2 = 绿色  3 = 浅绿色 4 = 红色 5 = 紫色 6 = 黄色
		//7 = 白色   8 = 灰色   9 = 淡蓝色 A = 淡绿色 B = 淡浅绿色  C = 淡红色
		//D = 淡紫色 E = 淡黄色 F = 亮白色
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), index);
#endif
	}
}

namespace net
{
	void S_CLIENT_BASE::Init()
	{
		recvBuf = new char[func::__ServerInfo->ReceMax];
		sendBuf = new char[func::__ServerInfo->SendMax];
		Reset();
	}

	void S_CLIENT_BASE::Reset()
	{
#ifdef ____WIN32_
		socketfd = INVALID_SOCKET;
#else
		socketfd = -1;
#endif

		port = 0;
		ID = -1;
		rCode = func::__ServerInfo->RCode;
		recv_Head = 0;
		recv_Tail = 0;
		recv_TempHead = 0;
		recv_TempTail = 0;
		is_RecvCompleted = false;

		send_Head = 0;
		send_Tail = 0;
		send_TempTail = 0;
		is_Sending = false;
		is_SendCompleted = true;

		theadID = 0;
		time_Connet = (int)time(NULL);
		time_Heart = (int)time(NULL);
		time_Close = (int)time(NULL);

		memset(recvBuf, 0, func::__ServerInfo->ReceMax);
		memset(sendBuf, 0, func::__ServerInfo->SendMax);
		memset(ip, 0, MAX_IP_LEN);

		closeState = 0;
		state = func::S_Free;
	}
	//初始化客户端数据
	void S_SERVER_BASE::init(int sid)
	{
		ID = 0;
		serverID = sid;
		serverType = func::GetServerType(sid);
		recvBuf = new char[func::__ClientInfo->ReceMax];
		sendBuf = new char[func::__ClientInfo->SendMax];
		recvBuf_Temp = new char[func::__ClientInfo->ReceOne];

		port = 0;
		memset(ip, 0, 16);
		reset();
	}
	void S_SERVER_BASE::reset()
	{
		state = 0;
		rCode = func::__ClientInfo->RCode;
		recv_Head = 0;
		recv_Tail = 0;
		recv_TempHead = 0;
		recv_TempTail = 0;
		is_Recved = false;

		send_Head = 0;
		send_Tail = 0;
		send_TempTail = 0;
		is_Sending = false;
		is_SendCompleted = false;
		time_Heart = (int)time(NULL);
		time_AutoConnect = (int)time(NULL);

		memset(recvBuf, 0, func::__ClientInfo->ReceMax);
		memset(sendBuf, 0, func::__ClientInfo->SendMax);
		memset(recvBuf_Temp, 0, func::__ClientInfo->ReceOne);
	}
}