#include "TcpClient.h"
#include "IContainer.h"

#include <string.h>


namespace net
{
	//业务层指令集合
	std::vector<IContainer*> __Commands;

	//******************************************************************
	void  TcpClient::initCommands()
	{
		if (__Commands.size() == MAX_COMMAND_LEN) return;

		__Commands.reserve(MAX_COMMAND_LEN);
		for (int i = 0; i < MAX_COMMAND_LEN; i++)
		{
			__Commands.emplace_back(nullptr);
		}
	}
	//注册
	void  TcpClient::registerCommand(int cmd, void* container)
	{
		if (cmd >= MAX_COMMAND_LEN) return;
		IContainer * icon = (IContainer*)container;
		if (icon == nullptr) return;
		__Commands[cmd] = icon;
	}
	//更新
	void TcpClient::parseCommand()
	{
		if (socketfd < 0) return;
		auto c = getData();
		if (c->state < func::C_Connect) return;

		//发送心跳包
		onHeart();
		//解析指令
		//if (c->recv_Tail <= c->recv_Head) return;
		while (c->recv_Tail - c->recv_Head > 7)
		{
			//1、解析头
			char head[2];
			head[0] = c->recvBuf[c->recv_Head] ^ c->rCode;
			head[1] = c->recvBuf[c->recv_Head + 1] ^ c->rCode;

			if (head[0] != func::__ClientInfo->Head[0] || head[1] != func::__ClientInfo->Head[1])
			{
				disconnectServer(2001, "head error...");
				return;
			}

			s32 cl = (*(u32*)(c->recvBuf + c->recv_Head + 2)) ^ c->rCode;
			u16 cmd = (*(u16*)(c->recvBuf + c->recv_Head + 6)) ^ c->rCode;

			//2、长度不够 需要继续等待
			if (c->recv_Tail < c->recv_Head + cl) break;
			c->recv_TempHead = c->recv_Head + 8;
			c->recv_TempTail = c->recv_Head + cl;
			parseCommand(cmd);
			if (c->state < func::C_Connect) return;

			//4、增加读取长度
			c->recv_Head += cl;

			//printf("readdata : %d ..%d:%d.\n", c->State, c->Rece_B, c->Rece_E);
		}
		//发送数据
		this->onSend();
	}
	void TcpClient::onHeart()
	{
		auto c = getData();
		if (c->state < func::C_ConnectSecure) return;

		s32 tempTime = (s32)time(NULL) - m_data.time_Heart;
		if (tempTime >= func::__ClientInfo->HeartTime)
		{
			m_data.time_Heart = (s32)time(NULL);
			begin(CMD_HEART);
			sss((u32)9999);
			end();

		}
	}
	void TcpClient::parseCommand(u16 cmd)
	{
		if (cmd < 65000)
		{
			auto container = __Commands[cmd];
			if (container == nullptr)
			{
				LOG_MSG("--------client command not register...%d \n", cmd);
				return;
			}

			//触发事件
			container->onClientCommand(this, cmd);
			return;
		}

		switch (cmd)
		{
		case CMD_RCODE:
		{
			auto c = getData();
			read(c->rCode);

			char a[20];
			sprintf(a, "%s_%d", func::__ClientInfo->SafeCode, c->rCode);
			memset(c->md5, 0, sizeof(c->md5));
			if (func::MD5str != NULL) func::MD5str(c->md5, (unsigned char*)a, strlen(a));

			//发送MD5验证
			begin(CMD_SECURITY);
			sss(func::__ServerInfo->ID);
			sss(func::__ServerInfo->Type);
			sss(func::__ClientInfo->Version);
			sss(c->md5, MAX_MD5_LEN);
			end();
		}
		break;
		case CMD_SECURITY:
		{
			auto c = getData();
			u16 kind = 0;
			read(kind);
			//printf("-----------client securrity...%d \n", kind);
			if (kind > 0)
			{
				//1 版本不对 2 MD5错误 
				if (onExceptEvent != nullptr) onExceptEvent(this, kind);
				break;
			}

			c->state = func::C_ConnectSecure;
			if (onSecureEvent != nullptr) onSecureEvent(this, 0);
		}

		break;
		}
	}
	//**********************************************************************
	//**********************************************************************
	void TcpClient::begin(const u16 cmd)
	{
		auto c = getData();
		//头尾相等
		if (c->send_Head == c->send_Tail)
		{
			c->send_Tail = 0;
			c->send_Head = 0;
		}
		c->send_TempTail = c->send_Tail;

		if (c->state >= func::C_Connect &&
			c->is_Sending == false &&
			socketfd > 0 &&
			c->send_Tail + 8 <= func::__ClientInfo->SendMax)
		{
			c->is_Sending = true;
			c->sendBuf[c->send_Tail + 0] = func::__ClientInfo->Head[0] ^ c->rCode;
			c->sendBuf[c->send_Tail + 1] = func::__ClientInfo->Head[1] ^ c->rCode;

			u16 newcmd = cmd ^ c->rCode;
			char* a = (char*)& newcmd;
			c->sendBuf[c->send_Tail + 6] = a[0];
			c->sendBuf[c->send_Tail + 7] = a[1];

			c->send_TempTail += 8;
			return;
		}

		disconnectServer(6001, "b error...");
	}

	void TcpClient::end()
	{
		auto c = getData();
		if (c->state == func::C_Free ||
			c->is_Sending == false ||
			socketfd < 0 ||
			c->send_Tail + 8 > func::__ClientInfo->SendMax ||
			c->send_TempTail > func::__ClientInfo->SendMax ||
			c->send_Tail >= c->send_TempTail)
		{
			disconnectServer(6002, "e error...");
			return;
		}

		c->is_Sending = false;
		u32 len = (c->send_TempTail - c->send_Tail) ^ c->rCode;
		char* a = (char*)& len;
		c->sendBuf[c->send_Tail + 2] = a[0];
		c->sendBuf[c->send_Tail + 3] = a[1];
		c->sendBuf[c->send_Tail + 4] = a[2];
		c->sendBuf[c->send_Tail + 5] = a[3];

		//最后结束赋值
		c->send_Tail = c->send_TempTail;
	}

	void TcpClient::sss(const s8 v)
	{
		auto c = getData();
		if (c->is_Sending && c->send_TempTail + 1 < func::__ClientInfo->SendMax)
		{
			c->sendBuf[c->send_TempTail] = v;
			c->send_TempTail++;
			return;
		}

		c->is_Sending = false;
	}

	void TcpClient::sss(const u8 v)
	{
		auto c = getData();
		if (c->is_Sending && c->send_TempTail + 1 < func::__ClientInfo->SendMax)
		{
			c->sendBuf[c->send_TempTail] = v;
			c->send_TempTail++;
			return;
		}

		c->is_Sending = false;
	}

	void TcpClient::sss(const s16 v)
	{
		auto c = getData();
		if (c->is_Sending && c->send_TempTail + 2 < func::__ClientInfo->SendMax)
		{
			char* p = (char*)& v;
			for (int i = 0; i < 2; i++)
				c->sendBuf[c->send_TempTail + i] = p[i];

			c->send_TempTail += 2;
			return;
		}

		c->is_Sending = false;
	}

	void TcpClient::sss(const u16 v)
	{
		auto c = getData();
		if (c->is_Sending && c->send_TempTail + 2 < func::__ClientInfo->SendMax)
		{
			char* p = (char*)& v;
			for (int i = 0; i < 2; i++)
				c->sendBuf[c->send_TempTail + i] = p[i];

			c->send_TempTail += 2;
			return;
		}

		c->is_Sending = false;
	}

	void TcpClient::sss(const s32 v)
	{
		auto c = getData();
		if (c->is_Sending && c->send_TempTail + 4 < func::__ClientInfo->SendMax)
		{
			char* p = (char*)& v;
			for (int i = 0; i < 4; i++)
				c->sendBuf[c->send_TempTail + i] = p[i];

			c->send_TempTail += 4;
			return;
		}

		c->is_Sending = false;
	}

	void TcpClient::sss(const u32 v)
	{
		auto c = getData();
		if (c->is_Sending && c->send_TempTail + 4 < func::__ClientInfo->SendMax)
		{
			char* p = (char*)& v;
			for (int i = 0; i < 4; i++)
				c->sendBuf[c->send_TempTail + i] = p[i];

			c->send_TempTail += 4;
			return;
		}

		c->is_Sending = false;
	}

	void TcpClient::sss(const s64 v)
	{
		auto c = getData();
		if (c->is_Sending && c->send_TempTail + 8 < func::__ClientInfo->SendMax)
		{
			char* p = (char*)& v;
			for (int i = 0; i < 8; i++)
				c->sendBuf[c->send_TempTail + i] = p[i];

			c->send_TempTail += 8;
			return;
		}

		c->is_Sending = false;
	}

	void TcpClient::sss(const u64 v)
	{
		auto c = getData();
		if (c->is_Sending && c->send_TempTail + 8 < func::__ClientInfo->SendMax)
		{
			char* p = (char*)& v;
			for (int i = 0; i < 8; i++)
				c->sendBuf[c->send_TempTail + i] = p[i];

			c->send_TempTail += 8;
			return;
		}

		c->is_Sending = false;
	}

	void TcpClient::sss(const bool v)
	{
		auto c = getData();
		if (c->is_Sending && c->send_TempTail + 1 < func::__ClientInfo->SendMax)
		{
			char* p = (char*)& v;
			c->sendBuf[c->send_TempTail] = v;
			c->send_TempTail += 1;
			return;
		}

		c->is_Sending = false;
	}

	void TcpClient::sss(const f32 v)
	{
		auto c = getData();
		if (c->is_Sending && c->send_TempTail + 4 < func::__ClientInfo->SendMax)
		{
			char* p = (char*)& v;
			for (int i = 0; i < 4; i++)
				c->sendBuf[c->send_TempTail + i] = p[i];

			c->send_TempTail += 4;
			return;
		}

		c->is_Sending = false;
	}

	void TcpClient::sss(const f64 v)
	{
		auto c = getData();
		if (c->is_Sending && c->send_TempTail + 8 < func::__ClientInfo->SendMax)
		{
			char* p = (char*)& v;
			for (int i = 0; i < 8; i++)
				c->sendBuf[c->send_TempTail + i] = p[i];

			c->send_TempTail += 8;
			return;
		}

		c->is_Sending = false;
	}

	void TcpClient::sss(void* v, const u32 len)
	{
		auto c = getData();
		if (c->is_Sending && c->send_TempTail + len < func::__ClientInfo->SendMax)
		{
			memcpy(&c->sendBuf[c->send_TempTail], v, len);

			c->send_TempTail += len;
			return;
		}
		c->is_Sending = false;
	}
	//*******************************************************************
	//*******************************************************************
	//*******************************************************************
	bool isValid(S_SERVER_BASE* c, s32 value)
	{
		if (c->state == func::C_Free ||
			c->recv_TempTail == 0 ||
			c->recv_TempHead + value > c->recv_TempTail)
		{
			return false;
		}
		return true;
	}

	void TcpClient::read(s8& v)
	{
		auto c = getData();
		if (isValid(c, 1) == false)
		{
			v = 0;
			return;
		}
		v = (*(s8*)(c->recvBuf + c->recv_TempHead));
		c->recv_TempHead++;
	}

	void TcpClient::read(u8 & v)
	{
		auto c = getData();
		if (isValid(c, 1) == false)
		{
			v = 0;
			return;
		}
		v = (*(u8*)(c->recvBuf + c->recv_TempHead));
		c->recv_TempHead++;
	}

	void TcpClient::read(s16 & v)
	{
		auto c = getData();
		if (isValid(c, 1) == false)
		{
			v = 0;
			return;
		}
		v = (*(s16*)(c->recvBuf + c->recv_TempHead));
		c->recv_TempHead += 2;
	}

	void TcpClient::read(u16 & v)
	{
		auto c = getData();
		if (isValid(c, 2) == false)
		{
			v = 0;
			return;
		}
		v = (*(u16*)(c->recvBuf + c->recv_TempHead));
		c->recv_TempHead += 2;
	}

	void TcpClient::read(s32 & v)
	{
		auto c = getData();
		if (isValid(c, 4) == false)
		{
			v = 0;
			return;
		}
		v = (*(s32*)(c->recvBuf + c->recv_TempHead));
		c->recv_TempHead += 4;
	}

	void TcpClient::read(u32 & v)
	{
		auto c = getData();
		if (isValid(c, 4) == false)
		{
			v = 0;
			return;
		}
		v = (*(u32*)(c->recvBuf + c->recv_TempHead));
		c->recv_TempHead += 4;
	}

	void TcpClient::read(s64 & v)
	{
		auto c = getData();
		if (isValid(c, 8) == false)
		{
			v = 0;
			return;
		}
		v = (*(s64*)(c->recvBuf + c->recv_TempHead));
		c->recv_TempHead += 8;
	}

	void TcpClient::read(u64 & v)
	{
		auto c = getData();
		if (isValid(c, 8) == false)
		{
			v = 0;
			return;
		}
		v = (*(u64*)(c->recvBuf + c->recv_TempHead));
		c->recv_TempHead += 8;
	}

	void TcpClient::read(bool& v)
	{
		auto c = getData();
		if (isValid(c, 1) == false)
		{
			v = 0;
			return;
		}
		v = (*(bool*)(c->recvBuf + c->recv_TempHead));
		c->recv_TempHead += 1;
	}

	void TcpClient::read(f32 & v)
	{
		auto c = getData();
		if (isValid(c, 4) == false)
		{
			v = 0;
			return;
		}
		v = (*(f32*)(c->recvBuf + c->recv_TempHead));
		c->recv_TempHead += 4;
	}

	void TcpClient::read(f64 & v)
	{
		auto c = getData();
		if (isValid(c, 8) == false)
		{
			v = 0;
			return;
		}
		v = (*(f64*)(c->recvBuf + c->recv_TempHead));
		c->recv_TempHead += 8;
	}

	void TcpClient::read(void* v, const u32 len)
	{
		auto c = getData();
		if (isValid(c, len) == false)
		{
			v = 0;
			return;
		}
		memcpy(v, &c->recvBuf[c->recv_TempHead], len);
		c->recv_TempHead += len;
	}


	void TcpClient::setOnConnect(TCPCLIENTNOTIFY_EVENT event)
	{
		onAcceptEvent = event;
	}

	void TcpClient::setOnConnectSecure(TCPCLIENTNOTIFY_EVENT event)
	{
		onSecureEvent = event;
	}

	void TcpClient::setOnDisconnect(TCPCLIENTNOTIFY_EVENT event)
	{
		onDisconnectEvent = event;
	}

	void TcpClient::setOnExcept(TCPCLIENTNOTIFY_EVENT event)
	{
		onExceptEvent = event;
	}


}