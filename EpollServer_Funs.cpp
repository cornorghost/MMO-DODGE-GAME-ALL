#include "EpollServer.h"
#ifndef ____WIN32_
#include <sys/socket.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <string.h>
using namespace net;


std::vector<IContainer*> __Commands;
void net::EpollServer::initCommands()
{
	__Commands.reserve(MAX_COMMAND_LEN);
	for (int i = 0; i < MAX_COMMAND_LEN; i++)
	{
		__Commands.emplace_back(nullptr);
	}
}
void net::EpollServer::registerCommand(int cmd, void* container)
{
	if (cmd >= MAX_COMMAND_LEN) return;
	IContainer* icon = (IContainer*)container;
	if (icon == nullptr) return;
	__Commands[cmd] = icon;
}


void net::EpollServer::parseCommand()
{
	for (int i = 0; i < Linkers->length; i++)
	{
		auto c = Linkers->Value(i);
		if (c == nullptr) continue;
		if (c->ID == -1) continue;
		if (c->state == func::S_Free) continue;
		if (c->state == func::S_NeedSave) continue;

		checkConnect(c);
		if (c->closeState == func::S_CLOSE_SHUTDOWN) continue;
		parseCommand(c);
		this->onSend(c);
	}
}

void net::EpollServer::parseCommand(S_CLIENT_BASE* c)
{
	if (!c->is_RecvCompleted) return;

	while (c->recv_Tail - c->recv_Head > 7)
	{
		char head[2];
		head[0] = c->recvBuf[c->recv_Head] ^ c->rCode;
		head[1] = c->recvBuf[c->recv_Head+1] ^ c->rCode;
		if (head[0] != func::__ServerInfo->Head[0] || head[1] != func::__ServerInfo->Head[1])
		{
			shutDown(c->socketfd, 0, c, 2001);
			return;
		}
		int len = (*(u32*)(c->recvBuf + c->recv_Head + 2)) ^ c->rCode;
		u16 cmd = (*(u16*)(c->recvBuf + c->recv_Head + 6)) ^ c->rCode;
		if (c->recv_Tail < c->recv_Head + len) break;

		c->recv_TempHead = c->recv_Head + 8;
		c->recv_TempTail = c->recv_Head + len;

		parseCommand(c, cmd);

		if (c->state < func::S_Connect)
		{
			return;
		}
		c->recv_Head += len;
	}

	c->is_RecvCompleted = false;
}


void net::EpollServer::parseCommand(S_CLIENT_BASE* c, u16 cmd)
{
	if (cmd < 65000)
	{
		if (cmd == CMD_HEART)
		{
			c->time_Heart = (int)time(NULL);
			int value = 0;
			read(c->ID, value);
			return;
		}
		auto container = __Commands[cmd];
		if (container == nullptr) return;

		container->onServerCommand(this, c, cmd);
		return;
	}

	switch (cmd)
	{
	case CMD_SECURITY:
		char a[20];
		sprintf(a, "%s_%d", func::__ServerInfo->SafeCode, c->rCode);
		memset(c->md5, 0, MAX_MD5_LEN);

		if (func::MD5str != NULL) func::MD5str(c->md5, (unsigned char*)a, strlen(a));

		char str5[MAX_MD5_LEN];
		memset(str5, 0, MAX_MD5_LEN);

		u32 version = 0;
		u32 len = 0;

		u32 c_id = 0;
		u8 c_type = 0;
		read(c->ID, c_id);
		read(c->ID, c_type);

		read(c->ID, version);
		read(c->ID, str5,MAX_MD5_LEN);

		if (version != func::__ServerInfo->Version)
		{
			begin(c->ID, CMD_SECURITY);
			sss(c->ID, (u16)1);
			end(c->ID);
			return;
		}
		int error = strcasecmp(c->md5, str5);
		if (error != 0)
		{
			begin(c->ID, CMD_SECURITY);
			sss(c->ID, (u16)2);
			end(c->ID);
			return;
		}
		c->state = func::S_ConnectSecure;
		c->clientID = c_id;
		c->clientType = c_type;

		begin(c->ID, CMD_SECURITY);
		sss(c->ID, (u16)0);
		end(c->ID);
	    
		this->updateSercurityCount(true);
		if (onSecurityEvent != nullptr) this->onSecurityEvent(this, c, 0);
	}
}

void net::EpollServer::checkConnect(S_CLIENT_BASE* c)
{
	int temp = 0;
	if (c->closeState == func::S_CLOSE_SHUTDOWN)
	{
		temp = (int)time(NULL) - c->time_Close;
		if (c->is_RecvCompleted && c->is_SendCompleted)
		{
			closeSocket(c->socketfd, c, 2001);
		}
		else if (temp > 3)
		{
			closeSocket(c->socketfd, c, 2002);
		}
		return;
	}
	temp = (int)time(NULL) - c->time_Connet;
	if (c->state == func::S_Connect)
	{
		if (temp > 10)
		{
			if (this->onTimeoutEvent != nullptr) this->onTimeoutEvent(this, c, 2002);
			shutDown(c->socketfd, 0, c, 2002);
			return;
		}
	}

	temp = (int)time(NULL) - c->time_Heart;
	if (temp > func::__ServerInfo->HeartTime)
	{
		if (this->onTimeoutEvent != nullptr) this->onTimeoutEvent(this, c, 2003);
		shutDown(c->socketfd, 0, c, 2003);
		return;
	}
}


void net::EpollServer::getSecurityCount(int& connum, int& securtiynum)
{
	connum = m_ConnectCount;
	securtiynum = m_SercurityCount;
}

S_CLIENT_BASE* EpollServer::getFreeLinker()
{
	std::lock_guard<std::mutex> guard(this->m_FindLinkMutex);
	if (m_LinkIndex >= Linkers->length) m_LinkIndex = 0;
	int curindex = m_LinkIndex;
	for (int i = curindex; i < Linkers->length; i++)
	{
		m_LinkIndex++;
		auto c = Linkers->Value(i);
		if (c->state == func::S_Free)
		{
			c->Reset();
			c->ID = i;
			c->state = func::S_Connect;
			return c;
		}
	}
	return NULL;
}

S_CLIENT_BASE* net::EpollServer::client(const int id, const u32 clientid)
{
	if (id < 0 || id >= Linkers->length) return nullptr;

	S_CLIENT_BASE * c = Linkers->Value(id);
	if (c->state >= func::S_ConnectSecure &&
		c->clientID > 0 &&
		c->clientID == clientid) return c;

	for (u32 i = 0; i < Linkers->length; i++)
	{
		c = Linkers->Value(i);
		if (c->clientID == 0)    continue;
		if (c->state < func::S_ConnectSecure) continue;
		if (c->clientID != clientid) continue;

		LOG_MSG("get client - %d\n", c->clientID);
		return c;
	}

	LOG_MSG("get client is error- %d -%d\n", c->clientID, clientid);
	return nullptr;
}

S_CLIENT_BASE* net::EpollServer::client(int socketfd, bool isseriuty)
{
	if (socketfd < 0 || socketfd >= MAX_USER_SOCKETFD) return nullptr;
	auto cindex = LinkersIndex->Value(socketfd);
	if (cindex == nullptr) return nullptr;
	if (cindex->index < 0) return nullptr;
	auto c = Linkers->Value(cindex->index);
	if (c == nullptr) return nullptr;
	if (isseriuty)
	{
		if (!c->isT(socketfd)) return nullptr;
	}
	return c;
}

S_CLIENT_BASE* net::EpollServer::client(const int id)
{
	if (id < 0 || id >= Linkers->length) return nullptr;
	auto c = Linkers->Value(id);
	return c;
}

bool net::EpollServer::isID_T(const s32 id)
{
	if (id < 0 || id >= Linkers->length) return false;
	return true;
}

bool net::EpollServer::isSecure_T(const s32 id, s32 secure)
{
	if (id < 0 || id >= Linkers->length) return false;
	auto c = Linkers->Value(id);
	if (c == nullptr) return false;
	if (c->state < secure) return false;

	return true;
}

bool net::EpollServer::isSecure_F_Close(const s32 id, s32 secure)
{
	if (id < 0 || id >= Linkers->length) return false;
	auto c = Linkers->Value(id);
	if (c == nullptr) return false;
	if (c->state >= secure) return false;
	//关闭
	shutDown(c->socketfd,0,c,2006);
	return true;
}




//生产者 
void net::EpollServer::begin(const int id, const u16 cmd)
{
	auto c = client(id);
	if (c == nullptr) return;

	if (c->send_Head == c->send_Tail)
	{
		c->send_Tail = 0;
		c->send_Head = 0;
	}
	c->send_TempTail = c->send_Tail;

	if (c->state > 0 &&
		c->is_Sending == false &&
		c->socketfd != -1 &&
		c->send_TempTail + 8 <= func::__ServerInfo->SendMax)
	{
		c->is_Sending = true;
		c->sendBuf[c->send_Tail + 0] = func::__ServerInfo->Head[0] ^ c->rCode;
		c->sendBuf[c->send_Tail + 1] = func::__ServerInfo->Head[1] ^ c->rCode;

		u16 newcmd = cmd ^ c->rCode;
		char* a = (char*)& newcmd;
		c->sendBuf[c->send_Tail + 6] = a[0];
		c->sendBuf[c->send_Tail + 7] = a[1];

		c->send_TempTail += 8;
		return;
	}
	shutDown(c->socketfd, 0, c, 2004);

}

void net::EpollServer::end(const int id)
{
	auto c = client(id);
	if (c == nullptr) return;
	if (c->is_Sending == false ||
		c->send_Tail + 8 > func::__ServerInfo->SendMax ||
		c->send_TempTail > func::__ServerInfo->SendMax ||
		c->send_Tail >= c->send_TempTail)
	{
		shutDown(c->socketfd, 0, c, 2005);
		return;
	}

	c->is_Sending = false;
	u32 len = (c->send_TempTail - c->send_Tail) ^ c->rCode;
	char* a = (char*)& len;
	c->sendBuf[c->send_Tail + 2] = a[0];
	c->sendBuf[c->send_Tail + 3] = a[1];
	c->sendBuf[c->send_Tail + 4] = a[2];
	c->sendBuf[c->send_Tail + 5] = a[3];

	c->send_Tail = c->send_TempTail;

}

void net::EpollServer::sss(const int id, const s8 v)
{
	auto c = client(id);
	if (c == nullptr) return;

	if (c->is_Sending && c->send_TempTail + 1 <= func::__ServerInfo->SendMax)
	{
		c->sendBuf[c->send_TempTail] = v;
		c->send_TempTail++;
		return;
	}
	c->is_Sending = false;
}

void net::EpollServer::sss(const int id, const u8 v)
{
	auto c = client(id);
	if (c == nullptr) return;

	if (c->is_Sending && c->send_TempTail + 1 <= func::__ServerInfo->SendMax)
	{
		c->sendBuf[c->send_TempTail] = v;
		c->send_TempTail++;
		return;
	}
	c->is_Sending = false;
}

void net::EpollServer::sss(const int id, const s16 v)
{
	auto c = client(id);
	if (c == nullptr) return;

	if (c->is_Sending && c->send_TempTail + 2 <= func::__ServerInfo->SendMax)
	{
		char* p = (char*)& v;
		for (int i = 0; i < 2; i++)
			c->sendBuf[c->send_TempTail + i] = p[i];
		c->send_TempTail += 2;
		return;
	}
	c->is_Sending = false;
}
void net::EpollServer::sss(const int id, const u16 v)
{
	auto c = client(id);
	if (c == nullptr) return;

	if (c->is_Sending && c->send_TempTail + 2 <= func::__ServerInfo->SendMax)
	{
		char* p = (char*)& v;
		for (int i = 0; i < 2; i++)
			c->sendBuf[c->send_TempTail + i] = p[i];
		c->send_TempTail += 2;
		return;
	}
	c->is_Sending = false;
}
void net::EpollServer::sss(const int id, const s32 v)
{
	auto c = client(id);
	if (c == nullptr) return;

	if (c->is_Sending && c->send_TempTail + 4 <= func::__ServerInfo->SendMax)
	{
		char* p = (char*)& v;
		for (int i = 0; i < 4; i++)
			c->sendBuf[c->send_TempTail + i] = p[i];
		c->send_TempTail += 4;
		return;
	}
	c->is_Sending = false;
}
void net::EpollServer::sss(const int id, const u32 v)
{
	auto c = client(id);
	if (c == nullptr) return;

	if (c->is_Sending && c->send_TempTail + 4 <= func::__ServerInfo->SendMax)
	{
		char* p = (char*)& v;
		for (int i = 0; i < 4; i++)
			c->sendBuf[c->send_TempTail + i] = p[i];
		c->send_TempTail += 4;
		return;
	}
	c->is_Sending = false;
}
void net::EpollServer::sss(const int id, const s64 v)
{
	auto c = client(id);
	if (c == nullptr) return;

	if (c->is_Sending && c->send_TempTail + 8 <= func::__ServerInfo->SendMax)
	{
		char* p = (char*)& v;
		for (int i = 0; i < 8; i++)
			c->sendBuf[c->send_TempTail + i] = p[i];
		c->send_TempTail += 8;
		return;
	}
	c->is_Sending = false;
}
void net::EpollServer::sss(const int id, const u64 v)
{
	auto c = client(id);
	if (c == nullptr) return;

	if (c->is_Sending && c->send_TempTail + 8 <= func::__ServerInfo->SendMax)
	{
		char* p = (char*)& v;
		for (int i = 0; i < 8; i++)
			c->sendBuf[c->send_TempTail + i] = p[i];
		c->send_TempTail += 8;
		return;
	}
	c->is_Sending = false;
}

void net::EpollServer::sss(const int id, const bool v)
{
	auto c = client(id);
	if (c == nullptr) return;

	if (c->is_Sending && c->send_TempTail + 1 <= func::__ServerInfo->SendMax)
	{
		c->sendBuf[c->send_TempTail] = v;
		c->send_TempTail++;
		return;
	}
	c->is_Sending = false;
}

void net::EpollServer::sss(const int id, const f32 v)
{
	auto c = client(id);
	if (c == nullptr) return;

	if (c->is_Sending && c->send_TempTail + 4 <= func::__ServerInfo->SendMax)
	{
		char* p = (char*)& v;
		for (int i = 0; i < 4; i++)
			c->sendBuf[c->send_TempTail + i] = p[i];
		c->send_TempTail += 4;
		return;
	}
	c->is_Sending = false;
}

void net::EpollServer::sss(const int id, const f64 v)
{
	auto c = client(id);
	if (c == nullptr) return;

	if (c->is_Sending && c->send_TempTail + 8 <= func::__ServerInfo->SendMax)
	{
		char* p = (char*)& v;
		for (int i = 0; i < 8; i++)
			c->sendBuf[c->send_TempTail + i] = p[i];
		c->send_TempTail += 8;
		return;
	}
	c->is_Sending = false;
}

void net::EpollServer::sss(const int id, void* v, const u32 len)
{
	auto c = client(id);
	if (c == nullptr) return;

	if (c->is_Sending && c->send_TempTail + len <= func::__ServerInfo->SendMax)
	{
		memcpy(&c->sendBuf[c->send_TempTail], v, len);
		c->send_TempTail += len;
		return;
	}
	c->is_Sending = false;
}

bool isValidClient(S_CLIENT_BASE* c, int num)
{
	if (c->ID == -1 ||
		c->state == func::S_Free ||
		c->recv_TempTail == 0 ||
		c->recvBuf == nullptr ||
		c->recv_TempHead + num > c->recv_TempTail)
	{
		return false;
	}
	return true;
}
void net::EpollServer::read(const int id, s8& v)
{
	auto c = client(id);
	if (c == nullptr) return;
	if (isValidClient(c, 1) == false)
	{
		v = 0;
		return;
	}

	v = (*(s8*)(c->recvBuf + c->recv_TempHead));
	c->recv_TempHead++;
}

void net::EpollServer::read(const int id, u8& v)
{
	auto c = client(id);
	if (c == nullptr) return;
	if (isValidClient(c, 1) == false)
	{
		v = 0;
		return;
	}

	v = (*(s8*)(c->recvBuf + c->recv_TempHead));
	c->recv_TempHead++;
}

void net::EpollServer::read(const int id, s16& v)
{
	auto c = client(id);
	if (c == nullptr) return;
	if (isValidClient(c, 2) == false)
	{
		v = 0;
		return;
	}

	v = (*(s16*)(c->recvBuf + c->recv_TempHead));
	c->recv_TempHead+=2;
}
void net::EpollServer::read(const int id, u16& v)
{
	auto c = client(id);
	if (c == nullptr) return;
	if (isValidClient(c, 2) == false)
	{
		v = 0;
		return;
	}

	v = (*(u16*)(c->recvBuf + c->recv_TempHead));
	c->recv_TempHead+=2;
}
void net::EpollServer::read(const int id, s32& v)
{
	auto c = client(id);
	if (c == nullptr) return;
	if (isValidClient(c, 4) == false)
	{
		v = 0;
		return;
	}

	v = (*(s32*)(c->recvBuf + c->recv_TempHead));
	c->recv_TempHead+=4;
}
void net::EpollServer::read(const int id, u32& v)
{
	auto c = client(id);
	if (c == nullptr) return;
	if (isValidClient(c, 4) == false)
	{
		v = 0;
		return;
	}

	v = (*(u32*)(c->recvBuf + c->recv_TempHead));
	c->recv_TempHead+=4;
}
void net::EpollServer::read(const int id, s64&v)
{
	auto c = client(id);
	if (c == nullptr) return;
	if (isValidClient(c, 8) == false)
	{
		v = 0;
		return;
	}

	v = (*(s64*)(c->recvBuf + c->recv_TempHead));
	c->recv_TempHead += 8;
}
void net::EpollServer::read(const int id, u64& v)
{
	auto c = client(id);
	if (c == nullptr) return;
	if (isValidClient(c, 8) == false)
	{
		v = 0;
		return;
	}

	v = (*(u64*)(c->recvBuf + c->recv_TempHead));
	c->recv_TempHead += 8;
}

void net::EpollServer::read(const int id, bool& v)
{
	auto c = client(id);
	if (c == nullptr) return;
	if (isValidClient(c, 1) == false)
	{
		v = 0;
		return;
	}

	v = (*(bool*)(c->recvBuf + c->recv_TempHead));
	c->recv_TempHead += 1;
}

void net::EpollServer::read(const int id, f32& v)
{
	auto c = client(id);
	if (c == nullptr) return;
	if (isValidClient(c, 4) == false)
	{
		v = 0;
		return;
	}

	v = (*(f32*)(c->recvBuf + c->recv_TempHead));
	c->recv_TempHead += 4;
}

void net::EpollServer::read(const int id, f64& v)
{
	auto c = client(id);
	if (c == nullptr) return;
	if (isValidClient(c, 8) == false)
	{
		v = 0;
		return;
	}

	v = (*(f32*)(c->recvBuf + c->recv_TempHead));
	c->recv_TempHead += 8;
}

void net::EpollServer::read(const int id, void* v, const u32 len)
{
	auto c = client(id);
	if (c == nullptr) return;
	if (isValidClient(c, len) == false)
	{
		v = 0;
		return;
	}

	memcpy(v, &c->recvBuf[c->recv_TempHead], len);
	c->recv_TempHead += len;
}

void net::EpollServer::setOnClientAccept(TCPSERVERNOTIFY_EVENT event)
{
	onAcceptEvent = event;
}

void net::EpollServer::setOnClientSecureConnect(TCPSERVERNOTIFY_EVENT event)
{
	onSecurityEvent = event;
}

void net::EpollServer::setOnClientDisconnect(TCPSERVERNOTIFY_EVENT event)
{
	onDisconnectEvent = event;
}

void net::EpollServer::setOnClientTimeout(TCPSERVERNOTIFY_EVENT event)
{
	onTimeoutEvent = event;
}

void net::EpollServer::setOnClientExcept(TCPSERVERNOTIFY_EVENT event)
{
	onExceptEvent = event;
}




#endif