#ifndef  __ICONTAINER_H
#define  __ICONTAINER_H

#include "INetBase.h"
#include  "malloc.h"
template<class T>
class HashArray
{
public:
	int				length;//总的数据长度
	int				size;//这个数据结构T类型的长度
	void* pointer;//连续的内存数据结构
public:
	HashArray()
	{
		size = sizeof(T);
		length = 0;
		pointer = nullptr;
	}
	HashArray(int counter)
	{
		if (counter < 1) return;
		size = sizeof(T);
		if (size == 0) return;
		length = counter;
		pointer = malloc(length * size);
	}

	virtual ~HashArray()
	{
		if (pointer != nullptr)
		{
			free(pointer);
			pointer = nullptr;
		}
	}

	T* Value(const int index)
	{
		T* tmp = (T*)pointer;
		return &tmp[index];
	}
};

class IContainer
{
public:
	IContainer() {}
	virtual ~IContainer() {}
	virtual void  onInit() {}
	virtual void  onUpdate() {}
	virtual bool  onServerCommand(net::ITcpServer* ts, net::S_CLIENT_BASE* c, const u16 cmd) { return false; }
	virtual bool  onClientCommand(net::ITcpClient* tc, const u16 cmd) { return false; }
	virtual bool  OnDBCommand(void* buff) { return false; }
};


#endif // ! __ICONTAINER_H
