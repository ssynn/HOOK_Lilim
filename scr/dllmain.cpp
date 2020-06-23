// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <fstream>
#include <map>
#include <string>
#include <vector>
using namespace std;


enum WildcardByte { XX = 0x11 };
ifstream infile;
map<string, string>jp_chs;
char dictName[MAX_PATH];
wchar_t iniPath[MAX_PATH];
wchar_t dirPath[MAX_PATH];

void* OpenProcessAddr;// = (void*)0x453E80;
int* textAddr;// = (int*)0x4BFBE0;
int* nameAddr;// = (int*)0x4BFEE0;
DWORD oldProtect;
BYTE JmpByte[5];
BYTE OldByte[5];

void* OutputSelectionAddr;// = (void*)0x45C4E0;
int* PointersPage;// = (int*)0x4BFA84;
DWORD oldProtextSelection;
BYTE JmpByteSelection[5];
BYTE OldByteSelection[5];
uintptr_t processStartAddress, processStopAddress;

typedef unsigned long dword_t;

void Hook();
void UnHook();
void myFunc();
void InitGlobal();
void loadIni();
void FillRange();
void loadJpChs();
void HookSelection();
void UnHookSelection();
//void ReplaceSelection();
void __fastcall ReplaceSelection2(void* pThis);


DWORD findBytes(const void* pattern, DWORD patternSize, DWORD lowerBound, DWORD upperBound);


BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		InitGlobal();
		loadIni();
		loadJpChs();
		Hook();
		HookSelection();
		break;
	case DLL_PROCESS_DETACH:
		UnHook();
		UnHookSelection();
		break;
	}
	return TRUE;
}


void Log(int data)
{
	ofstream outtext("log.txt", ios::binary | ios::app);
	//outtext.write(text, strlen(text));
	outtext << hex << data << endl;
	outtext.close();
}


void Hook()
{
	// 1. 初始化地址
	void* addr = OpenProcessAddr;

	// 2. Hook
	//一般代码段是不可写的，需要改成可写
	VirtualProtect((LPVOID)addr, 5, PAGE_EXECUTE_READWRITE, &oldProtect);

	// 修改前面的5个字节为jmp 跳转到我们的代码.
	// 内联Hook 跳转偏移计算方式:跳转偏移=目标地址-指令地址-5
	// jmp 的OpCode 为:0xE9
	JmpByte[0] = 0xE9;
	*(DWORD*)&JmpByte[1] = (DWORD)myFunc - (DWORD)addr - (DWORD)5;

	// 保存原先字节
	memcpy(OldByte, (void*)addr, 5);

	// 替换原先字节
	memcpy((void*)addr, JmpByte, 5);

}


void UnHook()
{
	// 恢复原先字节
	memcpy((void*)OpenProcessAddr, OldByte, 5);
	// 恢复属性
	DWORD p;
	VirtualProtect((LPVOID)OpenProcessAddr, 5, oldProtect, &p);
}


void loadJpChs()
{
	ifstream infile(dictName, ios::binary | ios::in);

	char buff[1000] = {};
	int buffPos = 0;
	bool isJp = true;
	string jp;
	int cnt = 0;

	int length;
	char* buffer;
	infile.seekg(0, std::ios::end);    // go to the end
	length = infile.tellg();           // report location (this is the length)
	infile.seekg(0, std::ios::beg);    // go back to the beginning
	buffer = new char[length];         // allocate memory for a buffer of appropriate dimension
	infile.read(buffer, length);       // read the whole file into the buffer
	infile.close();

	for (int j = 0; j < length; j++)
	{
		char i = buffer[j];
		if (i == 0xFF)
		{
			break;
		}
		if (i == 0)
		{
			string temp(buff);
			if (isJp)
			{
				isJp = !isJp;
				jp = temp;
			}
			else
			{
				isJp = !isJp;
				jp_chs[jp] = temp;
				jp.clear();
			}
			memset(buff, 0, 1000);
			buffPos = 0;
		}
		else
		{
			buff[buffPos] = i;
			buffPos++;
		}
	}
}


void codeEdit(void* dst, const void* scr, int size)
{
	DWORD old;
	VirtualProtect(dst, size, PAGE_EXECUTE_READWRITE, &old);
	memcpy(dst, scr, size);
}


void InitGlobal()
{
	//char** table;
	vector<vector<unsigned char>> table = {
		{ 0x83, 0xC4, 0x08, 0x83, 0xFF, 0x02 },										// log函数
		{ 0x53, 0x8B, 0xD9, 0x56, 0x8B, 0x35 },										// 选择支HOOK点
		{ 0xFF, 0xD5, 0x68, 0x00, 0x00, 0x01, 0x00, 0x6A, 0x08, 0x50, 0xFF, 0xD6},	// 文本全局变量
		{ 0x53, 0x53, 0x53, 0x53, 0x53, 0x53, 0xB9, 0x02, 0x00, 0x00, 0x00, 0xE8},	// 人名全局变量
		{ 0x83, 0xC4, 0x08, 0x33, 0xC9, 0x39, 0x37, 0x74},							// 选择支全局变量
		{ 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x64},										// 选择支边界检查
		{ 0x8A, 0x03, 0x57, 0x33, 0xFF, 0x3C, 0x81},								// 文字边界检查
		{ 0x88, 0x5E, 0x57, 0x2B, 0xD0, 0x8D, 0x64, 0x24},							// 字符集
		{ 0x81, 0x79, 0x00, 0x00},													//【
		{ 0x81, 0x7A, 0x00, 0x00},													// 】
		{ 0x82, 0x6C, 0x82, 0x72, 0x20}
	};

	vector<vector<unsigned char>>newBytes = {
		{},
		{},
		{},
		{},
		{},
		{0xFE},
		{0xFE},
		{0x86},
		{0xA1, 0xBE},
		{0xA1, 0xBF},
		{0xba, 0xda, 0xcc, 0xe5, 0x00}
	};

	int offset[] = { -0x69, -0x1A, 0x12, 0x15, -0x4, 0x41, 0xA, -0xA, 0, 0, 0 };

	FillRange();
	Log(processStartAddress);
	Log(processStopAddress);

	for (int i = 0; i < table.size(); i++)
	{
		char* patt = new char[table[i].size()];
		memcpy(patt, &table[i][0], table[i].size());
		void* pos = (void*)findBytes(patt, table[i].size(), processStartAddress, processStopAddress);
		pos = (void*)((int)pos + offset[i]);
		switch (i)
		{
		case 0:
			OpenProcessAddr = pos;
			break;
		case 1:
			OutputSelectionAddr = pos;
			break;
		case 2:
			textAddr = (int*)*(int*)pos;
			break;
		case 3:
			nameAddr = (int*)*(int*)pos;
			break;
		case 4:
			PointersPage = (int*)*(int*)pos;
			break;
		default:
			codeEdit((char*)pos, (char*)&newBytes[i][0], newBytes[i].size());
			break;
		}
		delete[]patt;
	}
	Log((int)OpenProcessAddr);
	Log((int)OutputSelectionAddr);
	Log((int)textAddr);
	Log((int)nameAddr);
	Log((int)PointersPage);
}


void loadIni()
{
	wchar_t dict[MAX_PATH];
	GetCurrentDirectoryW(MAX_PATH, dirPath);
	wsprintfW(iniPath, L"%ls\\%ls", dirPath, L"hook.ini");
	// 加载字典名
	GetPrivateProfileStringW(L"FileName", L"DICT", L"", dict, MAX_PATH, iniPath);
	WideCharToMultiByte(CP_ACP, 0, dict, -1, dictName, MAX_PATH, NULL, NULL);
	//// Hook函数的地址
	//OpenProcessAddr = (void*)GetPrivateProfileIntW(L"FuncAddress", L"TEXTFUNC", 0, iniPath);
	//OutputSelectionAddr = (void*)GetPrivateProfileIntW(L"FuncAddress", L"BTNFUNC", 0, iniPath);

	//// 全局变量的地址
	//textAddr = (int*)GetPrivateProfileIntW(L"Text", L"TEXTADDR", 0, iniPath);
	//nameAddr = (int*)GetPrivateProfileIntW(L"Text", L"NAMEADDR", 0, iniPath);
	//PointersPage = (int*)GetPrivateProfileIntW(L"Text", L"BTNTEXTADDR", 0, iniPath);
}


void myFunc()
{
	//printf("oldProtect: %d\nOpenProcessAddr: %x\nJmpByte: %x", oldProtect, OpenProcessAddr, *(int*)&JmpByte[1]);

	char* p = (char*)*textAddr;
	char* pWrite = p;
	char* pName = (char*)nameAddr;

	char buffer[1000] = { 0 };
	int cnt = 0;
	while (cnt < 1000 && *p)
	{
		buffer[cnt] = *p;
		p++;
		cnt++;
	}

	// 在scenario.txt写入提取的文本
	/*buffer[cnt] = '\n';
	outtext.write(buffer, strlen(buffer));*/

	// 替换文本
	string temp(buffer);
	auto vk = jp_chs.find(temp);
	char* newText = NULL;
	if (vk != jp_chs.end())
	{
		// 替换文本
		newText = (char*)vk->second.c_str();

		for (int i = 0; i < strlen(newText); i++)
		{
			*pWrite = newText[i];
			pWrite++;
		}

		// 替换人名
		if (newText[0] == 0x5B)
		{
			for (int i = 1; i < vk->second.find(0x5D); i++)
			{
				*pName = newText[i];
				pName++;
			}
			*pName = 0x00;
		}
	}

	UnHook();
	if (newText)
	{
		(*(void(*)(char*))OpenProcessAddr)(newText);
	}
	else
	{
		(*(void(*)(char*))OpenProcessAddr)(buffer);
	}

	Hook();
}


void HookSelection()
{
	void* addr = OutputSelectionAddr;

	VirtualProtect(addr, 5, PAGE_EXECUTE_READWRITE, &oldProtextSelection);

	JmpByteSelection[0] = 0xE9;
	*(DWORD*)&JmpByteSelection[1] = (DWORD)ReplaceSelection2 - (DWORD)addr - (DWORD)5;

	memcpy(OldByteSelection, (void*)addr, 5);

	memcpy((void*)addr, JmpByteSelection, 5);
}


void UnHookSelection()
{
	memcpy((void*)OutputSelectionAddr, OldByteSelection, 5);
	DWORD p;
	VirtualProtect((LPVOID)OutputSelectionAddr, 5, oldProtextSelection, &p);
}

#if 0
void ReplaceSelection()
{
	/*
	选择支文本可能出现的位置
	[*(*addr+(0|4|8|c))+0x120]
	*/
	int* addPointer = (int*)*PointersPage;
	while (*addPointer != 0x00000000 && *addPointer != 0xFFFFFFFF)
	{
		char* text = (char*)*addPointer;
		text += 0x110;
		string oldText(text);
		if (*text)
		{
			auto vk = jp_chs.find(oldText);
			if (vk != jp_chs.end())
			{
				for (int i = 0; i < vk->second.length(); i++)
				{
					text[i] = vk->second[i];
				}
				text[vk->second.length()] = 0x00;
			}
		}

		text += 0x10;
		oldText = string(text);
		if (*text)
		{
			auto vk = jp_chs.find(oldText);
			if (vk != jp_chs.end())
			{
				for (int i = 0; i < vk->second.length(); i++)
				{
					text[i] = vk->second[i];
				}
				text[vk->second.length()] = 0x00;
			}
		}

		addPointer++;
	}

	UnHookSelection();
	(*(void(*)())OutputSelectionAddr)();
	HookSelection();
}
#endif

void __fastcall ReplaceSelection2(void* pThis)
{
	/*
	选择支文本可能出现的位置
	[*(*addr+(0|4|8|c))+0x120]
	*/
	if (*PointersPage)
	{
		int* addPointer = (int*)*PointersPage;
		while (*addPointer != 0x00000000 && *addPointer != 0xFFFFFFFF)
		{
			char* text = (char*)*addPointer;
			text += 0x110;
			string oldText(text);
			if (*text)
			{
				auto vk = jp_chs.find(oldText);
				if (vk != jp_chs.end())
				{
					for (int i = 0; i < vk->second.length(); i++)
					{
						text[i] = vk->second[i];
					}
					text[vk->second.length()] = 0x00;
				}
			}

			text += 0x10;
			oldText = string(text);
			if (*text)
			{
				auto vk = jp_chs.find(oldText);
				if (vk != jp_chs.end())
				{
					for (int i = 0; i < vk->second.length(); i++)
					{
						text[i] = vk->second[i];
					}
					text[vk->second.length()] = 0x00;
				}
			}

			addPointer++;
		}
	}


	UnHookSelection();
	(*(void(__fastcall*)(void*))OutputSelectionAddr)(pThis);
	HookSelection();
}


void FillRange()
{
	processStartAddress = processStopAddress = (uintptr_t)GetModuleHandleW(nullptr);
	MEMORY_BASIC_INFORMATION info;
	do
	{
		VirtualQuery((void*)processStopAddress, &info, sizeof(info));
		processStopAddress = (uintptr_t)info.BaseAddress + info.RegionSize;
	} while (info.Protect > PAGE_NOACCESS);
	processStopAddress -= info.RegionSize;
}


DWORD SearchPattern(DWORD base, DWORD base_length, LPCVOID search, DWORD search_length)
{
	// Artikash 7/14/2018: not sure, but I think this could throw read access violation if I dont subtract search_length
	for (int i = 0; i < base_length - search_length; ++i)
		for (int j = 0; j <= search_length; ++j)
			if (j == search_length) return i; // not sure about this algorithm...
			else if (*((BYTE*)base + i + j) != *((BYTE*)search + j) && *((BYTE*)search + j) != XX) break;
	//if (memcmp((void*)(base + i), search, search_length) == 0)
		//return i;

	return 0;
}


DWORD findBytes(const void* pattern, DWORD patternSize, DWORD lowerBound, DWORD upperBound)
{
	DWORD reladdr = SearchPattern(lowerBound, upperBound - lowerBound, pattern, patternSize);
	return reladdr ? lowerBound + reladdr : 0;
}