// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"

__declspec(dllexport) int Add(int a, int b)
{
	return a * 2 + b;
}