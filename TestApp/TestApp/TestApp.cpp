﻿// TestApp.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <thread>
#include <chrono>

extern "C" _declspec(dllexport) int Add(int a, int b)
{
	return a + b + 123;
}

int main()
{
	while (true)
	{
		int s = Add(12, 22);
		std::cout << s << std::endl;
		std::this_thread::sleep_for(std::chrono::seconds(1));
	}

	return -1;
}
