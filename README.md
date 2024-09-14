# DLLInject
## 简介  
DLLInject是windows下的DLL注入工具，使用的是创建远程线程调用Loadlibrary的方式给指定运行中的进程注入指定调试dll。  
*note:DllInject运行需要权限不低于被注入进程，不然会打开进程失败*

DLLInject目录是注入工具的源码。  
DebugProj目录下是调试dll的源码，目前提供了两个演示工程:  
TestAddDll: 注入TestApp.exe（TestApp目录），可以拦截和打印TestApp每一次调用Add的结果。  
SymbolLoadDLL： 演示了如何在一个指定进程中查找符号对应的地址。  
