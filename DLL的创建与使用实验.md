# DLL 的创建与使用

## DLL 生成
### C 源码编写
随便写一个 c 文件 baseLib.c 与对应的头文件，其中实现了一个函数:
``` C
int lib_func(char* msg);
```
函数功能是接受一个字符串，将之用 MessageBox 显示。
### def 文件编写
.def 文件为模块定义文件，为链接器提供有关被链接程序的导出、属性及其他方面的信息。
这里定义模块名为 baseLib; 要导出的函数为 lib_func; def 文件为 Source.def
#### 源码
```
LIBRARY   baseLib
EXPORTS
   lib_func   @1
```
### 编译与链接
打开命令行，编译链接 baseLib.c，生成 DLL 文件。
``` bash
cl -c baseLib.c
link -dll -def:Source.def baseLib.obj User32.lib
```
执行后，可以看到在文件夹下生产了对应的 dll 和 lib 文件。
使用命令
``` bash
dumpbin -exports baseLib.dll
```
查看 baseLib.dll 导出的函数，可以看到有一个导出函数 lib_func：
```
Section contains the following exports for baseLib.dll

    00000000 characteristics
    FFFFFFFF time date stamp
        0.00 version
           1 ordinal base
           1 number of functions
           1 number of names

    ordinal hint RVA      name

          1    0 00001000 lib_func
```

## DLL 使用
### load time 方法
+ C 源码：
``` C
// main.c

#include "baseLib.h"

int main()
{
	lib_func("call a dll");
}
```
+ 将 DLL 的头文件，lib、dll 文件复制到源码的同一级目录下。
+ 编译链接执行，可以看到执行结果。
``` bash
cl -c main.c
link main.obj baseLib.lib
main.exe
```
+ 查看 main.exe 的导入
``` bash
dumpbin -imports main.exe
```
可以看到导入了 baseLib.dll
```
 Section contains the following imports:

    baseLib.dll
                40E108 Import Address Table
                413558 Import Name Table
                     0 time date stamp
                     0 Index of first forwarder reference

                      Ordinal     1
```
### run time 方法
+ C 源码
``` C
// main.c

#include <stdio.h>
#include <wtypes.h>

int main()
{
	HINSTANCE hDLL;
	int (*lib_func)(char*);
	hDLL = LoadLibrary("baseLib.dll");  //加载 DLL文件  
	if (hDLL == NULL)
	{
		printf("%s\n", "Load DLL Error.");
		return -1;
	}
	lib_func = (int (*)(char*))GetProcAddress(hDLL, "lib_func");  //取DLL中的函数地址，以备调用 

	lib_func("call a dll");

	FreeLibrary(hDLL);
}
```
+ 将 DLL 复制到同一目录下
+ 编译链接执行，运行成功。
``` bash
cl main.c
main.exe
```
+ 查看 main.exe 的导入
``` bash
dumpbin -imports main.exe
```
可以看到没有 baseLib.dll 的导入。
