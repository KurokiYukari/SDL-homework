# MSVC 使用方法


## cl 命令

cl 是基础的编译命令，具体可以输入 <kbd>cl -help</kbd> 来获得帮助。直接使用<kbd>cl [filename, ...]</kbd>即可直接生成可执行文件。

#### 常用参数

- <kbd>-nologo</kbd> : 不显示 logo 字样。
- <kbd>-EH</kbd> : 一般用 <kbd>-EHsc</kbd> 指定异常处理模型。
- <kbd>-std</kbd> : 控制兼容的 C++ 版本。可以用 <kbd>-std:[c++14（默认） | c++17 | c++latest（最新）]</kbd>。 
- <kbd>-Fo[filename]</kbd> : 指定 <kbd>.obj</kbd> 文件的名称。
- <kbd>-Fe[filename]</kbd> : 指定 <kbd>.exe</kbd> 文件的名称。  
- <kbd>-c</kbd> : 只编译不连接。

## link 命令
link 可以将 <kbd>.obj</kbd> 文件连接为可执行文件 <kbd>.exe</kbd>。  
<kbd>-out:</kbd> 可以用来指定输出文件名称。

## lib 命令
lib 命令用于生成一个静态链接库。
<kbd>-out:</kbd> 可以用来指定输出文件名称。
