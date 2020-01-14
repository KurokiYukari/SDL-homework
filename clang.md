# Clang 使用方法

## Clang 命令
直接使用 <kbd>clang [filename, ...]</kbd> 即可直接生成一个名为 a.exe 可执行文件。

#### 常用参数
- <kbd>-o [filename]</kbd> : 输出文件，并指定输出文件的名称。
- <kbd>-E</kbd> : 预处理文件。
- <kbd>-S</kbd> : 生成汇编源程序。
- <kbd>-c</kbd> : 生成目标二进制文件。
- <kbd>-l</kbd> : 指定要使用的库的名称。
- <kbd>-L</kbd> : 指定搜索库的路径。
- 若要生成一个动态链接库，则在需要加上参数 <kbd>-shared -fPIC</kbd>。

## ar 命令
在 Linux 环境下，ar 命令用来生成 Linux 环境下的库文件<kbd>.a</kbd>  
命令格式为 <kbd>ar [libfilename] [count] [filenames, ...]</kbd>
- <kbd>t</kbd> : 显示库中的文件。
- <kbd>d</kbd> : 删除库中的文件。
- <kbd>r</kbd> : 在库中插入文件。
- <kbd>c</kbd> : 建立库文件。
