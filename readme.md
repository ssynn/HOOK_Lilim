# AOS2通用汉化插件

## 使用方法
1. 把bin文件夹内的三个文件放入游戏目录
2. 修改hook.ini文件内EXE字段为游戏启动exe
3. 把生成的翻译字典放入文件夹内

## 字典生成方式
1. 使用GARBro把游戏目录scr.aos拆包
2. 使用extract_for_hook_aos2提取文本并生成翻译字典
3. 翻译字典（左侧为日文，右侧填中文）注意格式
4. output_hook_dict 生成供汉化插件使用的汉化字典

## 注意
1. 仅支持AOS2
2. 字典内不能出现除 \\n \\f [ ] 以外的任何半角字符，可以使用 fix_dict 把半角转换为全角字符
3. 提取文本后记得检查，删除字典内不该提取的文本
4. 部分代码参考(复制)Textractor
