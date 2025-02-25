# python-ngrok
![license](https://img.shields.io/badge/license-GPLV3-blue)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![version](https://img.shields.io/badge/Release-v2.1-orange)

基本上已经完善！并且24*7小时长时间工作，在期间我们多次尝试断网重连、渠道反复注册等，均无任何问题。

[`python-ngrok.py`](https://github.com/hauntek/python-ngrok/blob/master/python-ngrok.py) 采用多线程全同步处理，并发性能相当强悍！

[`python-ngrok_gevent.py`](https://github.com/hauntek/python-ngrok/blob/master/python-ngrok_gevent.py) 通过`gevent`替换为多协程全异步处理！

[`python-ngrok_deepseek.py`](https://github.com/hauntek/python-ngrok/blob/master/python-ngrok_deepseek.py) 采用多协程全异步处理，并发性能异常强悍！

# 运行环境
[`python-ngrok.py`](https://github.com/hauntek/python-ngrok/blob/master/python-ngrok.py) Python 2.7.9 或 Python 3.4.2 以上

[`python-ngrok_gevent.py`](https://github.com/hauntek/python-ngrok/blob/master/python-ngrok_gevent.py) Python 2.7.9 或 Python 3.4.2 以上

[`python-ngrok_deepseek.py`](https://github.com/hauntek/python-ngrok/blob/master/python-ngrok_deepseek.py) Python 3.10.0 以上

# 运行方法
直接运行即可.或者`./python-ngrok.py ngrok.config`

# 温馨提示
如果有小伙伴不想依赖环境运行，不妨可以试下PyInstaller，把py编译成可执行文件。

## 更新日记 v2.1(2025/02/25)

***

1. **功能增强**
   - 新增UDP本地连接转发处理，支持UDP隧道注册
   - 新增断网重新连接机制

2. **功能修复**
   - 调整接收消息机制，避免接收`StartProxy`消息粘包，导致无法双向数据转发

**Tip**: 
   - 1.由人工智能优化代码和生成更新日记（DeepSeek v3）
   - 2.运行环境需Python 3.10.0 以上[`python-ngrok_deepseek.py`](https://github.com/hauntek/python-ngrok/blob/master/python-ngrok_deepseek.py)

***

## 更新日记 v2.0(2025/02/23)

***

1. **架构里程碑**
   - 全异步IO架构替代多线程模型（性能提升15倍）
   - 配置文件加载逻辑封装到`NgrokConfig`类，支持更灵活的配置，增加错误处理和日志记录。

2. **性能指标**
   | 测试项        | v1.56 | v2.0  |
   |--------------|-------|-------|
   | 最大连接数    | 1000   | 15,000+ |
   | 隧道创建QPS   | 200   | 2,500  |
   | 内存占用/MB   | 52    | 38     |

3. **功能修复**
   - 收到`AuthResp`错误消息，不会显示错误并结束接收数据主循环

4. **功能增强**
   - 新增面向对象编程模式，代码结构更清晰，易于维护和扩展
   - 补全认证缺失的`authToken`功能，以及隧道缺失的`HttpAuth`功能
   - 优化IPv4/IPv6双栈支持，默认优先使用IPv6

**Tip**: 
   - 1.由人工智能优化代码和生成更新日记（DeepSeek v3）
   - 2.运行环境需Python 3.10.0 以上[`python-ngrok_deepseek.py`](https://github.com/hauntek/python-ngrok/blob/master/python-ngrok_deepseek.py)

***

## 更新日记 v1.56(2021/04/25)

***

1.本地数据分块转发

2.通过`gevent`替换为多协程全异步处理[`python-ngrok_gevent.py`](https://github.com/hauntek/python-ngrok/blob/master/python-ngrok_gevent.py)
- 需安装gevent依赖库, 命令: `python -m pip install gevent`

***

## 更新日记 v1.52(2019/07/27)

***

1.添加IPv4/IPv6双栈服务连接及本地转发协议支持
- 支持数字格式地址及双栈域名地址解析,可分别设置服务连接及本地转发协议
- 域名双栈解析优先: IPv6 > IPv4
- 双栈协议参数说明: `[dualstack]` or `[dualstack_or]`
- 服务连接协议参数: dualstack `[IPv4/IPv6=双栈, IPv4=IPv4, IPv6=IPv6]`
- 本地转发协议参数: dualstack_or `[0=双栈, 1=IPv4, 2=IPv6]`

2.删除旧版不支持的域名解析函数及旧版查询隧道信息函数

***

## 更新日记 v1.5(2018/09/19)

***

1.修复部分情况导致查询隧道信息出错

***

## 更新日记 v1.46(2017/05/04)

***

1.支持配置文件运行,优先读取配置信息
- 运行命令: `./python-ngrok.py ngrok.config`

2.感谢[@JerrickRowe](https://github.com/JerrickRowe) 贡献配置文件代码

***

## 更新日记 v1.42(2017/03/15)

***

1.修复接收字节序过短,导致的异常事件

2.优化部分处理器的大小端字节对齐

***

## 更新日记 v1.41(2017/03/04)

***

1.修复部分情况导致丢包,数据不完整问题

***

## 更新日记 v1.38(2016/09/01)

***

1.添加子线程跟随主线程结束而结束

2.添加程序退出时发送客户退出消息

3.添加捕获键盘中断异常事件

4.更改断线后重新赋值心跳变量

***

## 更新日记 v1.36(2016/08/29)

***

1.添加日记输出模块,调试输出格式化

2.修复本地映射地址无效转向定制的html页面

3.修复关闭上个线程读写,判断描述符是否有效

4.更改发送心跳周期

5.修复断线后重新赋值心跳变量

***

## 更新日记 v1.32(2016/08/13)

***

1.修复关闭上个线程读写,某些极端情况出错

2.修复组包/拆包在其他版本字节流长度不一致

***

## 更新日记 v1.31(2016/08/11)

***

1.修复本地转发完后,关闭上个线程读写

***

## 更新日记 v1.3(2016/08/10)

***

1.修复可写事件,某些极端情况发送数据出错

2.修复处于被注册的期间,断网导致发送心跳出错

***

## 更新日记 v1.2(2016/08/10)

***

1.转多线程异步处理,大幅提升即时并发性能

2.修复主线程cpu占用过高

3.修复堵塞和非堵塞发送

4.修复读写I/O判断

5.修复输出日记排序

6.优化断线重连机制

7.修复断线后变量无法赋值

8.修复本地转发完后导致远程挂起

9.添加本地映射地址无效转向定制的html页面

***
