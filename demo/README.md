# python-ngrok
基于python-ngrok v1.42 适配ngrok.cc Python 客户端 (2017/08/18)

基于python-ngrok v1.42 适配natapp.cn Python 客户端 (2017/08/18)

# 运行环境
Python 2.7.12 或 Python 3.1 以上

# 运行方法
Linux 系统一般自带Python 可以直接运行

ngrok.cc -sunny.py
- 赋予权限 `chmod 755 sunny.py`
- 在命令行模式运行 `python sunny.py --clientid=xxxxxxxx`
- 如果是多个隧道换成 `python sunny.py --clientid=xxxxxxxx,xxxxxxxx`

natapp.cn -natapp.py
- 赋予权限 `chmod 755 natapp.py`
- 在命令行模式运行 `python natapp.py --authtoken=xxxxxxxx`
- 如果是复合隧道换成 `python natapp.py --clienttoken=xxxxxxxxxxxxxxxx`

# 温馨提示
如果有小伙伴不想依赖环境运行，不妨可以试下PyInstaller，把py编译成可执行文件。
