#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
    natapp.cn 内网穿透服务 Python 版

    本程序仅适用于natapp.cn 使用前请先在 https://natapp.cn 注册账号.
    Linux 系统一般自带Python 可以直接运行
    赋予权限 chmod 755 natapp.py
    直接运行 ./natapp.py --authtoken=xxxxxxxxxxxxxxxx
    命令行模式执行 python natapp.py --authtoken=xxxxxx 即可运行

    感谢 hauntek 提供的 python-ngrok 原版程序
"""
import getopt
import socket
import ssl
import json
import struct
import random
import sys
import time
import logging
import threading

python_version = sys.version_info >= (3, 0)
if not python_version:
    reload(sys)
    sys.setdefaultencoding('utf8')

options = {
    'clienttoken':'',
    'authtoken':'',
}

def usage():
    print(
        ' -h help \n' \
        ' -a authtoken xxxxxxxxxxxxxxxx\n' \
        ' -c clienttoken xxxxxxxxxxxxxxxx\n' \
    )
    sys.exit()

try:
    opts, args = getopt.getopt(sys.argv[1:], "ha:c:", ['help', "authtoken=", "clienttoken="])
except getopt.GetoptError:
    usage()

if len(opts) == 0:
    print(
        '使用说明\n' \
        '在命令行模式运行 python natapp.py --authtoken=xxxxxxxxxxxxxxxx\n' \
        '如果是复合隧道换成 python natapp.py --clienttoken=xxxxxxxxxxxxxxxx\n' \
        '请登录 https://natapp.cn 获取 authtoken\n' \
    )
    time.sleep(10)
    sys.exit()

for option, value in opts:
    if option in ['-h', '--help']:
        usage()
    if option in ['-c', '--clienttoken']:
        options['clienttoken'] = value
    elif option in ['-a', '--authtoken']:
        options['authtoken'] = value

# natapp.cn 获取服务器设置
def natapp_auth(options):
    host = 'auth.natapp.cn'
    port = 443
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_client = ssl.wrap_socket(client, ssl_version=ssl.PROTOCOL_TLSv1) # ssl.PROTOCOL_TLSv1_2
        ssl_client.connect((host, port))
    except Exception:
        print('连接认证服务器: https://auth.natapp.cn 错误.')
        time.sleep(10)
        sys.exit()

    data = {
        'Authtoken': options['authtoken'],
        'Clienttoken': options['clienttoken'],
        'Token': 'fffeephptokenkhd672'
    }
    query = json.dumps(data)

    header = "POST " + "/auth" + " HTTP/1.1" + "\r\n"
    header += "Content-Type: text/html" + "\r\n"
    header += "Host: auth.natapp.cn" + "\r\n"
    header += "Content-Length: %d" + "\r\n"
    header += "\r\n" + "%s"
    buf = header % (len(query), query)
    ssl_client.sendall(buf.encode('utf-8')) # 发送请求头

    fd = ssl_client.makefile('rb', 0)
    body = bytes()
    while True:
        line = fd.readline().decode('utf-8')
        if line == "\n" or line == "\r\n":
            # chunk_size = int(fd.readline(), 16)
            # if chunk_size > 0:
                # body = fd.read(chunk_size).decode('utf-8')
                # break
            body = fd.readline().decode('utf-8')
            break

    ssl_client.close()

    authData = json.loads(body)
    if authData['Success'] == False:
        print('认证错误:%s, ErrorCode:%s' % (authData['Msg'], authData['ErrorCode']))
        time.sleep(10)
        sys.exit()

    print('认证成功,正在连接服务器...')
    proto = authData['Data']['ServerAddr'].split(':')
    return proto

print('欢迎使用内网穿透 python-natapp v1.42\r\nCtrl+C 退出')
serverArr = natapp_auth(options)
host = str(serverArr[0]) # Ngrok服务器地址
port = int(serverArr[1]) # 端口
bufsize = 1024 # 吞吐量

Tunnels = dict() # 全局渠道赋值

mainsocket = 0

ClientId = ''
pingtime = 0

def getloacladdr(Tunnels, Url):
    proto = Tunnels[Url]['LocalAddr'].split(':')
    return proto

def dnsopen(host):
    try:
        ip = socket.gethostbyname(host)
    except socket.error:
        return False

    return ip

def connectremote(host, port):
    try:
        host = socket.gethostbyname(host)
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_client = ssl.wrap_socket(client, ssl_version=ssl.PROTOCOL_SSLv23)
        ssl_client.connect((host, port))
        ssl_client.setblocking(1)
        logger = logging.getLogger('%s:%d' % ('Conn', ssl_client.fileno()))
        logger.debug('New connection to: %s:%d' % (host, port))
    except socket.error:
        return False

    return ssl_client

def connectlocal(localhost, localport):
    try:
        localhost = socket.gethostbyname(localhost)
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((localhost, localport))
        client.setblocking(1)
        logger = logging.getLogger('%s:%d' % ('Conn', client.fileno()))
        logger.debug('New connection to: %s:%d' % (localhost, localport))
    except socket.error:
        return False

    return client

def NgrokAuth():
    Payload = dict()
    Payload['ClientId'] = ''
    Payload['OS'] = 'php'
    Payload['Arch'] = 'amd64'
    Payload['Version'] = '4'
    Payload['MmVersion'] = '2.1'
    Payload['User'] = 'user'
    Payload['Password'] = ''
    Payload['AuthToken'] = options['authtoken']
    Payload['ClientToken'] = options['clienttoken']
    body = dict()
    body['Type'] = 'Auth'
    body['Payload'] = Payload
    buffer = json.dumps(body)
    return(buffer)

def RegProxy(ClientId):
    Payload = dict()
    Payload['ClientId'] = ClientId
    body = dict()
    body['Type'] = 'RegProxy'
    body['Payload'] = Payload
    buffer = json.dumps(body)
    return(buffer)

def Ping():
    Payload = dict()
    body = dict()
    body['Type'] = 'Ping'
    body['Payload'] = Payload
    buffer = json.dumps(body)
    return(buffer)

def lentobyte(len):
    return struct.pack('<LL', len, 0)

def sendbuf(sock, buf, isblock = False):
    if isblock:
        sock.setblocking(1)
    sock.sendall(buf)
    if isblock:
        sock.setblocking(0)

def sendpack(sock, msg, isblock = False):
    if isblock:
        sock.setblocking(1)
    sock.sendall(lentobyte(len(msg)) + msg.encode('utf-8'))
    logger = logging.getLogger('%s:%d' % ('Send', sock.fileno()))
    logger.debug('Writing message: %s' % msg)
    if isblock:
        sock.setblocking(0)

def tolen(v):
    if len(v) == 8:
        return struct.unpack('<II', v)[0]
    return 0

def getRandChar(length):
    _chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz"
    return ''.join(random.sample(_chars, length))

# 客户端程序处理过程
def HKClient(sock, linkstate, type, tosock = None):
    global mainsocket
    global ClientId
    global pingtime
    global Tunnels
    recvbuf = bytes()
    while True:
        try:
            if linkstate == 0:
                if type == 1:
                    sendpack(sock, NgrokAuth(), False)
                    linkstate = 1
                if type == 2:
                    sendpack(sock, RegProxy(ClientId), False)
                    linkstate = 1
                if type == 3:
                    linkstate = 1

            recvbut = sock.recv(bufsize)
            if not recvbut: break

            if len(recvbut) > 0:
                if not recvbuf:
                    recvbuf = recvbut
                else:
                    recvbuf += recvbut

            if type == 1 or (type == 2 and linkstate == 1):
                lenbyte = tolen(recvbuf[0:8])
                if len(recvbuf) >= (8 + lenbyte):
                    buf = recvbuf[8:lenbyte + 8].decode('utf-8')
                    logger = logging.getLogger('%s:%d' % ('Recv', sock.fileno()))
                    logger.debug('Reading message with length: %d' % len(buf))
                    logger.debug('Read message: %s' % buf)
                    js = json.loads(buf)
                    if type == 1:
                        if js['Type'] == 'ReqProxy':
                            newsock = connectremote(host, port)
                            if newsock:
                                thread = threading.Thread(target = HKClient, args = (newsock, 0, 2))
                                thread.setDaemon(True)
                                thread.start()
                        if js['Type'] == 'AuthResp':
                            ClientId = js['Payload']['ClientId']
                            logger = logging.getLogger('%s' % 'client')
                            logger.debug('Authenticated with server, client id: %s' % ClientId)
                            sendpack(sock, Ping())
                            pingtime = time.time()
                        if js['Type'] == 'NewTunnel':
                            if js['Payload']['Error'] != '':
                                logger = logging.getLogger('%s' % 'client')
                                logger.error('Server failed to allocate tunnel: %s' % js['Payload']['Error'])
                                time.sleep(30)
                            else:
                                Tunnels[js['Payload']['Url']] = js['Payload']
                                logger = logging.getLogger('%s' % 'client')
                                logger.debug('Tunnel established at %s' % js['Payload']['Url'])
                                print('隧道建立成功: %s' % js['Payload']['Url']) # 注册成功
                    if type == 2:
                        if js['Type'] == 'StartProxy':
                            loacladdr = getloacladdr(Tunnels, js['Payload']['Url'])

                            newsock = connectlocal(str(loacladdr[0]), int(loacladdr[1]))
                            if newsock:
                                thread = threading.Thread(target = HKClient, args = (newsock, 0, 3, sock))
                                thread.setDaemon(True)
                                thread.start()
                                tosock = newsock
                                linkstate = 2
                            else:
                                body = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Web服务错误</title><meta name="viewport" content="initial-scale=1,maximum-scale=1,user-scalable=no"><meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1"><style>html,body{height:100%%}body{margin:0;padding:0;width:100%%;display:table;font-weight:100;font-family:"Microsoft YaHei",Arial,Helvetica,sans-serif}.container{text-align:center;display:table-cell;vertical-align:middle}.content{border:1px solid #ebccd1;text-align:center;display:inline-block;background-color:#f2dede;color:#a94442;padding:30px}.title{font-size:18px}.copyright{margin-top:30px;text-align:right;color:#000}</style></head><body><div class="container"><div class="content"><div class="title">隧道 %s 无效<br>无法连接到<strong>%s</strong>. 此端口尚未提供Web服务</div></div></div></body></html>'
                                html = body % (js['Payload']['Url'], str(loacladdr[0]) + ':' + str(loacladdr[1]))
                                header = "HTTP/1.0 502 Bad Gateway" + "\r\n"
                                header += "Content-Type: text/html" + "\r\n"
                                header += "Content-Length: %d" + "\r\n"
                                header += "\r\n" + "%s"
                                buf = header % (len(html.encode('utf-8')), html)
                                sendbuf(sock, buf.encode('utf-8'))

                    if len(recvbuf) == (8 + lenbyte):
                        recvbuf = bytes()
                    else:
                        recvbuf = recvbuf[8 + lenbyte:]

            if type == 3 or (type == 2 and linkstate == 2):
                sendbuf(tosock, recvbuf)
                recvbuf = bytes()

        except socket.error:
            break

    if type == 1:
        mainsocket = False
    if type == 3:
        try:
            tosock.shutdown(socket.SHUT_WR)
        except socket.error:
            tosock.close()

    logger = logging.getLogger('%s:%d' % ('Close', sock.fileno()))
    logger.debug('Closing')
    sock.close()

# 客户端程序初始化
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s', datefmt='%Y/%m/%d %H:%M:%S')
    logger = logging.getLogger('%s' % 'client')
    logger.debug('python-ngrok v1.42')
    while True:
        try:
            # 检测控制连接是否连接.
            if mainsocket == False:
                ip = dnsopen(host)
                if ip == False:
                    logger = logging.getLogger('%s' % 'client')
                    logger.debug('update dns')
                    print('连接natapp服务器失败.')
                    time.sleep(10)
                    continue
                mainsocket = connectremote(ip, port)
                if mainsocket == False:
                    logger = logging.getLogger('%s' % 'client')
                    logger.debug('connect failed...!')
                    print('连接natapp服务器失败.')
                    time.sleep(10)
                    continue
                thread = threading.Thread(target = HKClient, args = (mainsocket, 0, 1))
                thread.setDaemon(True)
                thread.start()

            # 发送心跳
            if pingtime + 20 < time.time() and pingtime != 0:
                sendpack(mainsocket, Ping())
                pingtime = time.time()

            time.sleep(1)

        except socket.error:
            pingtime = 0
        except KeyboardInterrupt:
            sys.exit()
