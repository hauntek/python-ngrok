#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
    ngrok.cc 内网穿透服务 Python 版

    本程序仅适用于ngrok.cc 使用前请先在 https://ngrok.cc 注册账号.
    Linux 系统一般自带Python 可以直接运行
    赋予权限 chmod 755 sunny.py
    直接运行 ./sunny.py --clientid=xxxxxxxxxxxxxxxx
    命令行模式执行 python sunny.py --clientid=xxxxxx 即可运行

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
    'clientid':'',
}

def usage():
    print(
        ' -h help \n' \
        ' -a clientid xxxxxxxxxxxxxxxx\n' \
    )
    sys.exit()

try:
    opts, args = getopt.getopt(sys.argv[1:], "h:c:", ['help', "clientid="])
except getopt.GetoptError:
    usage()

if len(opts) == 0:
    print(
        '使用说明\n' \
        '在命令行模式运行 python sunny.py --clientid=xxxxxxxx\n' \
        '如果是多个隧道换成 python sunny.py --clientid=xxxxxxxx,xxxxxxxx\n' \
        '请登录 https://ngrok.cc 获取 clientid\n' \
    )

for option, value in opts:
    if option in ['-h', '--help']:
        usage()
    if option in ['-c', '--clientid']:
        options['clientid'] = value

if options['clientid'] == '':
    if not python_version:
        input_clientid = raw_input('请输入clientid：')
    else:
        input_clientid = str(input('请输入clientid：'))
    if input_clientid != '':
        options['clientid'] = input_clientid
    else:
        sys.exit()

Tunnels = list() # 全局渠道赋值

# ngrok.cc 添加到渠道队列
def ngrok_adds(Tunnel):
    global Tunnels
    for tunnelinfo in Tunnel:
        if tunnelinfo.get('proto'):
            if tunnelinfo.get('proto').get('http'):
                protocol = 'http'
            if tunnelinfo.get('proto').get('https'):
                protocol = 'https'
            if tunnelinfo.get('proto').get('tcp'):
                protocol = 'tcp'

            proto = tunnelinfo['proto'][protocol].split(':') # 127.0.0.1:80 拆分成数组
            if proto[0] == '':
                proto[0] = '127.0.0.1'
            if proto[1] == '' or proto[1] == 0:
                proto[1] = 80

            body = dict()
            body['protocol'] = protocol
            body['hostname'] = tunnelinfo['hostname']
            body['subdomain'] = tunnelinfo['subdomain']
            body['httpauth'] = tunnelinfo['httpauth']
            body['rport'] = tunnelinfo['remoteport']
            body['lhost'] = str(proto[0])
            body['lport'] = int(proto[1])
            Tunnels.append(body) # 加入渠道队列

# ngrok.cc 获取服务器设置
def ngrok_auth(options):
    host = 'www.ngrok.cc'
    port = 443
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_client = ssl.wrap_socket(client, ssl_version=ssl.PROTOCOL_TLSv1) # ssl.PROTOCOL_TLSv1_2
        ssl_client.connect((host, port))
    except Exception:
        print('连接认证服务器: https://www.ngrok.cc 错误.')
        time.sleep(10)
        sys.exit()

    header = "POST " + "/api/clientid/clientid/%s" + " HTTP/1.1" + "\r\n"
    header += "Content-Type: text/html" + "\r\n"
    header += "Host: %s" + "\r\n"
    header += "\r\n"
    buf = header % (options, host)
    ssl_client.sendall(buf.encode('utf-8')) # 发送请求头

    fd = ssl_client.makefile('rb', 0)
    body = bytes()
    while True:
        line = fd.readline().decode('utf-8')
        if line == "\n" or line == "\r\n":
            chunk_size = int(fd.readline(), 16)
            if chunk_size > 0:
                body = fd.read(chunk_size).decode('utf-8')
                break

    ssl_client.close()

    authData = json.loads(body)
    if authData['status'] != 200:
        print('认证错误:%s, ErrorCode:%s' % (authData['msg'], authData['status']))
        time.sleep(10)
        sys.exit()

    print('认证成功,正在连接服务器...')
    # 设置映射隧道,支持多渠道[客户端id]
    ngrok_adds(authData['data'])
    proto = authData['server'].split(':')
    return proto

print('欢迎使用内网穿透 python-ngrok v1.42\r\nCtrl+C 退出')
serverArr = ngrok_auth(options['clientid'])
host = str(serverArr[0]) # Ngrok服务器地址
port = int(serverArr[1]) # 端口
bufsize = 1024 # 吞吐量

mainsocket = 0

ClientId = ''
pingtime = 0

def getloacladdr(Tunnels, Url):
    protocol = Url[0:Url.find(':')]
    hostname = Url[Url.find('//') + 2:]
    subdomain = hostname[0:hostname.find('.')]
    rport = Url[Url.rfind(':') + 1:]

    for tunnelinfo in Tunnels:
        if tunnelinfo.get('protocol') == protocol:
            if tunnelinfo.get('protocol') in ['http', 'https']:
                if tunnelinfo.get('hostname') == hostname:
                    return tunnelinfo
                if tunnelinfo.get('subdomain') == subdomain:
                    return tunnelinfo
            if tunnelinfo.get('protocol') == 'tcp':
                if tunnelinfo.get('rport') == int(rport):
                    return tunnelinfo

    return dict()

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
    Payload['OS'] = 'darwin'
    Payload['Arch'] = 'amd64'
    Payload['Version'] = '2'
    Payload['MmVersion'] = '2.1'
    Payload['User'] = 'user'
    Payload['Password'] = ''
    body = dict()
    body['Type'] = 'Auth'
    body['Payload'] = Payload
    buffer = json.dumps(body)
    return(buffer)

def ReqTunnel(Protocol, Hostname, Subdomain, HttpAuth, RemotePort):
    Payload = dict()
    Payload['ReqId'] = getRandChar(8)
    Payload['Protocol'] = Protocol
    Payload['Hostname'] = Hostname
    Payload['Subdomain'] = Subdomain
    Payload['HttpAuth'] = HttpAuth
    Payload['RemotePort'] = RemotePort
    body = dict()
    body['Type'] = 'ReqTunnel'
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
                            for tunnelinfo in Tunnels:
                                # 注册通道
                                sendpack(sock, ReqTunnel(tunnelinfo['protocol'], tunnelinfo['hostname'], tunnelinfo['subdomain'], tunnelinfo['httpauth'], tunnelinfo['rport']))
                        if js['Type'] == 'NewTunnel':
                            if js['Payload']['Error'] != '':
                                logger = logging.getLogger('%s' % 'client')
                                logger.error('Server failed to allocate tunnel: %s' % js['Payload']['Error'])
                                print('隧道建立失败: %s' % js['Payload']['Error'])
                                time.sleep(30)
                            else:
                                logger = logging.getLogger('%s' % 'client')
                                logger.debug('Tunnel established at %s' % js['Payload']['Url'])
                                print('隧道建立成功: %s' % js['Payload']['Url']) # 注册成功
                    if type == 2:
                        if js['Type'] == 'StartProxy':
                            loacladdr = getloacladdr(Tunnels, js['Payload']['Url'])

                            newsock = connectlocal(loacladdr['lhost'], loacladdr['lport'])
                            if newsock:
                                thread = threading.Thread(target = HKClient, args = (newsock, 0, 3, sock))
                                thread.setDaemon(True)
                                thread.start()
                                tosock = newsock
                                linkstate = 2
                            else:
                                body = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Web服务错误</title><meta name="viewport" content="initial-scale=1,maximum-scale=1,user-scalable=no"><meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1"><style>html,body{height:100%%}body{margin:0;padding:0;width:100%%;display:table;font-weight:100;font-family:"Microsoft YaHei",Arial,Helvetica,sans-serif}.container{text-align:center;display:table-cell;vertical-align:middle}.content{border:1px solid #ebccd1;text-align:center;display:inline-block;background-color:#f2dede;color:#a94442;padding:30px}.title{font-size:18px}.copyright{margin-top:30px;text-align:right;color:#000}</style></head><body><div class="container"><div class="content"><div class="title">隧道 %s 无效<br>无法连接到<strong>%s</strong>. 此端口尚未提供Web服务</div></div></div></body></html>'
                                html = body % (js['Payload']['Url'], loacladdr['lhost'] + ':' + str(loacladdr['lport']))
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
                    print('连接ngrok服务器失败.')
                    time.sleep(10)
                    continue
                mainsocket = connectremote(ip, port)
                if mainsocket == False:
                    logger = logging.getLogger('%s' % 'client')
                    logger.debug('connect failed...!')
                    print('连接ngrok服务器失败.')
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
