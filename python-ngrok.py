#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# 建议Python 2.7.13 或 Python 3.1 以上运行
# 项目地址: https://github.com/hauntek/python-ngrok
# Version: v1.41
import socket
import ssl
import json
import struct
import random
import sys
import time
import logging
import threading

host = 'tunnel.qydev.com' # Ngrok服务器地址
port = 4443 # 端口
bufsize = 1024 # 吞吐量

Tunnels = list() # 全局渠道赋值
body = dict()
body['protocol'] = 'http'
body['hostname'] = 'www.xxx.com'
body['subdomain'] = ''
body['rport'] = 0
body['lhost'] = '127.0.0.1'
body['lport'] = 80
Tunnels.append(body) # 加入渠道队列

body = dict()
body['protocol'] = 'http'
body['hostname'] = ''
body['subdomain'] = 'xxx'
body['rport'] = 0
body['lhost'] = '127.0.0.1'
body['lport'] = 80
Tunnels.append(body) # 加入渠道队列

body = dict()
body['protocol'] = 'tcp'
body['hostname'] = ''
body['subdomain'] = ''
body['rport'] = 55499
body['lhost'] = '127.0.0.1'
body['lport'] = 22
Tunnels.append(body) # 加入渠道队列

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
    Payload['MmVersion'] = '1.7'
    Payload['User'] = 'user'
    Payload['Password'] = ''
    body = dict()
    body['Type'] = 'Auth'
    body['Payload'] = Payload
    buffer = json.dumps(body)
    return(buffer)

def ReqTunnel(Protocol, Hostname, Subdomain, RemotePort):
    Payload = dict()
    Payload['ReqId'] = getRandChar(8)
    Payload['Protocol'] = Protocol
    Payload['Hostname'] = Hostname
    Payload['Subdomain'] = Subdomain
    Payload['HttpAuth'] = ''
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
    xx = struct.pack('I', len)
    xx1 = struct.pack('I', 0)
    return xx + xx1

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
    return struct.unpack('I', v)[0]

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
                lenbyte = tolen(recvbuf[0:4])
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
                            logger.info('Authenticated with server, client id: %s' % ClientId)
                            sendpack(sock, Ping())
                            pingtime = time.time()
                            for tunnelinfo in Tunnels:
                                # 注册通道
                                sendpack(sock, ReqTunnel(tunnelinfo['protocol'], tunnelinfo['hostname'], tunnelinfo['subdomain'], tunnelinfo['rport']))
                        if js['Type'] == 'NewTunnel':
                            if js['Payload']['Error'] != '':
                                logger = logging.getLogger('%s' % 'client')
                                logger.error('Server failed to allocate tunnel: %s' % js['Payload']['Error'])
                                time.sleep(30)
                            else:
                                logger = logging.getLogger('%s' % 'client')
                                logger.info('Tunnel established at %s' % js['Payload']['Url'])
                    if type == 2:
                        if linkstate == 1:
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
                                    body = '<html><body style="background-color: #97a8b9"><div style="margin:auto; width:400px;padding: 20px 60px; background-color: #D3D3D3; border: 5px solid maroon;"><h2>Tunnel %s unavailable</h2><p>Unable to initiate connection to <strong>%s</strong>. This port is not yet available for web server.</p>'
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
        if tosock.fileno() != -1:
            tosock.shutdown(socket.SHUT_WR)

    logger = logging.getLogger('%s:%d' % ('Close', sock.fileno()))
    logger.debug('Closing')
    sock.close()

# 客户端程序初始化
if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s] [%(levelname)s:%(lineno)d] [%(name)s] %(message)s', datefmt='%Y/%m/%d %H:%M:%S')
    while True:
        try:
            # 检测控制连接是否连接.
            if mainsocket == False:
                ip = dnsopen(host)
                if ip == False:
                    logging.info('update dns')
                    time.sleep(10)
                    continue
                mainsocket = connectremote(ip, port)
                if mainsocket == False:
                    logging.info('connect failed...!')
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
