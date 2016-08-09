# 建议Python 3.1 以上运行 以下是依赖
# 项目地址: https://github.com/hauntek/python-ngrok
import socket
import select
import ssl
import json
import struct
import random
import time
import threading

host = 'server.ngrok.cc' # Ngrok服务器地址
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
        ip = socket.gethostbyname(host)
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_client = ssl.wrap_socket(client, ssl_version=ssl.PROTOCOL_SSLv23)
        ssl_client.connect((ip, port))
        ssl_client.setblocking(0)
    except socket.error:
        return False

    return ssl_client

def connectlocal(localhost, localport):
    try:
        ip = socket.gethostbyname(localhost)
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((ip, localport))
        client.setblocking(0)
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
    xx = struct.pack('N', len)
    xx1 = struct.pack('N', 0)
    return xx + xx1

def lentobyte1(len):
    xx = struct.pack('L', len)
    xx1 = struct.pack('L', 0)
    return xx + xx1

def sendbuf(sock, buf, isblock = True):
    if isblock:
        sock.setblocking(1)
    sock.send(buf)
    if isblock:
        sock.setblocking(0)

def sendpack(sock, msg, isblock = True):
    if isblock:
        sock.setblocking(1)
    sock.send(lentobyte1(len(msg)) + msg.encode('utf-8'))
    if isblock:
        sock.setblocking(0)

def tolen(v):
    return struct.unpack('N', v)[0]

def tolen1(v):
    return struct.unpack('L', v)[0]

def getRandChar(length):
    _chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz"
    return ''.join(random.sample(_chars, length))

# 客户端程序处理过程
def HKClient(sock, linkstate, type, tosock = None):
    global ClientId
    global pingtime
    recvbuf = bytes()
    while True:
        inputs = list()
        outputs = list()
        if isinstance(sock, socket.socket):
            inputs.append(sock)
            if linkstate == 0:
                outputs.append(sock)
        else:
            if sock == 1:
                mainsocket = False
            print('z:close')
        try:
            readable , writable , exceptional = select.select(inputs, outputs, [], 1)
        except select.error:
            print('select.error')

        # 可读
        if readable:
            try:
                recvbut = sock.recv(bufsize)
                if not recvbut: break

                if len(recvbut) > 0:
                    if not recvbuf:
                        recvbuf = recvbut
                    else:
                        recvbuf += recvbut

                if type == 1 or (type == 2 and linkstate == 1):
                    lenbyte = tolen1(recvbuf[0:4])
                    if len(recvbuf) >= (8 + lenbyte):
                        buf = recvbuf[8:].decode('utf-8')
                        js = json.loads(buf)
                        print(js)
                        if type == 1:
                            if js['Type'] == 'ReqProxy':
                                newsock = connectremote(host, port)
                                if newsock:
                                    thread = threading.Thread(target = HKClient, args = (newsock, 0, 2))
                                    thread.start()
                            if js['Type'] == 'AuthResp':
                                ClientId = js['Payload']['ClientId']
                                sendpack(sock, Ping())
                                pingtime = time.time()
                                for tunnelinfo in Tunnels:
                                    # 注册通道
                                    sendpack(sock, ReqTunnel(tunnelinfo['protocol'], tunnelinfo['hostname'], tunnelinfo['subdomain'], tunnelinfo['rport']))
                            if js['Type'] == 'NewTunnel':
                                if js['Payload']['Error'] != '':
                                    print('Add tunnel failed,%s' % js['Payload']['Error'])
                                    time.sleep(30)
                                else:
                                    print('Add tunnel ok,type:%s url:%s' % (js['Payload']['Protocol'], js['Payload']['Url']))

                        if type == 2:
                            if linkstate == 1:
                                if js['Type'] == 'StartProxy':
                                    loacladdr = getloacladdr(Tunnels, js['Payload']['Url'])

                                    newsock = connectlocal(loacladdr['lhost'], loacladdr['lport'])
                                    if newsock:
                                        thread = threading.Thread(target = HKClient, args = (newsock, 0, 3, sock))
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
                                        buf = header % (len(html), html)
                                        sendbuf(sock, buf.encode('utf-8'))

                        if len(recvbuf) == (8 + lenbyte):
                            recvbuf = bytes()
                        else:
                            recvbuf = recvbuf[8 + lenbyte:]

                if type == 3 or (type == 2 and linkstate == 2):
                    sendbuf(tosock, recvbuf)
                    recvbuf = bytes()

            except socket.error:
                print('socket.error')
                break

        # 可写
        if writable:
            if linkstate == 0:
                if type == 1:
                    sendpack(sock, NgrokAuth(), False)
                    linkstate = 1
                if type == 2:
                    sendpack(sock, RegProxy(ClientId), False)
                    linkstate = 1
                if type == 3:
                    linkstate = 1

    if type == 1:
        mainsocket = False
    # if type == 3:
    #     tosock.close()
    sock.close()

# 客户端程序初始化
if __name__ == '__main__':
    print('python-ngrok v1.2')
    mainsocket = connectremote(host, port)
    if mainsocket:
        thread = threading.Thread(target = HKClient, args = (mainsocket, 0, 1))
        thread.start()
    while True:

        # 检测控制连接是否连接.
        if mainsocket == False:
            ip = dnsopen(host)
            if ip == False:
                print('update dns')
                time.sleep(10)
                continue
            mainsocket = connectremote(ip, port)
            if mainsocket == False:
                print('connect failed...!')
                time.sleep(10)
                continue
            thread = threading.Thread(target = HKClient, args = (mainsocket, 0, 1))
            thread.start()

        # 发送心跳
        if pingtime + 25 < time.time() and pingtime != 0:
            sendpack(mainsocket, Ping())
            pingtime = time.time()
