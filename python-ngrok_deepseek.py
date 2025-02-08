import socket
import ssl
import json
import struct
import random
import sys
import time
import logging
import threading
from typing import Dict, Tuple, Optional, List

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y/%m/%d %H:%M:%S'
)
logger = logging.getLogger('NgrokClient')

class NgrokConfig:
    def __init__(self):
        self.server_host = 'tunnel.qydev.com'
        self.server_port = 4443
        self.bufsize = 4096
        self.dualstack = True
        self.tunnels: List[dict] = []
        
    @classmethod
    def from_file(cls, filename: str) -> 'NgrokConfig':
        """从配置文件加载配置"""
        config = cls()
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
                config.server_host = data["server"]["host"]
                config.server_port = int(data["server"]["port"])
                config.bufsize = int(data["server"].get("bufsize", 4096))
                config.tunnels = [
                    {
                        'protocol': t["protocol"],
                        'hostname': t.get("hostname", ""),
                        'subdomain': t.get("subdomain", ""),
                        'rport': int(t.get("rport", 0)),
                        'lhost': t["lhost"],
                        'lport': int(t["lport"])
                    }
                    for t in data["client"]
                ]
        except Exception as e:
            logger.error(f"配置文件加载失败: {str(e)}")
            raise
        return config

class NgrokClient:
    def __init__(self, config: NgrokConfig):
        self.config = config
        self.client_id = ''
        self.last_ping = 0.0
        self.main_socket: Optional[ssl.SSLSocket] = None
        self.req_map: Dict[str, Tuple[str, int]] = {}
        self.tunnel_map: Dict[str, Tuple[str, int]] = {}
        self.lock = threading.Lock()
        self.running = True
        
        # 创建SSL上下文
        self.ssl_ctx = ssl.create_default_context()
        self.ssl_ctx.check_hostname = False
        self.ssl_ctx.verify_mode = ssl.CERT_NONE
        
        # 验证隧道配置
        self._validate_tunnels()

    def _validate_tunnels(self):
        """验证隧道配置有效性"""
        required = ['protocol', 'lhost', 'lport']
        for t in self.config.tunnels:
            for field in required:
                if field not in t:
                    raise ValueError(f"隧道配置缺少必要字段: {field}")

    def _create_socket(self, af: int) -> Optional[socket.socket]:
        """创建基础socket连接"""
        try:
            return socket.socket(af, socket.SOCK_STREAM)
        except socket.error as e:
            logger.debug(f"创建socket失败: {str(e)}")
            return None

    def connect_server(self) -> Optional[ssl.SSLSocket]:
        """连接到Ngrok服务器"""
        logger.info(f"正在连接服务器 {self.config.server_host}:{self.config.server_port}...")
        
        # 获取地址信息
        addrinfo = socket.getaddrinfo(
            self.config.server_host,
            self.config.server_port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM
        )

        for res in sorted(addrinfo, key=lambda x: x[0] == socket.AF_INET6, reverse=True):
            af, socktype, proto, _, sa = res
            client = self._create_socket(af)
            if not client:
                continue

            try:
                client.settimeout(10)
                client.connect(sa)
                ssl_sock = self.ssl_ctx.wrap_socket(client, server_hostname=self.config.server_host)
                ssl_sock.setblocking(False)
                logger.info(f"成功连接到服务器 {sa[0]}:{sa[1]}")
                return ssl_sock
            except (socket.error, ssl.SSLError) as e:
                logger.debug(f"连接失败 {sa}: {str(e)}")
                client.close()

        logger.error("无法连接到服务器")
        return None

    def _send_packet(self, sock: ssl.SSLSocket, data: dict):
        """发送协议数据包"""
        try:
            msg = json.dumps(data).encode('utf-8')
            header = struct.pack('<LL', len(msg), 0)
            with self.lock:
                sock.send(header + msg)
                logger.debug(f"发送数据包: {data}")
        except (OSError, ssl.SSLError) as e:
            logger.error(f"发送数据失败: {str(e)}")
            self._safe_close(sock)

    def _safe_close(self, sock: Optional[ssl.SSLSocket]):
        """安全关闭socket"""
        if sock:
            try:
                sock.shutdown(socket.SHUT_RDWR)
                sock.close()
            except:
                pass

    def _handle_auth(self):
        """处理认证流程"""
        auth_msg = {
            'Type': 'Auth',
            'Payload': {
                'ClientId': self.client_id,
                'OS': 'python',
                'Arch': 'universal',
                'Version': '2.3',
                'MmVersion': '1.7',
                'User': 'user',
                'Password': ''
            }
        }
        self._send_packet(self.main_socket, auth_msg)

    def _handle_req_tunnel(self):
        """请求建立隧道"""
        for tunnel in self.config.tunnels:
            req_id = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=8))
            self.req_map[req_id] = (tunnel['lhost'], tunnel['lport'])
            
            req_msg = {
                'Type': 'ReqTunnel',
                'Payload': {
                    'ReqId': req_id,
                    'Protocol': tunnel['protocol'],
                    'Hostname': tunnel['hostname'],
                    'Subdomain': tunnel['subdomain'],
                    'RemotePort': tunnel['rport'],
                    'HttpAuth': ''
                }
            }
            self._send_packet(self.main_socket, req_msg)

    def _handle_proxy_connection(self, url: str):
        """处理代理连接"""
        if url not in self.tunnel_map:
            logger.error(f"未知隧道URL: {url}")
            return

        lhost, lport = self.tunnel_map[url]
        try:
            with socket.create_connection((lhost, lport), timeout=10) as local_sock:
                thread = threading.Thread(
                    target=self._bridge_connections,
                    args=(self.main_socket, local_sock)
                )
                thread.start()
                thread.join()
        except Exception as e:
            logger.error(f"无法连接到本地服务 {lhost}:{lport}: {str(e)}")

    def _bridge_connections(self, remote: ssl.SSLSocket, local: socket.socket):
        """桥接两个连接"""
        try:
            while self.running:
                r, _, _ = select.select([remote, local], [], [], 1)
                for sock in r:
                    data = sock.recv(self.config.bufsize)
                    if not data:
                        return
                    if sock is remote:
                        local.sendall(data)
                    else:
                        remote.sendall(data)
        except:
            pass
        finally:
            self._safe_close(remote)
            local.close()

    def _process_message(self, sock: ssl.SSLSocket, msg: dict):
        """处理服务器消息"""
        msg_type = msg.get('Type', '')
        payload = msg.get('Payload', {})

        if msg_type == 'AuthResp':
            self.client_id = payload.get('ClientId', '')
            logger.info(f"认证成功，客户端ID: {self.client_id}")
            self._send_packet(sock, {'Type': 'Ping'})
            self.last_ping = time.time()
            self._handle_req_tunnel()

        elif msg_type == 'NewTunnel':
            if payload.get('Error'):
                logger.error(f"隧道建立失败: {payload['Error']}")
            else:
                url = payload['Url']
                self.tunnel_map[url] = self.req_map.get(payload['ReqId'], ('', 0))
                logger.info(f"隧道已建立: {url}")

        elif msg_type == 'StartProxy':
            self._handle_proxy_connection(payload['Url'])

        elif msg_type == 'Pong':
            self.last_ping = time.time()

    def _recv_loop(self, sock: ssl.SSLSocket):
        """接收数据主循环"""
        buffer = b''
        while self.running:
            try:
                data = sock.recv(self.config.bufsize)
                if not data:
                    break

                buffer += data
                while len(buffer) >= 8:
                    msg_len = struct.unpack('<LL', buffer[:8])[0]
                    if len(buffer) < msg_len + 8:
                        break

                    msg_data = buffer[8:8+msg_len]
                    buffer = buffer[8+msg_len:]
                    
                    try:
                        msg = json.loads(msg_data.decode('utf-8'))
                        logger.debug(f"收到消息: {msg}")
                        self._process_message(sock, msg)
                    except json.JSONDecodeError:
                        logger.error("消息解析失败")

            except (ssl.SSLError, socket.error) as e:
                logger.error(f"连接错误: {str(e)}")
                break

        self.running = False
        self._safe_close(sock)

    def start(self):
        """启动客户端主循环"""
        while self.running:
            if not self.main_socket:
                self.main_socket = self.connect_server()
                if not self.main_socket:
                    time.sleep(5)
                    continue

                # 启动认证流程
                self._handle_auth()
                threading.Thread(target=self._recv_loop, args=(self.main_socket,)).start()

            # 心跳处理
            if time.time() - self.last_ping > 20 and self.last_ping > 0:
                try:
                    self._send_packet(self.main_socket, {'Type': 'Ping'})
                    self.last_ping = time.time()
                except:
                    self.main_socket = None

            time.sleep(1)

        logger.info("客户端已停止")

if __name__ == '__main__':
    try:
        config = NgrokConfig.from_file(sys.argv[1]) if len(sys.argv) > 1 else NgrokConfig()
        client = NgrokClient(config)
        client.start()
    except KeyboardInterrupt:
        logger.info("用户中断操作")
    except Exception as e:
        logger.error(f"客户端异常终止: {str(e)}")