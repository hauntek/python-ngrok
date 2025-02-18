import socket
import ssl
import json
import struct
import random
import sys
import time
import logging
import threading
import asyncio

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
        self.tunnels: list[dict] = []
        
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

class ProxyConnection:
    """代理连接处理器"""
    def __init__(self, client: 'NgrokClient'):
        self.client = client
        self.url = None
        self.proxy_reader: asyncio.StreamReader | None = None
        self.proxy_writer: asyncio.StreamWriter | None = None
        self.local_reader: asyncio.StreamReader | None = None
        self.local_writer: asyncio.StreamWriter | None = None
        self.running = True

    async def start(self):
        """启动代理连接全流程"""
        try:
            # 建立新的代理连接
            await self._connect_proxy_server()
            
            # 发送RegProxy注册
            await self._send_regproxy()

            # 等待StartProxy消息
            self.url = await self._message_loop_until_startproxy()
            if not self.url:
                logger.error("未收到有效URL")
                return

            # 连接到本地服务
            await self._connect_local_service()
            
            # 启动双向数据桥接
            await self._bridge_data()

        except asyncio.TimeoutError:
            logger.error("等待StartProxy消息超时")
        except Exception as e:
            logger.error(f"代理连接失败: {str(e)}")
        finally:
            await self._cleanup()

    async def _connect_proxy_server(self):
        """连接到代理服务器"""
        try:
            self.proxy_reader, self.proxy_writer = await asyncio.open_connection(
                host=self.client.config.server_host,
                port=self.client.config.server_port,
                ssl=self.client.ssl_ctx,
                server_hostname=self.client.config.server_host
            )
            logger.debug(f"已建立代理连接到 {self.client.config.server_host}:{self.client.config.server_port}")
        except Exception as e:
            logger.error(f"代理服务器连接失败: {str(e)}")
            raise

    async def _send_regproxy(self):
        """发送代理注册信息"""
        regproxy_msg = {
            'Type': 'RegProxy',
            'Payload': {
                'ClientId': self.client.client_id
            }
        }
        await self._send_packet(regproxy_msg)
        logger.debug(f"已发送RegProxy: {regproxy_msg}")

    async def _connect_local_service(self):
        """连接到本地服务"""
        lhost, lport = self.client.tunnel_map[self.url]
        try:
            self.local_reader, self.local_writer = await asyncio.open_connection(
                host=lhost,
                port=lport
            )
            logger.info(f"已连接到本地服务 {lhost}:{lport}")
        except Exception as e:
            logger.error(f"本地服务连接失败: {str(e)}")
            raise

    async def _message_loop_until_startproxy(self):
        """持续接收消息，直到收到StartProxy"""
        buffer = b''
        while True:
            data = await asyncio.wait_for(self.proxy_reader.read(4096), timeout=30)
            buffer += data
            while len(buffer) >= 8:
                msg_len = struct.unpack('<II', buffer[:8])[0]
                if len(buffer) < msg_len + 8:
                    break
                msg_data = buffer[8:8+msg_len]
                buffer = buffer[8+msg_len:]
                msg = json.loads(msg_data.decode('utf-8'))
                if msg.get('Type') == 'StartProxy':
                    return msg['Payload']['Url']

        return ''

    async def _bridge_data(self):
        """双向数据转发"""
        async def forward(src: asyncio.StreamReader, dst: asyncio.StreamWriter, label: str):
            try:
                while self.running:
                    data = await src.read(self.client.config.bufsize)
                    if not data:
                        logger.debug(f"{label} 连接正常关闭")
                        break
                    dst.write(data)
                    await dst.drain()
                    logger.debug(f"{label} 转发 {len(data)} bytes")
            except Exception as e:
                if self.running:
                    logger.error(f"{label} 转发错误: {str(e)}")

        await asyncio.gather(
            forward(self.local_reader, self.proxy_writer, "本地->服务端"),
            forward(self.proxy_reader, self.local_writer, "服务端->本地")
        )

    async def _send_packet(self, data: dict):
        """发送协议数据包"""
        try:
            msg = json.dumps(data).encode('utf-8')
            header = struct.pack('<II', len(msg), 0)
            self.proxy_writer.write(header + msg)
            await self.proxy_writer.drain()
        except Exception as e:
            logger.error(f"发送数据包失败: {str(e)}")
            raise

    async def _cleanup(self):
        """资源清理"""
        self.running = False
        for writer in [self.proxy_writer, self.local_writer]:
            if writer:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception as e:
                    logger.debug(f"资源清理时发生错误: {str(e)}")

class NgrokClient:
    def __init__(self, config: NgrokConfig):
        self.config = config
        self.client_id = ''
        self.last_ping = 0.0
        self.main_reader: asyncio.StreamReader | None = None
        self.main_writer: asyncio.StreamWriter | None = None
        self.req_map: dict[str, tuple[str, int]] = {}
        self.tunnel_map: dict[str, tuple[str, int]] = {}
        self.lock = threading.Lock()
        self.running = True
        self.ssl_ctx = self._create_ssl_context()
        self._validate_tunnels()

    def _create_ssl_context(self) -> ssl.SSLContext:
        """创建SSL上下文"""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _validate_tunnels(self):
        """验证隧道配置有效性"""
        required_fields = ['protocol', 'lhost', 'lport']
        for t in self.config.tunnels:
            for field in required_fields:
                if field not in t:
                    raise ValueError(f"隧道配置缺少必要字段: {field}")

    async def _connect_server(self):
        """连接到服务器"""
        try:
            self.main_reader, self.main_writer = await asyncio.open_connection(
                host=self.config.server_host,
                port=self.config.server_port,
                ssl=self.ssl_ctx,
                server_hostname=self.config.server_host
            )
            logger.info(f"成功连接到服务器 {self.config.server_host}:{self.config.server_port}")
        except Exception as e:
            logger.error(f"服务器连接失败: {str(e)}")
            raise

    async def _handle_auth(self):
        """处理认证流程"""
        auth_msg = {
            'Type': 'Auth',
            'Payload': {
                'ClientId': self.client_id,
                'OS': 'darwin',
                'Arch': 'amd64',
                'Version': '2',
                'MmVersion': '1.7',
                'User': 'user',
                'Password': ''
            }
        }
        await self._send_packet(auth_msg)

    async def _send_packet(self, data: dict):
        """发送协议数据包"""
        try:
            msg = json.dumps(data).encode('utf-8')
            header = struct.pack('<II', len(msg), 0)
            self.main_writer.write(header + msg)
            await self.main_writer.drain()
            logger.debug(f"发送数据包: {data}")
        except Exception as e:
            logger.error(f"发送数据失败: {str(e)}")
            self._safe_close()

    def _safe_close(self):
        """安全关闭连接"""
        if self.main_writer:
            try:
                self.main_writer.close()
            except:
                pass

    async def _handle_req_tunnel(self):
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
            await self._send_packet(req_msg)

    async def _process_message(self, msg: dict):
        """处理服务器消息"""
        msg_type = msg.get('Type', '')
        payload = msg.get('Payload', {})

        if msg_type == 'AuthResp':
            self.client_id = payload.get('ClientId', '')
            logger.info(f"认证成功，客户端ID: {self.client_id}")
            await self._handle_req_tunnel()
            self.last_ping = time.time()

        elif msg_type == 'NewTunnel':
            if payload.get('Error'):
                logger.error(f"隧道建立失败: {payload['Error']}")
            else:
                url = payload['Url']
                self.tunnel_map[url] = self.req_map.get(payload['ReqId'], ('', 0))
                logger.info(f"隧道已建立: {url}")

        elif msg_type == 'ReqProxy':
            logger.info(f"收到代理请求，启动新连接...")
            proxy_conn = ProxyConnection(self)
            asyncio.create_task(proxy_conn.start())

        elif msg_type == 'Pong':
            self.last_ping = time.time()
            logger.debug("收到心跳响应")

    async def _recv_loop(self):
        """接收数据主循环"""
        try:
            buffer = b''
            while self.running:
                data = await self.main_reader.read(4096)
                buffer += data
                while len(buffer) >= 8:
                    msg_len = struct.unpack('<II', buffer[:8])[0]
                    if len(buffer) < msg_len + 8:
                        break

                    msg_data = buffer[8:8+msg_len]
                    buffer = buffer[8+msg_len:]
                    
                    try:
                        msg = json.loads(msg_data.decode('utf-8'))
                        logger.debug(f"收到消息: {msg}")
                        await self._process_message(msg)
                    except json.JSONDecodeError:
                        logger.error("消息解析失败")


        except (asyncio.IncompleteReadError, ConnectionError) as e:
            logger.error(f"连接中断: {str(e)}")
        except Exception as e:
            logger.error(f"接收数据时发生错误: {str(e)}")
        finally:
            self.running = False
            self._safe_close()

    async def _heartbeat_task(self):
        """心跳任务"""
        while self.running:
            if time.time() - self.last_ping > 20:
                try:
                    await self._send_packet({'Type': 'Ping'})
                    self.last_ping = time.time()
                except Exception as e:
                    logger.error(f"发送心跳失败: {str(e)}")
                    self.running = False
            await asyncio.sleep(1)

    async def start(self):
        """启动客户端主循环"""
        try:
            await self._connect_server()
            await self._handle_auth()
            
            # 启动接收和心跳任务
            await asyncio.gather(
                self._recv_loop(),
                self._heartbeat_task()
            )

        except Exception as e:
            logger.error(f"客户端启动失败: {str(e)}")
        finally:
            self._safe_close()
            logger.info("客户端已停止")

if __name__ == '__main__':
    try:
        config = NgrokConfig.from_file(sys.argv[1]) if len(sys.argv) > 1 else NgrokConfig()
        client = NgrokClient(config)
        asyncio.run(client.start())
    except KeyboardInterrupt:
        logger.info("用户中断操作")
    except Exception as e:
        logger.error(f"客户端异常终止: {str(e)}")
