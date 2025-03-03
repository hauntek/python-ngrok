#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# 建议Python 3.10.0 以上运行
# 项目地址: https://github.com/hauntek/python-ngrok
# Version: 2.2.0
import asyncio
import socket
import ssl
import json
import struct
import sys
import time
import secrets
import logging
from dataclasses import dataclass, asdict, fields

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y/%m/%d %H:%M:%S'
)
logger = logging.getLogger('NgrokClient')

@dataclass
class Auth:
    Version: str = "2"
    MmVersion: str = "1.7"
    User: str = ""
    Password: str = ""
    OS: str = "darwin"
    Arch: str = "amd64"
    ClientId: str = ""
    @classmethod
    def get_class_name(cls):
        return cls.__name__

@dataclass
class AuthResp:
    Version: str = "2"
    MmVersion: str = "1.7"
    ClientId : str = ""
    Error: str = ""
    @classmethod
    def get_class_name(cls):
        return cls.__name__

@dataclass
class ReqTunnel:
    ReqId: str = ""
    Protocol: str = ""
    Hostname: str = ""
    Subdomain: str = ""
    HttpAuth: str = ""
    RemotePort: int = 0
    @classmethod
    def get_class_name(cls):
        return cls.__name__

@dataclass
class NewTunnel:
    ReqId: str = ""
    Url: str = ""
    Protocol: str = ""
    Error: str = ""
    @classmethod
    def get_class_name(cls):
        return cls.__name__

@dataclass
class ReqProxy:
    pass
    @classmethod
    def get_class_name(cls):
        return cls.__name__

@dataclass
class RegProxy:
    ClientId: str = ""
    @classmethod
    def get_class_name(cls):
        return cls.__name__

@dataclass
class StartProxy:
    Url: str = ""
    ClientAddr: str = ""
    @classmethod
    def get_class_name(cls):
        return cls.__name__

@dataclass
class Ping:
    pass
    @classmethod
    def get_class_name(cls):
        return cls.__name__

@dataclass
class Pong:
    pass
    @classmethod
    def get_class_name(cls):
        return cls.__name__

class NgrokConfig:
    def __init__(self):
        self.server_host = 'tunnel.qydev.com'
        self.server_port = 4443
        self.bufsize = 1024
        self.authtoken = ''
        self.tunnels: list[dict] = []

        body = dict()
        body['protocol'] = 'http'
        body['hostname'] = 'www.xxx.com'
        body['subdomain'] = ''
        body['httpauth'] = ''
        body['rport'] = 0
        body['lhost'] = '127.0.0.1'
        body['lport'] = 80
        self.tunnels.append(body) # 加入渠道队列

        body = dict()
        body['protocol'] = 'http'
        body['hostname'] = ''
        body['subdomain'] = 'xxx'
        body['httpauth'] = ''
        body['rport'] = 0
        body['lhost'] = '127.0.0.1'
        body['lport'] = 80
        self.tunnels.append(body) # 加入渠道队列

        body = dict()
        body['protocol'] = 'tcp'
        body['hostname'] = ''
        body['subdomain'] = ''
        body['httpauth'] = ''
        body['rport'] = 55499
        body['lhost'] = '127.0.0.1'
        body['lport'] = 22
        self.tunnels.append(body) # 加入渠道队列

        body = dict()
        body['protocol'] = 'udp'
        body['hostname'] = ''
        body['subdomain'] = ''
        body['httpauth'] = ''
        body['rport'] = 55499
        body['lhost'] = '127.0.0.1'
        body['lport'] = 53
        self.tunnels.append(body) # 加入渠道队列

    @classmethod
    def from_file(cls, filename: str) -> 'NgrokConfig':
        """从配置文件加载配置"""
        config = cls()
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
                config.server_host = data["server"]["host"]
                config.server_port = int(data["server"]["port"])
                config.bufsize = int(data["server"].get("bufsize", 1024))
                config.authtoken = data["server"].get("authtoken", "")
                config.tunnels = [
                    {
                        'protocol': t["protocol"],
                        'hostname': t.get("hostname", ""),
                        'subdomain': t.get("subdomain", ""),
                        'httpauth': t.get("httpauth", ""),
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
        self.udp_transport: asyncio.DatagramTransport | None = None
        self.local_queue: asyncio.Queue | None = None
        self.tasks = []
        self.running = True

    async def start(self):
        """启动代理连接全流程"""
        try:
            # 建立新的代理连接
            await self._connect_proxy_server()
            
            # 发送RegProxy注册
            try:
                regproxy_msg = RegProxy(ClientId=self.client.client_id)
                await self.client._send_packet(self.proxy_writer, regproxy_msg)
            except Exception as e:
                logger.debug(f"发送数据时发生错误: {str(e)}")
                return

            # 等待StartProxy消息
            try:
                msg = await self.client._recv_packet(self.proxy_reader)
                if not msg:
                    return
                if not isinstance(msg, StartProxy):
                    logger.debug("未收到StartProxy消息")
                    return

                if not msg.Url:
                    logger.debug("未收到有效URL")
                    return
                self.url = msg.Url
            except Exception as e:
                logger.debug(f"接收数据时发生错误: {str(e)}")
                return

            protocol = self.url.split(":")[0]
            if protocol == 'udp':
                # 连接到本地服务
                await self._connect_local_service_udp()
                # 启动双向数据桥接
                await self._bridge_data_udp()
                return

            # 连接到本地服务
            await self._connect_local_service_tcp()
            # 启动双向数据桥接
            await self._bridge_data_tcp()

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

    async def _connect_local_service_udp(self):
        class LocalProtocol(asyncio.DatagramProtocol):
            def __init__(self, proxy_conn: ProxyConnection):
                self.proxy_conn = proxy_conn
                self.local_queue = asyncio.Queue()

            def datagram_received(self, data: bytes, addr: tuple[str, int]):
                self.local_queue.put_nowait(data)

            def error_received(self, exc: OSError):
                logger.error(f"UDP 错误: {exc}")

        """连接到本地UDP服务"""
        local_host, local_port = self.client.tunnel_map[self.url]
        try:
            loop = asyncio.get_running_loop()
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: LocalProtocol(self),
                remote_addr=(local_host, local_port)
            )
            self.udp_transport = transport
            self.local_queue = protocol.local_queue
            logger.info(f"已连接到本地 UDP 服务 {local_host}:{local_port}")
        except Exception as e:
            logger.error(f"本地 UDP 服务连接失败: {str(e)}")
            raise

    async def _connect_local_service_tcp(self):
        """连接到本地TCP服务"""
        local_host, local_port = self.client.tunnel_map[self.url]
        try:
            self.local_reader, self.local_writer = await asyncio.open_connection(
                host=local_host,
                port=local_port
            )
            logger.info(f"已连接到本地 TCP 服务 {local_host}:{local_port}")
        except Exception as e:
            logger.error(f"本地 TCP 服务连接失败: {str(e)}")
            raise

    async def _bridge_data_udp(self):
        """双向数据转发"""
        async def tcp_to_udp(src: asyncio.StreamReader, label: str):
            try:
                buffer = b''
                while self.running:
                    data = await src.read(self.client.config.bufsize)
                    if not data:
                        logger.debug(f"{label} 连接正常关闭")
                        break
                    buffer += data
                    while len(buffer) >= 8:
                        pkt_len, _ = struct.unpack('<II', buffer[:8])
                        if len(buffer) < 8 + pkt_len:
                            break
                        udp_data = buffer[8:8+pkt_len]
                        if self.udp_transport:
                            self.udp_transport.sendto(udp_data, None)
                            logger.debug(f"{label} 转发 {len(udp_data)} bytes")
                        buffer = buffer[8+pkt_len:]
            except asyncio.CancelledError:
                pass
            except Exception as e:
                if self.running:
                    logger.error(f"{label} 转发错误: {str(e)}")

        async def udp_to_tcp(src: asyncio.Queue, label: str):
            try:
                while self.running:
                    data = await src.get()
                    if data is None:
                        logger.debug(f"{label} 收到终止信号")
                        break
                    header = struct.pack('<LL', len(data), 0)
                    self.proxy_writer.write(header + data)
                    await self.proxy_writer.drain()
                    logger.debug(f"{label} 转发 {len(data)} bytes")
            except asyncio.CancelledError:
                pass
            except Exception as e:
                if self.running:
                    logger.error(f"{label} 转发错误: {str(e)}")

        tcp_task = asyncio.create_task(tcp_to_udp(self.proxy_reader, "服务端 TCP -> 本地 UDP"))
        udp_task = asyncio.create_task(udp_to_tcp(self.local_queue, "服务端 TCP <- 本地 UDP"))
        self.tasks.extend([tcp_task, udp_task])

        done, pending = await asyncio.wait({udp_task, tcp_task}, return_when=asyncio.FIRST_COMPLETED)

        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)

    async def _bridge_data_tcp(self):
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
            except asyncio.CancelledError:
                pass
            except Exception as e:
                if self.running:
                    logger.error(f"{label} 转发错误: {str(e)}")

        task1 = asyncio.create_task(
            forward(self.proxy_reader, self.local_writer, "服务端 TCP -> 本地 TCP")
        )
        task2 = asyncio.create_task(
            forward(self.local_reader, self.proxy_writer, "服务端 TCP <- 本地 TCP")
        )
        self.tasks.extend([task1, task2])

        done, pending = await asyncio.wait({task1, task2}, return_when=asyncio.FIRST_COMPLETED)

        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)

    async def _cleanup(self):
        """资源清理"""
        self.running = False

        # 取消本连接创建的所有任务
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)

        writers = [self.proxy_writer, self.local_writer]
        for writer in writers:
            if writer and not writer.is_closing():
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception as e:
                    logger.debug(f"关闭 writer 时发生错误: {str(e)}")

        if self.udp_transport:
            try:
                self.udp_transport.close()
            except Exception as e:
                logger.debug(f"关闭 UDP 传输时发生错误: {str(e)}")

        if self.local_queue is not None:
            try:
                self.local_queue.put_nowait(None)
            except asyncio.QueueFull:
                await self.local_queue.put(None)

        # 从客户端移除本连接
        async with self.client.lock:
            if self in self.client.proxy_connections:
                self.client.proxy_connections.remove(self)

class NgrokClient:
    def __init__(self, config: NgrokConfig):
        self.config = config
        self.client_id = ''
        self.last_ping = 0.0
        self.current_retry_interval = 1
        self.max_retry_interval = 60
        self.main_loop_task = None
        self.main_reader: asyncio.StreamReader | None = None
        self.main_writer: asyncio.StreamWriter | None = None
        self.ssl_ctx = self._create_ssl_context()
        self.req_map: dict[str, tuple[str, int]] = {}
        self.tunnel_map: dict[str, tuple[str, int]] = {}
        self.proxy_connections = []
        self.lock = asyncio.Lock()
        self.running = True
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
        except ConnectionRefusedError:
            logger.error(f"服务器拒绝连接: {self.config.server_host}:{self.config.server_port}")
            raise
        except Exception as e:
            logger.error(f"服务器连接失败: {str(e)}")
            raise

    async def _handle_auth(self):
        """处理认证流程"""
        auth_msg = Auth(ClientId=self.client_id, User=self.config.authtoken)
        await self._send_packet(self.main_writer, auth_msg)

    def dict_to_message(self, msg: dict):
        """
        Converts a dictionary to a message type.
        """
        msg_type = msg.get("Type")
        payload = msg.get("Payload", {})
        msg_classes = {
            "Auth": Auth,
            "AuthResp": AuthResp,
            "ReqTunnel": ReqTunnel,
            "NewTunnel": NewTunnel,
            "ReqProxy": ReqProxy,
            "RegProxy": RegProxy,
            "StartProxy": StartProxy,
            "Ping": Ping,
            "Pong": Pong
        }
        if msg_type in msg_classes:
            cls = msg_classes[msg_type]
            payload = {k: payload[k] for k in payload if k in {f.name for f in fields(cls)}}
            return cls(**payload)
        else:
            raise ValueError(f"Unknown message type: {msg_type}")

    async def _recv_packet(self, reader: asyncio.StreamReader):
        """接收协议数据包"""
        header = await reader.read(8)
        if not header:
            logger.debug("连接已关闭")
            return
        msg_len, _ = struct.unpack('<II', header)
        data = await reader.read(msg_len)
        msg = json.loads(data.decode('utf-8'))
        logger.debug(f"收到消息: {msg}")
        return self.dict_to_message(msg)

    async def _send_packet(self, writer: asyncio.StreamWriter, msg):
        """发送协议数据包"""
        data = {"Type": msg.get_class_name(), "Payload": asdict(msg)}
        msg = json.dumps(data).encode('utf-8')
        header = struct.pack('<LL', len(msg), 0)
        writer.write(header + msg)
        await writer.drain()
        logger.debug(f"发送数据包: {data}")

    async def _handle_req_tunnel(self):
        """请求建立隧道"""
        for tunnel in self.config.tunnels:
            request_id = secrets.token_hex(8)
            self.req_map[request_id] = (tunnel['lhost'], tunnel['lport'])
            
            req_msg = ReqTunnel(
                ReqId=request_id,
                Protocol=tunnel['protocol'],
                Hostname=tunnel['hostname'],
                Subdomain=tunnel['subdomain'],
                HttpAuth=tunnel['httpauth'],
                RemotePort=tunnel['rport']
            )
            await self._send_packet(self.main_writer, req_msg)

    async def _process_message(self, msg):
        """处理服务器消息"""
        if isinstance(msg, AuthResp):
            if msg.Error:
                logger.error(f"认证失败: {msg.Error}")
                self.running = False
                return
            self.client_id = msg.ClientId
            logger.info(f"认证成功，客户端ID: {self.client_id}")
            await self._handle_req_tunnel()
            self.last_ping = time.time()
        elif isinstance(msg, NewTunnel):
            if msg.Error:
                logger.error(f"隧道建立失败: {msg.Error}")
                return
            url = msg.Url
            self.tunnel_map[url] = self.req_map.get(msg.ReqId, ('', 0))
            logger.info(f"隧道已建立: {url}")
        elif isinstance(msg, ReqProxy):
            async with self.lock:
                logger.info(f"收到代理请求，启动新连接...")
                proxy_conn = ProxyConnection(self)
                self.proxy_connections.append(proxy_conn)
                asyncio.create_task(proxy_conn.start())
        elif isinstance(msg, Pong):
            self.last_ping = time.time()
            logger.debug("收到心跳响应")

    async def _recv_loop(self):
        """接收数据主循环"""
        try:
            while self.running:
                msg = await self._recv_packet(self.main_reader)
                if not msg:
                    self.last_ping = time.time()
                    await asyncio.sleep(1)
                await self._process_message(msg)
        except (asyncio.IncompleteReadError, ConnectionError) as e:
            logger.debug(f"连接中断: {str(e)}")
        except Exception as e:
            logger.debug(f"接收数据时发生错误: {str(e)}")
        finally:
            self.running = False

    async def _wait_for_reconnect(self):
        """等待重连前的清理"""
        if self.main_loop_task:
            try:
                self.main_loop_task.cancel()
                await self.main_loop_task
            except asyncio.CancelledError:
                logger.debug("主循环任务已正常取消")

    async def _cleanup_resources(self):
        """增强的资源清理方法"""
        # 关闭主连接
        if self.main_writer:
            self.main_writer.close()
            try:
                await self.main_writer.wait_closed()
            except Exception as e:
                logger.debug(f"关闭连接时发生错误: {str(e)}")
            self.main_writer = None

        # 关闭所有代理连接任务
        async with self.lock:
            for conn in self.proxy_connections.copy():
                try:
                    # 取消所有代理连接创建的任务
                    for task in conn.tasks:
                        task.cancel()
                    await asyncio.gather(*conn.tasks, return_exceptions=True)
                except Exception as e:
                    logger.debug(f"清理代理连接任务时出错: {str(e)}")

        self.req_map.clear()
        self.tunnel_map.clear()
        self.proxy_connections.clear()

    async def _heartbeat_task(self):
        """心跳任务"""
        while self.running:
            if self.last_ping and time.time() - self.last_ping > 20:
                try:
                    await self._send_packet(self.main_writer, Ping())
                    self.last_ping = time.time()
                except Exception as e:
                    logger.debug(f"发送心跳失败: {str(e)}")
                    self.running = False
            await asyncio.sleep(1)

    async def _main_loop(self):
        """业务逻辑主循环"""
        self.running = True
        self.main_loop_task = asyncio.gather(
            self._recv_loop(),
            self._heartbeat_task()
        )
        try:
            try:
                await self._handle_auth()
            except Exception as e:
               logger.debug(f"发送数据时发生错误: {str(e)}")
               raise
            # 启动接收和心跳任务
            await self.main_loop_task
        except asyncio.CancelledError:
            logger.debug("主循环任务被取消")
            raise

    async def _connect_with_retry(self):
        """带指数退避的连接方法"""
        while True:
            try:
                await self._connect_server()
                self.current_retry_interval = 1
                return
            except Exception as e:
                logger.error(f"连接失败，{self.current_retry_interval}秒后重试...")
                try:
                    # 等待重连间隔
                    await asyncio.sleep(self.current_retry_interval)
                except asyncio.CancelledError:
                    logger.debug("重连等待被中断")
                    raise
                self.current_retry_interval = min(
                    self.current_retry_interval * 2,
                    self.max_retry_interval
                )

    async def start(self):
        """启动客户端主循环"""
        while True:
            try:
                await self._connect_with_retry()
                await self._main_loop()
            except Exception as e:
                logger.error(f"运行时异常: {str(e)}")
            finally:
                await self._cleanup_resources()
                await self._wait_for_reconnect()

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
