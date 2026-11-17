"""Muser 的应用层代理配置与探测（只依赖标准库）。

由 Muser 移植时加入（上游 Muser 1.0.0 无代理支持）：Muse 的服务在
某些网络下必须经网关代理才能到达，本模块让 vendored SDK 的三条链路
（muse_api 的 HTTPS、link_client 的 WSS、network 的在线探测）统一
经代理，与 Muse Gadget Zero 的 proxy.py 同一套语义：

* 配置优先级：环境变量 > Muser 偏好文件。环境变量指
  ``https_proxy/HTTPS_PROXY/all_proxy/ALL_PROXY/http_proxy/HTTP_PROXY``
  （按此顺序取第一个非空值），``NO_PROXY/no_proxy`` 单独合并。
* 偏好文件是 Muser 状态目录下的 ``preferences.json``（与音量、语言
  同一个文件），代理字段为 ``proxy_mode``（off/http/socks5）、
  ``proxy_host``、``proxy_port``、``proxy_username``、
  ``proxy_password``、``no_proxy``；没有代理字段时视为直连（off），
  与上游原行为完全一致。
* 状态目录的定位与 worker 一致：``MUSER_STATE_DIR`` 环境变量优先，
  其次 SDK 的 ``MUSEGADGET_STATE_DIR``，最后 ``~/.local/share/muser``。
* 密码只进内存：不出现在 ``repr``、日志、异常消息与
  :meth:`ProxyConfig.redacted_url` 的返回值中。
* websockets 的 ``proxy`` 参数语义（websockets 15.0.1，包内锁定
  版本）：``None`` 表示禁用代理、强制直连，字符串表示显式代理
  地址；不要传 ``False``。SOCKS 代理还需要 python-socks。
"""

from __future__ import annotations

import base64
import json
import os
import socket
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

__all__ = [
    "ProxyConfig",
    "ProxyConfigError",
    "CONFIG_ENV",
    "default_config_paths",
    "direct_opener",
    "find_config_path",
    "load_proxy_config",
]

#: 指定偏好文件的环境变量名（一般不用；默认按状态目录定位）。
CONFIG_ENV = "MUSER_PROXY_CONFIG"

#: 代理 URL 环境变量的优先级顺序（Muse 的目标都是 https/wss，
#: 因此 https_proxy 优先于只对明文 http 有意义的 http_proxy）。
_PROXY_ENV_KEYS = (
    "https_proxy",
    "HTTPS_PROXY",
    "all_proxy",
    "ALL_PROXY",
    "http_proxy",
    "HTTP_PROXY",
)

_VALID_MODES = ("off", "http", "socks5")


class ProxyConfigError(ValueError):
    """代理配置不合法。消息中永远不包含密码或完整的代理 URL。"""


def default_config_paths(environ: dict | None = None) -> list[Path]:
    """偏好文件候选路径（第一个存在的文件生效）。

    与 worker.initialize_state 的状态目录定位保持一致。
    """
    env = os.environ if environ is None else environ
    paths: list[Path] = []
    named = env.get(CONFIG_ENV)
    if named:
        paths.append(Path(named).expanduser())
    state = env.get("MUSER_STATE_DIR") or env.get("MUSEGADGET_STATE_DIR")
    if state:
        paths.append(Path(state).expanduser() / "preferences.json")
    home = Path(env.get("HOME", str(Path.home())))
    paths.append(home / ".local" / "share" / "muser" / "preferences.json")
    return paths


def find_config_path(
    config_path: str | Path | None = None,
    environ: dict | None = None,
) -> Path | None:
    """解析实际要读的配置文件路径；不存在时返回 None。"""
    if config_path is not None:
        path = Path(config_path).expanduser()
        return path if path.is_file() else None
    for candidate in default_config_paths(environ):
        if candidate.is_file():
            return candidate
    return None


@dataclass
class ProxyConfig:
    """一份已校验的代理配置。

    ``password`` 字段设置了 ``repr=False``，且本类自定义了
    ``__repr__``，密码不会出现在任何字符串表示中。
    """

    mode: str = "off"  # off / http / socks5
    host: str = ""
    port: int = 0
    username: str = ""
    password: str = field(default="", repr=False)
    no_proxy: tuple[str, ...] = ()

    def __repr__(self) -> str:  # 永远不带密码
        return (
            f"ProxyConfig(mode={self.mode!r}, host={self.host!r}, "
            f"port={self.port!r}, username={self.username!r}, "
            f"password=<redacted>, no_proxy={self.no_proxy!r})"
        )

    @property
    def is_off(self) -> bool:
        return self.mode == "off"

    def _auth_part(self) -> str:
        """URL 中的 ``user:pass@`` 片段（含密码，仅供拼真实连接 URL）。"""
        if not self.username:
            return ""
        user = urllib.parse.quote(self.username, safe="")
        secret = urllib.parse.quote(self.password, safe="")
        return f"{user}:{secret}@"

    def url_with_auth(self) -> str | None:
        """带凭据的完整代理 URL（含密码，禁止写日志/状态文件）。"""
        if self.is_off:
            return None
        scheme = "http" if self.mode == "http" else "socks5"
        return f"{scheme}://{self._auth_part()}{self.host}:{self.port}"

    def redacted_url(self) -> str:
        """供日志与 UI 显示的代理摘要，永不含密码。

        off 时返回 ``"off"``；有用户名时显示为 ``user:***@host:port``。
        """
        if self.is_off:
            return "off"
        scheme = "http" if self.mode == "http" else "socks5"
        if self.username:
            user = urllib.parse.quote(self.username, safe="")
            return f"{scheme}://{user}:***@{self.host}:{self.port}"
        return f"{scheme}://{self.host}:{self.port}"

    def summary(self) -> dict:
        """写入 status.json 的非敏感摘要。"""
        return {
            "mode": self.mode,
            "url": self.redacted_url(),
            "has_auth": bool(self.username),
            "no_proxy": list(self.no_proxy),
        }

    def should_bypass(self, host: str) -> bool:
        """目标主机是否命中 no_proxy（支持 ``.example.com`` 后缀写法）。"""
        target = (host or "").strip().lower()
        if not target:
            return False
        for entry in self.no_proxy:
            item = entry.strip().lower()
            if not item:
                continue
            if item == "*":
                return True
            if item.startswith("."):
                if target == item[1:] or target.endswith(item):
                    return True
            elif target == item or target.endswith("." + item):
                return True
        return False

    # -- 三条链路 -----------------------------------------------------------

    def urllib_opener(self) -> urllib.request.OpenerDirector:
        """为 HTTPS API 构建显式 opener，不受进程环境变量的隐式影响。

        * off：空 ProxyHandler，强制直连（连环境变量里的代理也忽略）。
        * http：显式 ProxyHandler，http/https 都走该代理。
        * socks5：标准库 urllib 不支持 SOCKS，抛出 ProxyConfigError；
          设备上如需 SOCKS 出口访问 HTTPS API，需另装 PySocks 并自建
          opener（WSS 链路不受影响，websockets + python-socks 可用）。
        """
        if self.is_off:
            # 手工组装 OpenerDirector 且不放 ProxyHandler：
            # build_opener() 会自带一个读环境变量的默认 ProxyHandler，
            # 正是要避免的隐式行为；而 ProxyHandler({}) 的空配置不
            # 注册任何协议处理方法、会被 add_handler 直接跳过，因此
            # 「不放 ProxyHandler」就是 urllib 里显式的无代理 opener，
            # 任何环境下都是确定性直连。
            opener = urllib.request.OpenerDirector()
            opener.add_handler(urllib.request.UnknownHandler())
            opener.add_handler(urllib.request.HTTPHandler())
            opener.add_handler(urllib.request.HTTPSHandler())
            opener.add_handler(urllib.request.HTTPDefaultErrorHandler())
            opener.add_handler(urllib.request.HTTPRedirectHandler())
            opener.add_handler(urllib.request.HTTPErrorProcessor())
            return opener
        if self.mode == "socks5":
            raise ProxyConfigError(
                "urllib does not support SOCKS proxies; "
                "use an http proxy for the Muse API or install PySocks"
            )
        url = self.url_with_auth()
        return urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": url, "https": url})
        )

    def websockets_proxy_arg(self):
        """应传给 ``websockets.asyncio.client.connect`` 的 ``proxy`` 值。

        * off -> ``None``：禁用代理并禁止库自行读环境变量（见模块
          docstring 对 websockets 15+ API 的核对结论；不要传 ``False``）。
        * http -> ``http://[user:pass@]host:port``
        * socks5 -> ``socks5://[user:pass@]host:port``（需 python-socks）
        """
        if self.is_off:
            return None
        return self.url_with_auth()

    # -- 连通性探测 -----------------------------------------------------------

    def probe(self, host: str, port: int, timeout: float = 5.0) -> bool:
        """探测能否经本代理到达 ``host:port``；off 时直连。

        http 走 CONNECT 隧道，socks5 走 SOCKS5 握手 + CONNECT。
        任何失败都返回 False，不抛带敏感信息的异常。
        """
        try:
            if self.is_off:
                with socket.create_connection((host, port), timeout=timeout):
                    return True
            if self.mode == "http":
                return self._probe_http_connect(host, port, timeout)
            return self._probe_socks5(host, port, timeout)
        except OSError:
            return False

    def _probe_http_connect(self, host: str, port: int, timeout: float) -> bool:
        with socket.create_connection((self.host, self.port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            lines = [
                f"CONNECT {host}:{port} HTTP/1.1",
                f"Host: {host}:{port}",
            ]
            if self.username:
                raw = f"{self.username}:{self.password}".encode()
                token = base64.b64encode(raw).decode("ascii")
                lines.append(f"Proxy-Authorization: Basic {token}")
            lines.append("")
            lines.append("")
            sock.sendall("\r\n".join(lines).encode("ascii", errors="replace"))
            reply = b""
            while b"\r\n\r\n" not in reply and len(reply) < 65536:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                reply += chunk
            status_line = reply.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
            parts = status_line.split(" ", 2)
            return len(parts) >= 2 and parts[1] == "200"

    def _probe_socks5(self, host: str, port: int, timeout: float) -> bool:
        with socket.create_connection((self.host, self.port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            methods = [0x00]  # 无认证
            if self.username:
                methods.append(0x02)  # 用户名/密码认证
            sock.sendall(bytes([0x05, len(methods), *methods]))
            greeting = _recv_exact(sock, 2)
            if greeting[0] != 0x05 or greeting[1] == 0xFF:
                return False
            if greeting[1] == 0x02:
                user = self.username.encode()
                secret = self.password.encode()
                if len(user) > 255 or len(secret) > 255:
                    return False
                sock.sendall(bytes([0x01, len(user)]) + user + bytes([len(secret)]) + secret)
                auth_reply = _recv_exact(sock, 2)
                if auth_reply[1] != 0x00:
                    return False
            host_bytes = host.encode("idna")
            if len(host_bytes) > 255:
                return False
            request = (
                bytes([0x05, 0x01, 0x00, 0x03, len(host_bytes)])
                + host_bytes
                + int(port).to_bytes(2, "big")
            )
            sock.sendall(request)
            reply_head = _recv_exact(sock, 4)
            if reply_head[0] != 0x05 or reply_head[1] != 0x00:
                return False
            # 按地址类型跳过绑定地址与端口，把隧道视为已建立。
            atyp = reply_head[3]
            if atyp == 0x01:
                _recv_exact(sock, 4 + 2)
            elif atyp == 0x03:
                length = _recv_exact(sock, 1)[0]
                _recv_exact(sock, length + 2)
            elif atyp == 0x04:
                _recv_exact(sock, 16 + 2)
            else:
                return False
            return True


def direct_opener() -> urllib.request.OpenerDirector:
    """显式无代理 opener（等价于 ProxyConfig(mode='off').urllib_opener()）。"""
    return ProxyConfig(mode="off").urllib_opener()


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    data = bytearray()
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise OSError("proxy closed the connection")
        data += chunk
    return bytes(data)


# -- 配置解析 ---------------------------------------------------------------


def _validate_host_port(host: object, port: object) -> tuple[str, int]:
    """校验主机与端口；错误消息只含字段名与类别，不回显凭据。"""
    if not isinstance(host, str) or not host.strip():
        raise ProxyConfigError("proxy host is required when a proxy mode is set")
    host = host.strip()
    if any(ch.isspace() for ch in host) or "/" in host or "@" in host:
        raise ProxyConfigError("proxy host is invalid")
    if ":" in host:
        # 只允许 IPv6 字面量（不带端口，端口是独立字段）。
        import ipaddress

        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            raise ProxyConfigError("proxy host is invalid") from None
    try:
        port_int = int(port)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        raise ProxyConfigError("proxy port must be an integer") from None
    if isinstance(port, bool) or not 1 <= port_int <= 65535:
        raise ProxyConfigError("proxy port must be between 1 and 65535")
    return host, port_int


def _parse_no_proxy(raw: object) -> tuple[str, ...]:
    if raw is None:
        return ()
    if isinstance(raw, str):
        items = raw.replace(";", ",").split(",")
    elif isinstance(raw, (list, tuple)):
        items = [str(item) for item in raw]
    else:
        return ()
    return tuple(item.strip() for item in items if str(item).strip())


def _config_from_env(environ: dict) -> ProxyConfig | None:
    """从环境变量解析；没有代理 URL 时返回 None（继续看配置文件）。"""
    raw_url = ""
    for key in _PROXY_ENV_KEYS:
        value = environ.get(key)
        if value and value.strip():
            raw_url = value.strip()
            break
    no_proxy = _parse_no_proxy(environ.get("NO_PROXY") or environ.get("no_proxy"))
    if not raw_url:
        return None
    if raw_url.lower() in ("off", "none", "direct"):
        return ProxyConfig(mode="off", no_proxy=no_proxy)
    parsed = urllib.parse.urlparse(raw_url if "://" in raw_url else f"http://{raw_url}")
    scheme = (parsed.scheme or "http").lower()
    if scheme in ("http", "https"):
        mode = "http"
    elif scheme in ("socks5", "socks5h", "socks4", "socks4a"):
        mode = "socks5"
    else:
        # 不回显原始 URL：其中可能带密码。
        raise ProxyConfigError("proxy environment URL has an unsupported scheme")
    if not parsed.hostname:
        raise ProxyConfigError("proxy environment URL is missing a host")
    try:
        port = parsed.port
    except ValueError:
        raise ProxyConfigError("proxy environment URL has an invalid port") from None
    if port is None:
        port = 1080 if mode == "socks5" else 8080
    host, port = _validate_host_port(parsed.hostname, port)
    username = urllib.parse.unquote(parsed.username or "")
    password = urllib.parse.unquote(parsed.password or "")
    return ProxyConfig(
        mode=mode, host=host, port=port,
        username=username, password=password, no_proxy=no_proxy,
    )


def _config_from_file(path: Path, environ: dict) -> ProxyConfig:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ProxyConfigError(f"cannot read proxy config file (OS error {exc.errno})") from None
    except ValueError:
        raise ProxyConfigError("proxy config file is not valid JSON") from None
    if not isinstance(data, dict):
        raise ProxyConfigError("proxy config file must contain a JSON object")

    # 同时接受 proxy_ 前缀字段（Muser 偏好文件的约定）与短字段名。
    def pick(*names: str, default=None):
        for name in names:
            if name in data and data[name] is not None:
                return data[name]
        return default

    mode = str(pick("proxy_mode", "mode", default="off")).strip().lower()
    if mode not in _VALID_MODES:
        raise ProxyConfigError("proxy_mode must be one of: off, http, socks5")
    no_proxy = _parse_no_proxy(pick("no_proxy", "proxy_no_proxy"))
    # 文件配置存在时，环境变量的 NO_PROXY 仍可覆盖绕过列表。
    env_no_proxy = _parse_no_proxy(environ.get("NO_PROXY") or environ.get("no_proxy"))
    if env_no_proxy:
        no_proxy = env_no_proxy
    if mode == "off":
        return ProxyConfig(mode="off", no_proxy=no_proxy)
    host, port = _validate_host_port(
        pick("proxy_host", "host"), pick("proxy_port", "port")
    )
    username = pick("proxy_username", "username", default="") or ""
    password = pick("proxy_password", "password", default="") or ""
    if not isinstance(username, str) or not isinstance(password, str):
        raise ProxyConfigError("proxy username/password must be strings")
    return ProxyConfig(
        mode=mode, host=host, port=port,
        username=username, password=password, no_proxy=no_proxy,
    )


def load_proxy_config(
    config_path: str | Path | None = None,
    environ: dict | None = None,
) -> ProxyConfig:
    """按「环境变量 > Muser 偏好文件 > 直连」解析代理配置。

    ``config_path`` 显式给出时只读该文件（文件不存在则视为无文件
    配置）；未给出时按 :func:`default_config_paths` 的顺序查找。
    环境变量中出现无法解析的代理 URL 时抛 ProxyConfigError，
    而不是悄悄回退到文件配置，避免「以为走了代理其实直连」。
    """
    env = os.environ if environ is None else environ
    from_env = _config_from_env(env)
    if from_env is not None:
        return from_env
    path = find_config_path(config_path, env)
    if path is not None:
        return _config_from_file(path, env)
    return ProxyConfig(mode="off", no_proxy=_parse_no_proxy(
        env.get("NO_PROXY") or env.get("no_proxy")
    ))
