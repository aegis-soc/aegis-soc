"""内置插件注册入口。新增插件在此追加一行 register(...) 即可。"""
from __future__ import annotations

from typing import Callable

from plugins.base import BasePlugin
from plugins.builtin.http_generic import HttpGenericPlugin
from plugins.builtin.mock import MockPlugin
from plugins.builtin.sangfor_ips import SangforIpsPlugin
from plugins.builtin.ssh_firewall import SshFirewallPlugin


def register_builtins(register: Callable[[BasePlugin | type[BasePlugin]], None]) -> None:
    register(MockPlugin)
    register(HttpGenericPlugin)
    register(SshFirewallPlugin)
    register(SangforIpsPlugin)
