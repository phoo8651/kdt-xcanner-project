# modules/utils/__init__.py
from .ip import (
    parse_ports, normalize_targets, iter_targets, is_ipv4, is_ipv6,
    expand_cidr, validate_port
)
from .net import (
    is_admin, list_interfaces, get_iface_ips, pick_interface,
    resolve_host, set_socket_opts, set_tos_ttl
)
from .log import setup_logging, get_logger