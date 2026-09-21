"""Private IPv4 interface policy shared by LAN discovery and libtorrent."""

from __future__ import annotations

import socket
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network

import psutil

_PRIVATE_NETWORKS = tuple(
    ip_network(network) for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


@dataclass(frozen=True)
class LanInterface:
    name: str
    address: IPv4Address
    network: IPv4Network


def _eligible_address(address: IPv4Address) -> bool:
    return any(address in network for network in _PRIVATE_NETWORKS)


def lan_interfaces() -> tuple[LanInterface, ...]:
    """Return active non-point-to-point RFC 1918 IPv4 interfaces."""
    stats = psutil.net_if_stats()
    found: list[LanInterface] = []
    seen: set[IPv4Address] = set()
    for name, addresses in psutil.net_if_addrs().items():
        state = stats.get(name)
        if state is None or not state.isup:
            continue
        flags = {flag.strip().lower() for flag in str(state.flags or "").split(",") if flag}
        if "pointopoint" in flags or "loopback" in flags:
            continue
        for assigned in addresses:
            if assigned.family != socket.AF_INET or assigned.netmask is None:
                continue
            try:
                address = IPv4Address(assigned.address)
                network = ip_network(f"{assigned.address}/{assigned.netmask}", strict=False)
            except ValueError:
                continue
            if (
                not isinstance(network, IPv4Network)
                or network.prefixlen == 32
                or not _eligible_address(address)
                or address in {network.network_address, network.broadcast_address}
                or address in seen
            ):
                continue
            seen.add(address)
            found.append(LanInterface(name, address, network))
    return tuple(found)


@dataclass(frozen=True)
class LanNetworkPolicy:
    interfaces: tuple[LanInterface, ...]

    @property
    def addresses(self) -> tuple[str, ...]:
        return tuple(str(interface.address) for interface in self.interfaces)

    def allows_peer(self, value: str | IPv4Address) -> bool:
        try:
            address = value if isinstance(value, IPv4Address) else ip_address(value)
        except ValueError:
            return False
        return (
            isinstance(address, IPv4Address)
            and _eligible_address(address)
            and any(
                address in interface.network
                and address
                not in {
                    interface.network.network_address,
                    interface.network.broadcast_address,
                }
                for interface in self.interfaces
            )
        )


def current_lan_policy() -> LanNetworkPolicy:
    return LanNetworkPolicy(lan_interfaces())
