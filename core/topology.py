from dataclasses import dataclass


@dataclass(frozen=True)
class VMTopology:
    local_underlay: str
    remote_underlay: str
    local_ts: str
    remote_ts: str
    traffic_source: str
    traffic_target: str


VM1_UNDERLAY = "10.10.10.1"
VM2_UNDERLAY = "10.10.10.2"

VM1_TUNNEL_IP = "10.20.1.1"
VM2_TUNNEL_IP = "10.20.2.1"


def get_topology(vm_number: int, mode: str) -> VMTopology:
    if vm_number not in (1, 2):
        raise ValueError("vm_number must be 1 or 2")

    if mode not in ("tunnel", "transport"):
        raise ValueError("mode must be 'tunnel' or 'transport'")

    if vm_number == 1:
        local_underlay = VM1_UNDERLAY
        remote_underlay = VM2_UNDERLAY
        local_tunnel_ip = VM1_TUNNEL_IP
        remote_tunnel_ip = VM2_TUNNEL_IP
    else:
        local_underlay = VM2_UNDERLAY
        remote_underlay = VM1_UNDERLAY
        local_tunnel_ip = VM2_TUNNEL_IP
        remote_tunnel_ip = VM1_TUNNEL_IP

    if mode == "transport":
        return VMTopology(
            local_underlay=local_underlay,
            remote_underlay=remote_underlay,
            local_ts=f"{local_underlay}/32",
            remote_ts=f"{remote_underlay}/32",
            traffic_source=local_underlay,
            traffic_target=remote_underlay,
        )

    return VMTopology(
        local_underlay=local_underlay,
        remote_underlay=remote_underlay,
        local_ts=f"{local_tunnel_ip}/32",
        remote_ts=f"{remote_tunnel_ip}/32",
        traffic_source=local_tunnel_ip,
        traffic_target=remote_tunnel_ip,
    )


def get_tunnel_network(vm_number: int) -> str:
    if vm_number == 1:
        return "10.20.1.0/24"

    if vm_number == 2:
        return "10.20.2.0/24"

    raise ValueError("vm_number must be 1 or 2")