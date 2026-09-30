from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from core.topology import get_topology


PROJECT_DIR = Path(__file__).resolve().parent.parent
TEMPLATE_DIR = PROJECT_DIR / "templates"
GENERATED_DIR = PROJECT_DIR / "generated"


def dh_to_strongswan(dh):
    if dh == 14:
        return "modp2048"

    if dh == 19:
        return "ecp256"

    raise ValueError(f"Unsupported DH group: {dh}")


def build_ike_proposal(dh):
    return f"aes256-sha256-{dh_to_strongswan(dh)}"


def build_esp_proposal(cipher, integrity, dh, pfs):
    if cipher == "aes128-cbc":
        proposal = "aes128-sha256"

    elif cipher == "aes256-cbc":
        proposal = "aes256-sha256"

    elif cipher == "aes128-gcm":
        proposal = "aes128gcm16"

    elif cipher == "aes256-gcm":
        proposal = "aes256gcm16"

    else:
        raise ValueError(f"Unsupported cipher: {cipher}")

    if pfs == "on":
        proposal += f"-{dh_to_strongswan(dh)}"

    return proposal


def build_config(test_id, mode, cipher, integrity, dh, pfs):
    if mode not in ("tunnel", "transport"):
        raise ValueError(f"Unsupported mode: {mode}")

    if cipher.endswith("-gcm"):
        integrity = None

    topology_vm1 = get_topology(1, mode)
    topology_vm2 = get_topology(2, mode)

    return {
        "test_id": test_id,
        "mode": mode,
        "cipher": cipher,
        "integrity": integrity,
        "dh": dh,
        "pfs": pfs,

        # IKE
        "ike_proposal": build_ike_proposal(dh),

        # ESP
        "esp_proposal": build_esp_proposal(
            cipher=cipher,
            integrity=integrity,
            dh=dh,
            pfs=pfs,
        ),

        # VM1 topology
        "vm1_local_addr": topology_vm1.local_underlay,
        "vm1_remote_addr": topology_vm1.remote_underlay,
        "vm1_local_ts": topology_vm1.local_ts,
        "vm1_remote_ts": topology_vm1.remote_ts,
        "vm1_traffic_source": topology_vm1.traffic_source,
        "vm1_traffic_target": topology_vm1.traffic_target,

        # VM2 topology
        "vm2_local_addr": topology_vm2.local_underlay,
        "vm2_remote_addr": topology_vm2.remote_underlay,
        "vm2_local_ts": topology_vm2.local_ts,
        "vm2_remote_ts": topology_vm2.remote_ts,
        "vm2_traffic_source": topology_vm2.traffic_source,
        "vm2_traffic_target": topology_vm2.traffic_target,
    }


def get_template_environment():
    return Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render_vm_config(vm_number, config):
    environment = get_template_environment()

    if vm_number == 1:
        template_name = "vm1_swanctl.conf.j2"

        template_values = {
            **config,

            "local_addr": config["vm1_local_addr"],
            "remote_addr": config["vm1_remote_addr"],

            "local_id": "vm1",
            "remote_id": "vm2",

            "local_ts": config["vm1_local_ts"],
            "remote_ts": config["vm1_remote_ts"],

            "traffic_source": config["vm1_traffic_source"],
            "traffic_target": config["vm1_traffic_target"],

            "psk": "IPsecLab-Shared-Key",
        }

    elif vm_number == 2:
        template_name = "vm2_swanctl.conf.j2"

        template_values = {
            **config,

            "local_addr": config["vm2_local_addr"],
            "remote_addr": config["vm2_remote_addr"],

            "local_id": "vm2",
            "remote_id": "vm1",

            "local_ts": config["vm2_local_ts"],
            "remote_ts": config["vm2_remote_ts"],

            "traffic_source": config["vm2_traffic_source"],
            "traffic_target": config["vm2_traffic_target"],

            "psk": "IPsecLab-Shared-Key",
        }

    else:
        raise ValueError("vm_number must be 1 or 2")

    template = environment.get_template(template_name)

    return template.render(**template_values)


def write_vm_config(vm_number, config):
    config_text = render_vm_config(
        vm_number=vm_number,
        config=config,
    )

    vm_directory = GENERATED_DIR / f"vm{vm_number}"
    vm_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_file = vm_directory / "swanctl.conf"

    output_file.write_text(
        config_text,
        encoding="utf-8",
    )

    return output_file