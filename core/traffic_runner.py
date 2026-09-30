import json
import shlex
from datetime import datetime, timezone
from pathlib import Path

from core.deployer import run_remote_command
from core.topology import get_topology
from core.traffic_profiles import get_profile


PROJECT_DIR = Path(__file__).resolve().parent.parent
RUNS_DIR = PROJECT_DIR / "runs"


def get_endpoints(mode, address_family, direction):
    """
    Select source/destination VM and IP based on:
    - IPsec mode
    - address family
    - traffic direction
    """

    if address_family == "ipv6":
        raise NotImplementedError(
            "IPv6 traffic generation is architecturally supported, "
            "but IPv6 lab endpoints will be added with the IPv6 Part 1A topology."
        )

    vm1_topology = get_topology(1, mode)
    vm2_topology = get_topology(2, mode)

    if direction == "vm1-to-vm2":
        return {
            "source_vm": 1,
            "destination_vm": 2,
            "source_ip": vm1_topology.traffic_source,
            "destination_ip": vm2_topology.traffic_source,
        }

    if direction == "vm2-to-vm1":
        return {
            "source_vm": 2,
            "destination_vm": 1,
            "source_ip": vm2_topology.traffic_source,
            "destination_ip": vm1_topology.traffic_source,
        }

    raise ValueError(f"Unsupported direction: {direction}")


def get_destination_vm(source_vm):
    if source_vm == 1:
        return 2
    if source_vm == 2:
        return 1
    raise ValueError("source_vm must be 1 or 2")


def verify_vpn_established():
    """
    Confirm that an IPsec IKE SA and CHILD_SA already exist.

    Part 1B does not establish the VPN.
    Part 1A must establish it first.
    """

    output = run_remote_command(
        1,
        "sudo -n swanctl --list-sas",
    )

    if "ESTABLISHED" not in output or "INSTALLED" not in output:
        raise RuntimeError(
            "No established IPsec VPN was detected. "
            "Run Part 1A first and establish the VPN."
        )

    print("Existing IPsec VPN detected.")


def run_icmp(source_vm, destination_ip, duration):
    """
    Generate ICMP traffic from the selected source VM.

    One ping is generated approximately every second.
    """

    count = max(1, int(duration))

    command = (
        f"ping "
        f"-c {count} "
        f"{shlex.quote(destination_ip)}"
    )

    return run_remote_command(source_vm, command)


def build_tcp_server_command(port, duration):
    """
    Create a bounded TCP server.

    The server:
    - listens on the requested port
    - accepts multiple connections
    - receives data
    - automatically exits after duration + 5 seconds

    This avoids the infinite nc listener that caused the
    previous WhatsApp implementation to hang.
    """

    python_code = f"""
import socket
import time

HOST = "0.0.0.0"
PORT = {port}
END_TIME = time.time() + {float(duration) + 5.0}

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.settimeout(1.0)
server.bind((HOST, PORT))
server.listen(20)

try:
    while time.time() < END_TIME:
        try:
            conn, addr = server.accept()
        except socket.timeout:
            continue

        conn.settimeout(1.0)

        try:
            while True:
                try:
                    data = conn.recv(65535)
                except socket.timeout:
                    continue

                if not data:
                    break
        except Exception:
            pass
        finally:
            conn.close()
finally:
    server.close()
"""

    command = (
        "nohup python3 -c "
        f"{shlex.quote(python_code)} "
        f"> /tmp/ipsec_tcp_{port}.log 2>&1 "
        f"< /dev/null &"
    )

    return command


def build_udp_server_command(port, duration):
    """
    Create a bounded UDP server.

    The server:
    - listens for UDP packets
    - receives packets until timeout
    - automatically exits

    No infinite foreground process remains attached to SSH.
    """

    python_code = f"""
import socket
import time

HOST = "0.0.0.0"
PORT = {port}
END_TIME = time.time() + {float(duration) + 5.0}

server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.settimeout(1.0)
server.bind((HOST, PORT))

try:
    while time.time() < END_TIME:
        try:
            server.recvfrom(65535)
        except socket.timeout:
            continue
        except Exception:
            break
finally:
    server.close()
"""

    command = (
        "nohup python3 -c "
        f"{shlex.quote(python_code)} "
        f"> /tmp/ipsec_udp_{port}.log 2>&1 "
        f"< /dev/null &"
    )

    return command


def start_tcp_listener(destination_vm, port, duration):
    command = build_tcp_server_command(
        port=port,
        duration=duration,
    )

    return run_remote_command(
        destination_vm,
        command,
    )


def start_udp_listener(destination_vm, port, duration):
    command = build_udp_server_command(
        port=port,
        duration=duration,
    )

    return run_remote_command(
        destination_vm,
        command,
    )


def run_tcp(
    source_vm,
    destination_ip,
    duration,
    packet_size,
    port=5001,
):
    """
    Generate controlled TCP traffic.

    A bounded server is started on the destination.
    The source creates a TCP connection, sends the payload,
    and closes the connection.
    """

    destination_vm = get_destination_vm(source_vm)

    start_tcp_listener(
        destination_vm=destination_vm,
        port=port,
        duration=duration,
    )

    payload = "T" * packet_size

    command = (
        f"printf '%s' {shlex.quote(payload)} | "
        f"nc -w 5 "
        f"{shlex.quote(destination_ip)} "
        f"{port}"
    )

    return run_remote_command(
        source_vm,
        command,
    )


def run_udp(
    source_vm,
    destination_ip,
    duration,
    packet_size,
    rate,
    port,
):
    """
    Generate bounded UDP traffic.

    A Python UDP receiver runs on the destination VM for a
    limited amount of time. The source VM sends a controlled
    number of UDP packets.

    This is synthetic application-like traffic.
    """

    destination_vm = get_destination_vm(source_vm)

    # ---------------------------------------------------------
    # UDP SERVER
    # ---------------------------------------------------------
    udp_server_code = f"""
import socket
import time

HOST = "0.0.0.0"
PORT = {port}
END_TIME = time.time() + {float(duration) + 10.0}

server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.settimeout(1.0)

server.bind((HOST, PORT))

received = 0
received_bytes = 0

try:
    while time.time() < END_TIME:
        try:
            data, addr = server.recvfrom(65535)
        except socket.timeout:
            continue
        except Exception:
            break

        received += 1
        received_bytes += len(data)

finally:
    server.close()

print(f"UDP packets received: {{received}}")
print(f"UDP bytes received: {{received_bytes}}")
"""

    udp_start_command = (
        "nohup python3 -c "
        f"{shlex.quote(udp_server_code)} "
        f"> /tmp/ipsec_udp_{port}.log 2>&1 "
        f"< /dev/null &"
    )

    print()
    print(
        f"Starting bounded UDP server on "
        f"VM{destination_vm} port {port}..."
    )

    run_remote_command(
        destination_vm,
        udp_start_command,
    )

    # Give the UDP socket time to bind.
    import time
    time.sleep(1)

    # ---------------------------------------------------------
    # UDP CLIENT
    # ---------------------------------------------------------
    packet_count = max(1, int(duration * rate))

    udp_client_code = f"""
import socket
import time

HOST = {destination_ip!r}
PORT = {port}
PACKET_COUNT = {packet_count}
INTERVAL = {1.0 / rate}
PAYLOAD = {("U" * packet_size)!r}

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

try:
    start = time.time()

    for i in range(PACKET_COUNT):
        sock.sendto(
            PAYLOAD.encode(),
            (HOST, PORT)
        )

        if i + 1 < PACKET_COUNT:
            time.sleep(INTERVAL)

finally:
    sock.close()

elapsed = time.time() - start

print(f"UDP packets sent: {{PACKET_COUNT}}")
print(f"UDP payload size: {{len(PAYLOAD)}} bytes")
print(f"Elapsed time: {{elapsed:.2f}} seconds")
"""

    udp_command = (
        "python3 -c "
        f"{shlex.quote(udp_client_code)}"
    )

    print()
    print(
        f"Sending {packet_count} UDP packets "
        f"at approximately {rate} packets/sec..."
    )

    output = run_remote_command(
        source_vm,
        udp_command,
    )

    return output
    """
    Generate controlled UDP traffic.

    Number of packets:

        duration × rate

    Each packet contains packet_size bytes.
    """

    destination_vm = get_destination_vm(source_vm)

    start_udp_listener(
        destination_vm=destination_vm,
        port=port,
        duration=duration,
    )

    packets_per_second = max(1, int(rate))
    packet_count = max(
        1,
        int(duration * packets_per_second),
    )

    payload = "U" * packet_size

    command = (
        f"for i in $(seq 1 {packet_count}); "
        f"do "
        f"printf '%s' {shlex.quote(payload)} | "
        f"nc -u -w 1 "
        f"{shlex.quote(destination_ip)} "
        f"{port}; "
        f"sleep {1 / packets_per_second}; "
        f"done"
    )

    return run_remote_command(
        source_vm,
        command,
    )


def run_web(source_vm, destination_ip, duration):
    """
    Generate HTTP request/response traffic.

    A temporary Python HTTP server runs on the destination.
    """

    destination_vm = get_destination_vm(source_vm)
    port = 8080

    python_code = f"""
import http.server
import socketserver

class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

with socketserver.TCPServer(("0.0.0.0", {port}), Handler) as server:
    server.timeout = {max(1, int(duration)) + 5}
    server.handle_request()
"""

    start_command = (
        "nohup python3 -c "
        f"{shlex.quote(python_code)} "
        f"> /tmp/ipsec_http_server.log 2>&1 "
        f"< /dev/null &"
    )

    run_remote_command(
        destination_vm,
        start_command,
    )

    command = (
        f"curl --max-time 10 "
        f"http://{shlex.quote(destination_ip)}:{port}/"
    )

    return run_remote_command(
        source_vm,
        command,
    )


def run_email(
    source_vm,
    destination_ip,
    duration,
):
    """
    E-mail-like controlled traffic.

    Generates a bounded SMTP-like TCP session.

    This is synthetic application-like traffic.
    It is NOT a real SMTP server or real e-mail service.
    """

    destination_vm = get_destination_vm(source_vm)

    tcp_port = 2525

    # ---------------------------------------------------------
    # TCP SERVER
    # ---------------------------------------------------------
    tcp_server_code = f"""
import socket
import time

HOST = "0.0.0.0"
PORT = {tcp_port}
END_TIME = time.time() + {float(duration) + 10.0}

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.settimeout(1.0)
server.bind((HOST, PORT))
server.listen(5)

try:
    while time.time() < END_TIME:
        try:
            conn, addr = server.accept()
        except socket.timeout:
            continue

        conn.settimeout(1.0)

        try:
            while time.time() < END_TIME:
                try:
                    data = conn.recv(65535)
                except socket.timeout:
                    continue

                if not data:
                    break

        except Exception:
            pass

        finally:
            conn.close()

        # One complete SMTP-like session is enough.
        break

finally:
    server.close()
"""

    tcp_start_command = (
        "nohup python3 -c "
        f"{shlex.quote(tcp_server_code)} "
        f"> /tmp/ipsec_email_tcp.log 2>&1 "
        f"< /dev/null &"
    )

    print()
    print(f"Starting SMTP-like TCP server on VM{destination_vm}...")
    
    run_remote_command(
        destination_vm,
        tcp_start_command,
    )

    # ---------------------------------------------------------
    # WAIT FOR SERVER TO BIND
    # ---------------------------------------------------------
    import time

    time.sleep(1)

    # ---------------------------------------------------------
    # SMTP-LIKE MESSAGE
    # ---------------------------------------------------------
    email_message = (
        "EHLO ipsec-test\\r\\n"
        "MAIL FROM:<test@ipsec.local>\\r\\n"
        "RCPT TO:<receiver@ipsec.local>\\r\\n"
        "DATA\\r\\n"
        "Subject: IPsec Test Message\\r\\n"
        "\\r\\n"
        "Controlled e-mail-like traffic\\r\\n"
        ".\\r\\n"
        "QUIT\\r\\n"
    )

    tcp_client_code = f"""
import socket

HOST = {destination_ip!r}
PORT = {tcp_port}
MESSAGE = {email_message!r}

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(5)

try:
    sock.connect((HOST, PORT))
    sock.sendall(MESSAGE.encode())
finally:
    sock.close()
"""

    tcp_command = (
        "python3 -c "
        f"{shlex.quote(tcp_client_code)}"
    )

    print()
    print("Sending SMTP-like e-mail traffic...")

    run_remote_command(
        source_vm,
        tcp_command,
    )

    return "E-mail-like controlled traffic completed successfully."


def run_voip(
    source_vm,
    destination_ip,
    duration,
    packet_size,
    rate,
):
    """
    VoIP-like traffic:
    continuous UDP traffic with configurable
    packet size and packet rate.
    """

    return run_udp(
        source_vm=source_vm,
        destination_ip=destination_ip,
        duration=duration,
        packet_size=packet_size,
        rate=rate,
        port=5002,
    )


def run_whatsapp(
    source_vm,
    destination_ip,
    duration,
    packet_size,
):
    """
    WhatsApp-like controlled traffic.

    Generates:
    - one persistent TCP messaging-like session
    - periodic UDP messaging/media-like packets

    This is synthetic application-like traffic.
    It is NOT literal WhatsApp traffic.
    """

    destination_vm = get_destination_vm(source_vm)

    tcp_port = 5003
    udp_port = 5004

    # ---------------------------------------------------------
    # TCP SERVER
    # ---------------------------------------------------------
    tcp_server_code = f"""
import socket
import time

HOST = "0.0.0.0"
PORT = {tcp_port}
END_TIME = time.time() + {float(duration) + 10.0}

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.settimeout(1.0)
server.bind((HOST, PORT))
server.listen(5)

try:
    while time.time() < END_TIME:
        try:
            conn, addr = server.accept()
        except socket.timeout:
            continue

        conn.settimeout(1.0)

        try:
            while time.time() < END_TIME:
                try:
                    data = conn.recv(65535)
                except socket.timeout:
                    continue

                if not data:
                    break
        except Exception:
            pass
        finally:
            conn.close()

        break
finally:
    server.close()
"""

    # ---------------------------------------------------------
    # UDP SERVER
    # ---------------------------------------------------------
    udp_server_code = f"""
import socket
import time

HOST = "0.0.0.0"
PORT = {udp_port}
END_TIME = time.time() + {float(duration) + 10.0}

server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.settimeout(1.0)
server.bind((HOST, PORT))

try:
    while time.time() < END_TIME:
        try:
            server.recvfrom(65535)
        except socket.timeout:
            continue
        except Exception:
            break
finally:
    server.close()
"""

    # Start TCP server.
    tcp_start_command = (
        "nohup python3 -c "
        f"{shlex.quote(tcp_server_code)} "
        f"> /tmp/ipsec_whatsapp_tcp.log 2>&1 "
        f"< /dev/null &"
    )

    run_remote_command(
        destination_vm,
        tcp_start_command,
    )

    # Start UDP server.
    udp_start_command = (
        "nohup python3 -c "
        f"{shlex.quote(udp_server_code)} "
        f"> /tmp/ipsec_whatsapp_udp.log 2>&1 "
        f"< /dev/null &"
    )

    run_remote_command(
        destination_vm,
        udp_start_command,
    )

    # Give the listeners a moment to bind.
    import time
    time.sleep(1)

    # ---------------------------------------------------------
    # ONE PERSISTENT TCP CONNECTION
    # ---------------------------------------------------------
    tcp_client_code = f"""
import socket
import time

HOST = {destination_ip!r}
PORT = {tcp_port}
DURATION = {int(duration)}
PAYLOAD = {("M" * packet_size)!r}

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(5)

sock.connect((HOST, PORT))

try:
    start = time.time()

    while time.time() - start < DURATION:
        sock.sendall(PAYLOAD.encode())
        time.sleep(1)
finally:
    sock.close()
"""

    tcp_command = (
        "python3 -c "
        f"{shlex.quote(tcp_client_code)}"
    )

    run_remote_command(
        source_vm,
        tcp_command,
    )

    # ---------------------------------------------------------
    # UDP BURSTS
    # ---------------------------------------------------------
    udp_client_code = f"""
import socket
import time

HOST = {destination_ip!r}
PORT = {udp_port}
DURATION = {int(duration)}
PAYLOAD = {("U" * packet_size)!r}

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

try:
    start = time.time()

    while time.time() - start < DURATION:
        sock.sendto(
            PAYLOAD.encode(),
            (HOST, PORT)
        )
        time.sleep(1)
finally:
    sock.close()
"""

    udp_command = (
        "python3 -c "
        f"{shlex.quote(udp_client_code)}"
    )

    run_remote_command(
        source_vm,
        udp_command,
    )

    return (
        "WhatsApp-like controlled traffic completed "
        "(persistent TCP session + UDP bursts)."
    )
    """
    WhatsApp-like traffic.

    Represents a controlled mixture of:
    - TCP messaging-like traffic
    - UDP messaging/media-like traffic

    This is NOT literal WhatsApp traffic.
    It is synthetic application-like traffic intended
    for dataset generation.
    """

    destination_vm = get_destination_vm(source_vm)

    tcp_port = 5003
    udp_port = 5004

    # Start bounded listeners on destination.
    start_tcp_listener(
        destination_vm=destination_vm,
        port=tcp_port,
        duration=duration,
    )

    start_udp_listener(
        destination_vm=destination_vm,
        port=udp_port,
        duration=duration,
    )

    iterations = max(1, int(duration))

    tcp_payload = "M" * packet_size
    udp_payload = "U" * packet_size

    for _ in range(iterations):

        # TCP messaging-like burst.
        tcp_command = (
            f"printf '%s' {shlex.quote(tcp_payload)} | "
            f"nc -w 5 "
            f"{shlex.quote(destination_ip)} "
            f"{tcp_port}"
        )

        run_remote_command(
            source_vm,
            tcp_command,
        )

        # UDP messaging/media-like burst.
        udp_command = (
            f"printf '%s' {shlex.quote(udp_payload)} | "
            f"nc -u -w 1 "
            f"{shlex.quote(destination_ip)} "
            f"{udp_port}"
        )

        run_remote_command(
            source_vm,
            udp_command,
        )

    return "WhatsApp-like controlled traffic completed."


def run_video(
    source_vm,
    destination_ip,
    duration,
    packet_size,
    rate,
):
    """
    Video-streaming-like traffic:
    high-rate continuous UDP traffic.
    """

    return run_udp(
        source_vm=source_vm,
        destination_ip=destination_ip,
        duration=duration,
        packet_size=packet_size,
        rate=rate,
        port=5005,
    )


def run_normal(
    source_vm,
    destination_ip,
    duration,
    packet_size,
):
    """
    Normal communication:
    controlled TCP + UDP traffic.
    """

    tcp_result = run_tcp(
        source_vm=source_vm,
        destination_ip=destination_ip,
        duration=duration,
        packet_size=packet_size,
        port=5006,
    )

    udp_result = run_udp(
        source_vm=source_vm,
        destination_ip=destination_ip,
        duration=duration,
        packet_size=packet_size,
        rate=2,
        port=5007,
    )

    return (
        "Normal communication completed.\n"
        f"TCP: {tcp_result}\n"
        f"UDP: {udp_result}"
    )


def run_profile(
    profile,
    mode,
    address_family,
    direction,
    duration,
    packet_size,
    rate,
):
    """
    Main Part 1B execution function.
    """

    verify_vpn_established()

    endpoints = get_endpoints(
        mode=mode,
        address_family=address_family,
        direction=direction,
    )

    source_vm = endpoints["source_vm"]
    destination_vm = endpoints["destination_vm"]
    source_ip = endpoints["source_ip"]
    destination_ip = endpoints["destination_ip"]

    profile_data = get_profile(profile)

    print()
    print("=" * 60)
    print("TRAFFIC GENERATION")
    print("=" * 60)

    print(f"Profile       : {profile}")
    print(f"Description   : {profile_data['description']}")
    print(f"Mode          : {mode}")
    print(f"Address family: {address_family}")
    print(f"Direction     : {direction}")
    print(f"Source VM     : VM{source_vm}")
    print(f"Source IP     : {source_ip}")
    print(f"Destination VM: VM{destination_vm}")
    print(f"Destination   : {destination_ip}")
    print(f"Duration      : {duration}s")
    print(f"Packet size   : {packet_size} bytes")
    print(f"Rate          : {rate}")
    print()

    start_time = datetime.now(timezone.utc)

    if profile == "icmp":
        output = run_icmp(
            source_vm=source_vm,
            destination_ip=destination_ip,
            duration=duration,
        )

    elif profile == "web":
        output = run_web(
            source_vm=source_vm,
            destination_ip=destination_ip,
            duration=duration,
        )

    elif profile == "email":
        output = run_email(
            source_vm=source_vm,
            destination_ip=destination_ip,
            duration=duration,
        )

    elif profile == "voip":
        output = run_voip(
            source_vm=source_vm,
            destination_ip=destination_ip,
            duration=duration,
            packet_size=packet_size,
            rate=rate,
        )

    elif profile == "whatsapp":
        output = run_whatsapp(
            source_vm=source_vm,
            destination_ip=destination_ip,
            duration=duration,
            packet_size=packet_size,
        )

    elif profile == "video":
        output = run_video(
            source_vm=source_vm,
            destination_ip=destination_ip,
            duration=duration,
            packet_size=packet_size,
            rate=rate,
        )

    elif profile == "normal":
        output = run_normal(
            source_vm=source_vm,
            destination_ip=destination_ip,
            duration=duration,
            packet_size=packet_size,
        )

    else:
        raise ValueError(
            f"Unsupported profile: {profile}"
        )

    end_time = datetime.now(timezone.utc)

    run_id = start_time.strftime(
        "RUN-%Y%m%d-%H%M%S"
    )

    metadata = {
        "run_id": run_id,
        "profile": profile,
        "mode": mode,
        "address_family": address_family,
        "direction": direction,
        "source_vm": source_vm,
        "destination_vm": destination_vm,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "duration_seconds": duration,
        "packet_size_bytes": packet_size,
        "rate": rate,
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat(),
    }

    run_directory = RUNS_DIR / run_id
    run_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    metadata_file = (
        run_directory / "metadata.json"
    )

    metadata_file.write_text(
        json.dumps(
            metadata,
            indent=4,
        ),
        encoding="utf-8",
    )

    print()
    print("=" * 60)
    print("TRAFFIC GENERATION COMPLETE")
    print("=" * 60)
    print(f"Run ID       : {run_id}")
    print(f"Metadata     : {metadata_file}")

    return metadata