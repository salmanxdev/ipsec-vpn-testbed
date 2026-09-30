import json
import subprocess
from datetime import datetime
from pathlib import Path

from core.deployer import (
    get_vm_host,
    SSH_USER,
    run_remote_command,
)


CAPTURE_INTERFACE = "eth1"

REMOTE_PCAP = "/tmp/ipsec_phase1b_capture.pcap"
REMOTE_PID = "/tmp/ipsec_phase1b_capture.pid"
REMOTE_LOG = "/tmp/ipsec_phase1b_capture.log"


# ============================================================
# SESSION DIRECTORY
# ============================================================

def create_capture_directory():
    """
    Create a directory for one VPN capture session.

    Example:

        runs/
        └── SESSION-20260929-225500/
            ├── capture.pcap
            ├── metadata.json
            └── summary.json
    """

    timestamp = datetime.now().strftime(
        "%Y%m%d-%H%M%S"
    )

    session_directory = (
        Path("runs")
        / f"SESSION-{timestamp}"
    )

    session_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    return session_directory


# ============================================================
# START CAPTURE
# ============================================================

def start_capture(vm_number=1):
    """
    Start tcpdump on the IPsec underlay interface.

    This must run BEFORE IKE initiation so the PCAP can
    contain the complete VPN establishment sequence:

        IKE_SA_INIT
        IKE_AUTH
        CREATE_CHILD_SA
        ESP
        AH
        normal communication

    No capture filter is intentionally applied.
    """

    print()
    print("=" * 60)
    print("STARTING PACKET CAPTURE")
    print("=" * 60)

    # Remove stale capture state from an earlier session.

    cleanup_command = (
        f"sudo -n rm -f "
        f"{REMOTE_PCAP} "
        f"{REMOTE_PID} "
        f"{REMOTE_LOG}"
    )

    run_remote_command(
        vm_number,
        cleanup_command,
    )

    # --------------------------------------------------------
    # Start tcpdump
    #
    # -i eth1 -> IPsec underlay
    # -s 0    -> full packet capture
    # -U      -> packet-buffered PCAP writing
    # -n      -> don't perform DNS resolution
    #
    # No BPF filter is applied because we want the dataset
    # to retain all relevant protocols.
    # --------------------------------------------------------

    tcpdump_command = (
        "sudo -n sh -c "
        "'nohup tcpdump "
        f"-i {CAPTURE_INTERFACE} "
        "-n "
        "-s 0 "
        "-U "
        f"-w {REMOTE_PCAP} "
        f"> {REMOTE_LOG} 2>&1 "
        "< /dev/null & "
        "echo $! "
        f"> {REMOTE_PID}'"
    )

    run_remote_command(
        vm_number,
        tcpdump_command,
    )

    # Give tcpdump time to attach to the interface.

    import time

    time.sleep(1)

    # Verify process exists.

    check_command = (
        "sudo -n sh -c "
        f"'test -s {REMOTE_PID} && "
        f"kill -0 $(cat {REMOTE_PID})'"
    )

    run_remote_command(
        vm_number,
        check_command,
    )

    print()
    print(
        f"Packet capture active on VM{vm_number}."
    )

    print(
        f"Interface: {CAPTURE_INTERFACE}"
    )

    print()
    print(
        "Capture started before VPN establishment."
    )

    print(
        "IKE, ESP, AH and other network traffic "
        "will be recorded."
    )


# ============================================================
# STOP CAPTURE
# ============================================================

def stop_capture(vm_number=1):
    """
    Stop tcpdump cleanly using SIGINT.

    SIGINT allows tcpdump to flush and finalize the PCAP
    before the file is downloaded.
    """

    print()
    print("=" * 60)
    print("STOPPING PACKET CAPTURE")
    print("=" * 60)

    stop_command = (
        "sudo -n sh -c "
        f"'if test -f {REMOTE_PID}; then "
        f"kill -INT $(cat {REMOTE_PID}) "
        "2>/dev/null || true; "
        "sleep 2; "
        f"rm -f {REMOTE_PID}; "
        "fi'"
    )

    run_remote_command(
        vm_number,
        stop_command,
    )

    # Verify that tcpdump produced data.

    verify_command = (
        "sudo -n sh -c "
        f"'test -s {REMOTE_PCAP}'"
    )

    run_remote_command(
        vm_number,
        verify_command,
    )

    print()
    print(
        "Packet capture finalized successfully."
    )


# ============================================================
# DOWNLOAD PCAP
# ============================================================

def download_capture(
    vm_number,
    local_directory,
):
    """
    Download the completed PCAP from the capture VM.
    """

    local_directory = Path(
        local_directory
    )

    local_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    local_pcap = (
        local_directory
        / "capture.pcap"
    )

    vm_host = get_vm_host(
        vm_number
    )

    command = [
        "scp",
        (
            f"{SSH_USER}@{vm_host}:"
            f"{REMOTE_PCAP}"
        ),
        str(local_pcap),
    ]

    print()
    print("=" * 60)
    print("DOWNLOADING PACKET CAPTURE")
    print("=" * 60)

    print()
    print(
        f"Remote : VM{vm_number}:{REMOTE_PCAP}"
    )

    print(
        f"Local  : {local_pcap}"
    )

    result = subprocess.run(
        command,
        text=True,
        capture_output=True,
    )

    if result.stdout:
        print(
            result.stdout
        )

    if result.stderr:
        print(
            result.stderr
        )

    if result.returncode != 0:
        raise RuntimeError(
            "Failed to download packet capture "
            f"(exit code {result.returncode})."
        )

    if not local_pcap.exists():
        raise RuntimeError(
            "PCAP download reported success but "
            "capture.pcap does not exist locally."
        )

    if local_pcap.stat().st_size == 0:
        raise RuntimeError(
            "Downloaded capture.pcap is empty."
        )

    print()
    print(
        "Packet capture downloaded successfully."
    )

    print(
        f"Size: {local_pcap.stat().st_size} bytes"
    )

    return local_pcap


# ============================================================
# METADATA.JSON
# ============================================================

def write_metadata(
    local_directory,
    mode,
    cipher,
    integrity,
    dh,
    pfs,
    address_family="ipv4",
    capture_vm=1,
):
    """
    Write ground-truth configuration metadata describing
    how this VPN capture session was created.

    This file can later be used for:

        dataset labeling
        analyzer validation
        ML training/testing
        reproducibility
    """

    local_directory = Path(
        local_directory
    )

    session_id = (
        local_directory.name
    )

    metadata = {
        "session_id": session_id,

        "vpn": {
            "mode": mode,
            "cipher": cipher,
            "integrity": (
                integrity
                if integrity is not None
                else "AEAD"
            ),
            "dh_group": dh,
            "pfs": pfs,
            "address_family": address_family,
        },

        "capture": {
            "capture_vm": f"VM{capture_vm}",
            "interface": CAPTURE_INTERFACE,
            "pcap_file": "capture.pcap",
            "capture_scope": "full-interface",
            "started_before_ike": True,
        },

        "traffic": {
            "generation": "manual",
        },

        "created_at": (
            datetime.now().astimezone().isoformat()
        ),
    }

    metadata_path = (
        local_directory
        / "metadata.json"
    )

    with open(
        metadata_path,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            metadata,
            file,
            indent=4,
        )

    print()
    print(
        f"Metadata saved: {metadata_path}"
    )

    return metadata_path


# ============================================================
# SUMMARY.JSON
# ============================================================

def write_summary(
    local_directory,
    sa_status,
    xfrm_state,
    pcap_path,
):
    """
    Write an operational summary of the completed session.

    This is NOT a PASS/FAIL report.

    It records observed VPN/capture state for later
    processing.
    """

    local_directory = Path(
        local_directory
    )

    pcap = Path(
        pcap_path
    )

    # --------------------------------------------------------
    # Extract simple operational facts.
    # --------------------------------------------------------

    ike_established = (
        "ESTABLISHED"
        in sa_status
    )

    child_installed = (
        "INSTALLED"
        in sa_status
    )

    ikev2_detected = (
        "IKEv2"
        in sa_status
    )

    esp_state_present = (
        "proto esp"
        in xfrm_state.lower()
    )

    ah_state_present = (
        "proto ah"
        in xfrm_state.lower()
    )

    # AH being false does NOT mean failure.
    # It simply means AH was not present in this session.

    summary = {
        "session_id": (
            local_directory.name
        ),

        "vpn_state": {
            "ike_established": ike_established,
            "ike_version": (
                "IKEv2"
                if ikev2_detected
                else None
            ),
            "child_sa_installed": child_installed,
        },

        "kernel_state": {
            "esp_state_present": (
                esp_state_present
            ),
            "ah_state_present": (
                ah_state_present
            ),
        },

        "capture": {
            "completed": (
                pcap.exists()
                and pcap.stat().st_size > 0
            ),
            "file": "capture.pcap",
            "size_bytes": (
                pcap.stat().st_size
                if pcap.exists()
                else 0
            ),
        },

        "traffic": {
            "generation": "manual",
        },

        "completed_at": (
            datetime.now().astimezone().isoformat()
        ),
    }

    summary_path = (
        local_directory
        / "summary.json"
    )

    with open(
        summary_path,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            summary,
            file,
            indent=4,
        )

    print()
    print(
        f"Session summary saved: {summary_path}"
    )

    return summary_path


# ============================================================
# REMOTE CLEANUP
# ============================================================

def cleanup_remote_capture(
    vm_number=1,
):
    """
    Remove temporary packet-capture files from the VM
    after the local artifacts have been preserved.
    """

    cleanup_command = (
        f"sudo -n rm -f "
        f"{REMOTE_PCAP} "
        f"{REMOTE_PID} "
        f"{REMOTE_LOG}"
    )

    run_remote_command(
        vm_number,
        cleanup_command,
    )