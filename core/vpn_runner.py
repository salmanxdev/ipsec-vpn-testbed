import time

from dataclasses import dataclass


from core.deployer import (
    deploy_vm_config,
    ensure_strongswan_running,
    terminate_child_sa,
    load_swanctl_config,
    initiate_ike_sa,
    initiate_child_sa,
    get_sa_status,
    get_xfrm_state,
    run_remote_command,
)


from core.topology import (
    VM1_UNDERLAY,
    VM2_UNDERLAY,
    VM1_TUNNEL_IP,
    VM2_TUNNEL_IP,
)


from core.capture import (
    create_capture_directory,
    start_capture,
    stop_capture,
    download_capture,
    cleanup_remote_capture,
    write_metadata,
    write_summary,
)


@dataclass
class VPNSessionResult:
    """
    Artifacts and operational information produced
    by a VPN capture session.
    """

    sa_status: str
    xfrm_state: str
    pcap_path: str
    metadata_path: str
    summary_path: str


# ============================================================
# ENVIRONMENT PREPARATION
# ============================================================

def prepare_vms():

    print()
    print("=" * 60)
    print("PREPARING VPN ENVIRONMENT")
    print("=" * 60)

    ensure_strongswan_running(1)
    ensure_strongswan_running(2)


# ============================================================
# TUNNEL TOPOLOGY
# ============================================================

def prepare_tunnel_endpoints(mode):
    """
    Prepare virtual inner addresses for tunnel mode.

    Transport mode uses the underlay addresses directly.
    """

    if mode != "tunnel":
        return

    print()
    print("=" * 60)
    print("PREPARING TUNNEL ENDPOINTS")
    print("=" * 60)

    run_remote_command(
        1,
        (
            f"sudo -n ip addr replace "
            f"{VM1_TUNNEL_IP}/32 dev lo"
        ),
    )

    run_remote_command(
        2,
        (
            f"sudo -n ip addr replace "
            f"{VM2_TUNNEL_IP}/32 dev lo"
        ),
    )

    run_remote_command(
        1,
        (
            f"sudo -n ip route replace "
            f"{VM2_TUNNEL_IP}/32 "
            f"via {VM2_UNDERLAY} "
            f"dev eth1 "
            f"src {VM1_TUNNEL_IP}"
        ),
    )

    run_remote_command(
        2,
        (
            f"sudo -n ip route replace "
            f"{VM1_TUNNEL_IP}/32 "
            f"via {VM1_UNDERLAY} "
            f"dev eth1 "
            f"src {VM2_TUNNEL_IP}"
        ),
    )

    print()
    print(
        "Tunnel endpoints prepared successfully."
    )


# ============================================================
# CONFIGURATION DEPLOYMENT
# ============================================================

def deploy_configs(
    vm1_file,
    vm2_file,
):

    print()
    print("=" * 60)
    print("DEPLOYING VPN CONFIGURATION")
    print("=" * 60)

    deploy_vm_config(
        1,
        vm1_file,
    )

    deploy_vm_config(
        2,
        vm2_file,
    )


# ============================================================
# REMOVE PREVIOUS CONNECTION
# ============================================================

def clear_previous_vpn():

    print()
    print("=" * 60)
    print("CLEARING PREVIOUS VPN CONNECTION")
    print("=" * 60)

    terminate_child_sa(1)
    terminate_child_sa(2)


# ============================================================
# LOAD STRONGSWAN
# ============================================================

def load_configs():

    print()
    print("=" * 60)
    print("LOADING STRONGSWAN CONFIGURATION")
    print("=" * 60)

    load_swanctl_config(1)
    load_swanctl_config(2)


# ============================================================
# ESTABLISH VPN
# ============================================================

def establish_vpn():
    """
    Establish IKE SA and CHILD SA.

    Packet capture must already be active.
    """

    print()
    print("=" * 60)
    print("ESTABLISHING IKE SECURITY ASSOCIATION")
    print("=" * 60)

    initiate_ike_sa(1)

    print()
    print("=" * 60)
    print("ESTABLISHING IPSEC CHILD SA")
    print("=" * 60)

    initiate_child_sa(1)

    print()
    print("=" * 60)
    print("VPN CONNECTION ESTABLISHED")
    print("=" * 60)


# ============================================================
# CONNECTION STATE
# ============================================================

def collect_connection_state():
    """
    Collect operational strongSwan and Linux XFRM state.

    This is not a PASS/FAIL verification system.
    """

    print()
    print("=" * 60)
    print("VPN CONNECTION STATE")
    print("=" * 60)

    print()
    print(
        "--- strongSwan Security Associations ---"
    )

    sa_status = get_sa_status(1)

    print()
    print(
        "--- Linux XFRM State ---"
    )

    xfrm_state = get_xfrm_state(1)

    return (
        sa_status,
        xfrm_state,
    )


# ============================================================
# MANUAL TRAFFIC INSTRUCTIONS
# ============================================================

def print_traffic_instructions(mode):

    print()
    print("=" * 70)
    print("VPN ACTIVE - PACKET CAPTURE ACTIVE")
    print("=" * 70)

    print()
    print(
        "The VPN is established and tcpdump is "
        "currently recording packets."
    )

    print()
    print(
        "Open ANOTHER PowerShell terminal in this "
        "project directory."
    )

    print()
    print(
        "Generate whichever traffic profiles you want."
    )

    print()
    print("Available examples:")
    print()

    profiles = [
        "icmp",
        "web",
        "email",
        "voip",
        "whatsapp",
        "video",
        "normal",
    ]

    for profile in profiles:

        print(
            f"python traffic.py "
            f"--profile {profile} "
            f"--mode {mode}"
        )

    print()
    print(
        "You may run one profile, multiple profiles, "
        "or repeat profiles."
    )

    print()
    print(
        "The packet capture remains active while "
        "traffic.py runs."
    )

    print()
    print(
        "Return to THIS terminal and press Ctrl+C "
        "when traffic generation is complete."
    )

    print()
    print("=" * 70)


# ============================================================
# WAIT FOR USER
# ============================================================

def wait_for_capture_stop():

    print()
    print(
        "Capture session is running..."
    )

    print(
        "Press Ctrl+C when traffic generation "
        "is complete."
    )

    try:

        while True:
            time.sleep(1)

    except KeyboardInterrupt:

        print()
        print()
        print(
            "Capture stop requested."
        )


# ============================================================
# MAIN SESSION
# ============================================================

def run_vpn_session(
    vm1_file,
    vm2_file,
    mode,
    cipher=None,
    integrity=None,
    dh=None,
    pfs=None,
):
    """
    Integrated VPN + packet capture workflow.

    No automatic traffic profile is generated.

    No PASS/FAIL result is produced.
    """

    print()
    print("=" * 70)
    print("IPSEC VPN CAPTURE SESSION")
    print("=" * 70)

    print()
    print(
        f"Mode       : {mode}"
    )

    if cipher is not None:
        print(
            f"Cipher     : {cipher}"
        )

    if integrity is not None:
        print(
            f"Integrity  : {integrity}"
        )
    else:
        print(
            "Integrity  : AEAD / built into cipher"
        )

    if dh is not None:
        print(
            f"DH Group   : {dh}"
        )

    if pfs is not None:
        print(
            f"PFS        : {pfs}"
        )

    capture_directory = None

    capture_started = False

    pcap_path = ""
    metadata_path = ""
    summary_path = ""

    sa_status = ""
    xfrm_state = ""

    try:

        # ====================================================
        # PREPARE ENVIRONMENT
        # ====================================================

        prepare_vms()

        prepare_tunnel_endpoints(
            mode
        )

        deploy_configs(
            vm1_file,
            vm2_file,
        )

        clear_previous_vpn()

        load_configs()

        # ====================================================
        # CREATE SESSION DIRECTORY
        # ====================================================

        capture_directory = (
            create_capture_directory()
        )

        print()
        print("=" * 60)
        print("CAPTURE SESSION")
        print("=" * 60)

        print()
        print(
            f"Session directory: "
            f"{capture_directory}"
        )

        # ====================================================
        # WRITE CONFIGURATION METADATA
        #
        # Do this before the capture so the intended VPN
        # configuration is recorded independently of later
        # operational state.
        # ====================================================

        metadata_path = str(
            write_metadata(
                local_directory=capture_directory,
                mode=mode,
                cipher=cipher,
                integrity=integrity,
                dh=dh,
                pfs=pfs,
                address_family="ipv4",
                capture_vm=1,
            )
        )

        # ====================================================
        # START CAPTURE BEFORE IKE
        # ====================================================

        start_capture(
            vm_number=1
        )

        capture_started = True

        # ====================================================
        # ESTABLISH VPN
        #
        # Capture is already running here.
        #
        # Therefore IKE_SA_INIT / IKE_AUTH / CHILD SA
        # negotiation can appear in capture.pcap.
        # ====================================================

        establish_vpn()

        # ====================================================
        # COLLECT INITIAL CONNECTION STATE
        # ====================================================

        (
            sa_status,
            xfrm_state,
        ) = collect_connection_state()

        # ====================================================
        # MANUAL TRAFFIC GENERATION
        # ====================================================

        print_traffic_instructions(
            mode
        )

        wait_for_capture_stop()

        # ====================================================
        # STOP CAPTURE
        # ====================================================

        stop_capture(
            vm_number=1
        )

        capture_started = False

        # ====================================================
        # DOWNLOAD PCAP
        # ====================================================

        pcap_path = str(
            download_capture(
                vm_number=1,
                local_directory=(
                    capture_directory
                ),
            )
        )

        # ====================================================
        # COLLECT FINAL CONNECTION STATE
        # ====================================================

        try:

            (
                sa_status,
                xfrm_state,
            ) = collect_connection_state()

        except Exception as state_error:

            print()
            print(
                "WARNING: Final VPN state could not "
                "be collected."
            )

            print(
                state_error
            )

        # ====================================================
        # WRITE SUMMARY
        # ====================================================

        summary_path = str(
            write_summary(
                local_directory=(
                    capture_directory
                ),
                sa_status=sa_status,
                xfrm_state=xfrm_state,
                pcap_path=pcap_path,
            )
        )

        # ====================================================
        # CLEAN REMOTE CAPTURE FILES
        # ====================================================

        cleanup_remote_capture(
            vm_number=1
        )

        # ====================================================
        # COMPLETE
        # ====================================================

        print()
        print("=" * 70)
        print("VPN CAPTURE SESSION COMPLETE")
        print("=" * 70)

        print()
        print(
            "Session artifacts:"
        )

        print()
        print(
            f"  PCAP     : {pcap_path}"
        )

        print(
            f"  Metadata : {metadata_path}"
        )

        print(
            f"  Summary  : {summary_path}"
        )

        print()
        print(
            "The capture session is ready for the "
            "protocol analysis and AI pipeline."
        )

        return VPNSessionResult(
            sa_status=sa_status,
            xfrm_state=xfrm_state,
            pcap_path=pcap_path,
            metadata_path=metadata_path,
            summary_path=summary_path,
        )

    # ========================================================
    # OUTER CTRL+C PROTECTION
    # ========================================================

    except KeyboardInterrupt:

        print()
        print(
            "Session interrupted."
        )

        if capture_started:

            try:

                stop_capture(
                    vm_number=1
                )

                capture_started = False

                if capture_directory:

                    pcap_path = str(
                        download_capture(
                            vm_number=1,
                            local_directory=(
                                capture_directory
                            ),
                        )
                    )

                    summary_path = str(
                        write_summary(
                            local_directory=(
                                capture_directory
                            ),
                            sa_status=sa_status,
                            xfrm_state=xfrm_state,
                            pcap_path=pcap_path,
                        )
                    )

                    print()
                    print(
                        "Partial capture preserved:"
                    )

                    print(
                        f"  {pcap_path}"
                    )

            finally:

                try:

                    cleanup_remote_capture(
                        vm_number=1
                    )

                except Exception:
                    pass

        return VPNSessionResult(
            sa_status=sa_status,
            xfrm_state=xfrm_state,
            pcap_path=pcap_path,
            metadata_path=metadata_path,
            summary_path=summary_path,
        )

    # ========================================================
    # ERROR PROTECTION
    # ========================================================

    except Exception:

        if capture_started:

            print()
            print(
                "An error occurred while packet "
                "capture was active."
            )

            print(
                "Attempting to preserve the "
                "partial PCAP..."
            )

            try:

                stop_capture(
                    vm_number=1
                )

                capture_started = False

                if capture_directory:

                    try:

                        pcap_path = str(
                            download_capture(
                                vm_number=1,
                                local_directory=(
                                    capture_directory
                                ),
                            )
                        )

                        summary_path = str(
                            write_summary(
                                local_directory=(
                                    capture_directory
                                ),
                                sa_status=sa_status,
                                xfrm_state=xfrm_state,
                                pcap_path=pcap_path,
                            )
                        )

                        print()
                        print(
                            "Partial packet capture preserved:"
                        )

                        print(
                            f"  {pcap_path}"
                        )

                    except Exception as capture_error:

                        print()
                        print(
                            "WARNING: Partial PCAP could "
                            "not be downloaded."
                        )

                        print(
                            capture_error
                        )

                try:

                    cleanup_remote_capture(
                        vm_number=1
                    )

                except Exception:
                    pass

            except Exception as stop_error:

                print()
                print(
                    "WARNING: Packet capture could not "
                    "be stopped cleanly."
                )

                print(
                    stop_error
                )

        raise