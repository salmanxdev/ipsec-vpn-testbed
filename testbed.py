import argparse

from core.validator import (
    validate_parameters,
    find_test_id,
)

from core.config_generator import (
    build_config,
    write_vm_config,
)

from core.vpn_runner import run_vpn_session


def main():

    parser = argparse.ArgumentParser(
        description=(
            "IPsec VPN Configuration, Connection "
            "and Traffic Capture System"
        )
    )

    # =========================================================
    # VPN CONFIGURATION ARGUMENTS
    # =========================================================

    parser.add_argument(
        "--mode",
        required=True,
        choices=[
            "tunnel",
            "transport",
        ],
        help="IPsec operating mode",
    )

    parser.add_argument(
        "--cipher",
        required=True,
        choices=[
            "aes128-cbc",
            "aes256-cbc",
            "aes128-gcm",
            "aes256-gcm",
        ],
        help="ESP encryption algorithm",
    )

    parser.add_argument(
        "--integrity",
        choices=[
            "hmac-sha256",
        ],
        help=(
            "ESP integrity algorithm. "
            "Not required when AES-GCM is used."
        ),
    )

    parser.add_argument(
        "--dh",
        required=True,
        type=int,
        choices=[
            14,
            19,
        ],
        help="Diffie-Hellman group",
    )

    parser.add_argument(
        "--pfs",
        required=True,
        choices=[
            "on",
            "off",
        ],
        help="Perfect Forward Secrecy",
    )

    args = parser.parse_args()

    # =========================================================
    # NORMALIZE CRYPTOGRAPHIC PARAMETERS
    # =========================================================

    integrity = args.integrity

    # AES-GCM is AEAD.
    # Authentication is integrated into the cipher,
    # therefore a separate HMAC is not required.

    if args.cipher.endswith("-gcm"):
        integrity = None

    # =========================================================
    # VALIDATE CONFIGURATION
    # =========================================================

    try:

        validate_parameters(
            args.mode,
            args.cipher,
            integrity,
            args.dh,
            args.pfs,
        )

    except ValueError as error:

        parser.error(
            str(error)
        )

    # =========================================================
    # FIND CONFIGURATION MATRIX ENTRY
    #
    # find_test_id() is retained because the existing
    # validator/config generator currently uses this internal
    # identifier.
    #
    # It is NOT presented as a "test" to the user.
    # =========================================================

    configuration_id = find_test_id(
        args.mode,
        args.cipher,
        integrity,
        args.dh,
        args.pfs,
    )

    if configuration_id is None:

        parser.error(
            "No matching VPN configuration was found."
        )

    # =========================================================
    # BUILD STRONGSWAN CONFIGURATION
    # =========================================================

    config = build_config(
        test_id=configuration_id,
        mode=args.mode,
        cipher=args.cipher,
        integrity=integrity,
        dh=args.dh,
        pfs=args.pfs,
    )

    # =========================================================
    # WRITE VM CONFIGURATION FILES
    # =========================================================

    vm1_file = write_vm_config(
        vm_number=1,
        config=config,
    )

    vm2_file = write_vm_config(
        vm_number=2,
        config=config,
    )

    # =========================================================
    # DISPLAY VPN CONFIGURATION
    # =========================================================

    print()
    print("=" * 70)
    print("IPSEC VPN CONFIGURATION")
    print("=" * 70)

    print(
        f"Configuration ID : {configuration_id}"
    )

    print(
        f"Mode             : {args.mode}"
    )

    print(
        f"Cipher           : {args.cipher}"
    )

    print(
        f"Integrity        : "
        f"{integrity or 'AEAD / built into GCM'}"
    )

    print(
        f"DH Group         : {args.dh}"
    )

    print(
        f"PFS              : {args.pfs}"
    )

    print()
    print(
        "Generated strongSwan configuration:"
    )

    print(
        f"VM1              : {vm1_file}"
    )

    print(
        f"VM2              : {vm2_file}"
    )

    # =========================================================
    # START VPN + CAPTURE SESSION
    #
    # IMPORTANT:
    #
    # run_vpn_session() currently accepts:
    #
    # vm1_file
    # vm2_file
    # mode
    # cipher
    # integrity
    # dh
    # pfs
    #
    # Configuration ID is intentionally NOT passed because
    # vpn_runner does not require it.
    # =========================================================

    session = run_vpn_session(
        vm1_file=vm1_file,
        vm2_file=vm2_file,
        mode=args.mode,
        cipher=args.cipher,
        integrity=integrity,
        dh=args.dh,
        pfs=args.pfs,
    )

    # =========================================================
    # FINAL OUTPUT
    # =========================================================

    print()
    print("=" * 70)
    print("SESSION OUTPUT")
    print("=" * 70)

    if session.pcap_path:

        print()
        print(
            f"PCAP : {session.pcap_path}"
        )

    print()


if __name__ == "__main__":
    main()