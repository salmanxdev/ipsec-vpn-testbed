import argparse

from core.traffic_profiles import TRAFFIC_PROFILES
from core.traffic_runner import run_profile
from core.traffic_validator import validate_traffic_parameters


def main():
    parser = argparse.ArgumentParser(
        description="IPsec VPN Testbed - Phase 1B Traffic Generator"
    )

    parser.add_argument(
        "--profile",
        required=True,
        choices=list(TRAFFIC_PROFILES.keys()),
        help="Traffic profile to generate",
    )

    parser.add_argument(
        "--mode",
        required=True,
        choices=["tunnel", "transport"],
        help="Active IPsec mode",
    )

    parser.add_argument(
        "--family",
        default="ipv4",
        choices=["ipv4", "ipv6"],
        help="IP address family",
    )

    parser.add_argument(
        "--direction",
        default="vm1-to-vm2",
        choices=["vm1-to-vm2", "vm2-to-vm1"],
        help="Traffic direction",
    )

    parser.add_argument(
        "--duration",
        type=int,
        default=5,
        help="Traffic duration in seconds",
    )

    parser.add_argument(
        "--packet-size",
        type=int,
        default=256,
        help="Payload size in bytes",
    )

    parser.add_argument(
        "--rate",
        type=float,
        default=1,
        help="Packets/events per second",
    )

    args = parser.parse_args()

    try:
        validate_traffic_parameters(
            profile=args.profile,
            address_family=args.family,
            direction=args.direction,
            duration=args.duration,
            packet_size=args.packet_size,
            rate=args.rate,
        )
    except ValueError as error:
        parser.error(str(error))

    run_profile(
        profile=args.profile,
        mode=args.mode,
        address_family=args.family,
        direction=args.direction,
        duration=args.duration,
        packet_size=args.packet_size,
        rate=args.rate,
    )


if __name__ == "__main__":
    main()