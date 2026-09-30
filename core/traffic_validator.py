from core.traffic_profiles import TRAFFIC_PROFILES


VALID_ADDRESS_FAMILIES = {"ipv4", "ipv6"}
VALID_DIRECTIONS = {"vm1-to-vm2", "vm2-to-vm1"}


def validate_traffic_parameters(
    profile,
    address_family,
    direction,
    duration,
    packet_size,
    rate,
):
    errors = []

    if profile not in TRAFFIC_PROFILES:
        errors.append(
            f"Invalid traffic profile '{profile}'. "
            f"Choose: {', '.join(TRAFFIC_PROFILES.keys())}."
        )

    if address_family not in VALID_ADDRESS_FAMILIES:
        errors.append(
            f"Invalid address family '{address_family}'. "
            "Choose: ipv4 or ipv6."
        )

    if direction not in VALID_DIRECTIONS:
        errors.append(
            f"Invalid direction '{direction}'. "
            "Choose: vm1-to-vm2 or vm2-to-vm1."
        )

    if duration <= 0:
        errors.append("Duration must be greater than 0 seconds.")

    if packet_size <= 0:
        errors.append("Packet size must be greater than 0 bytes.")

    if rate <= 0:
        errors.append("Rate must be greater than 0.")

    if errors:
        raise ValueError("\n".join(errors))