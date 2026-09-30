import re

from dataclasses import dataclass


@dataclass
class VerificationResult:
    passed: bool
    checks: list[str]
    failures: list[str]

    def print_report(self):
        print()
        print("=" * 70)
        print("VPN VERIFICATION REPORT")
        print("=" * 70)

        for check in self.checks:
            print(f"[PASS] {check}")

        for failure in self.failures:
            print(f"[FAIL] {failure}")

        print()

        if self.passed:
            print("FINAL RESULT: PASS")
        else:
            print("FINAL RESULT: FAIL")

        print("=" * 70)


def _extract_ike_proposal(sa_status):
    """
    Extract the IKE proposal from swanctl --list-sas output.

    Example:
        AES_CBC-256/HMAC_SHA2_256_128/
        PRF_HMAC_SHA2_256/MODP_2048
    """

    match = re.search(
        r"^\s+("
        r"[A-Z0-9_]+-\d+/"
        r"[A-Z0-9_]+/"
        r"[A-Z0-9_]+/"
        r"(?:MODP_\d+|ECP_\d+)"
        r")\s*$",
        sa_status,
        re.MULTILINE,
    )

    if match:
        return match.group(1)

    return None


def _extract_child_proposal(sa_status):
    """
    Extract the CHILD_SA ESP proposal.

    Examples:
        ESP:AES_CBC-256/HMAC_SHA2_256_128
        ESP:AES_GCM_16-128
        ESP:AES_GCM_16-128/MODP_2048

    Returns only the proposal portion after 'ESP:'.
    """

    match = re.search(
        r"ESP:("
        r"[A-Z0-9_]+-\d+"
        r"(?:/[A-Z0-9_]+)*"
        r")",
        sa_status,
    )

    if match:
        return match.group(1)

    return None


def _extract_ike_dh(sa_status):
    proposal = _extract_ike_proposal(sa_status)

    if proposal is None:
        return None

    if "MODP_2048" in proposal:
        return "modp2048"

    if "ECP_256" in proposal:
        return "ecp256"

    return None


def _extract_child_dh(sa_status):
    proposal = _extract_child_proposal(sa_status)

    if proposal is None:
        return None

    if "MODP_2048" in proposal:
        return "modp2048"

    if "ECP_256" in proposal:
        return "ecp256"

    return None


def _expected_esp_cipher(cipher):
    mapping = {
        "aes128-cbc": "AES_CBC-128",
        "aes256-cbc": "AES_CBC-256",
        "aes128-gcm": "AES_GCM_16",
        "aes256-gcm": "AES_GCM_16",
    }

    if cipher not in mapping:
        raise ValueError(f"Unsupported cipher: {cipher}")

    return mapping[cipher]


def _expected_integrity(cipher, integrity):
    """
    GCM is AEAD, so it does not use a separate HMAC.
    """

    if cipher.endswith("-gcm"):
        return None

    if integrity == "hmac-sha256":
        return "HMAC_SHA2_256_128"

    return None


def verify_sa_status(
    sa_status,
    mode,
    cipher,
    integrity,
    dh,
    pfs,
):
    checks = []
    failures = []

    # ---------------------------------------------------------
    # IKE SA
    # ---------------------------------------------------------

    if "ESTABLISHED" in sa_status:
        checks.append("IKE SA is ESTABLISHED.")
    else:
        failures.append("IKE SA is not ESTABLISHED.")

    # ---------------------------------------------------------
    # CHILD SA
    # ---------------------------------------------------------

    if "INSTALLED" in sa_status:
        checks.append("CHILD_SA is INSTALLED.")
    else:
        failures.append("CHILD_SA is not INSTALLED.")

    # ---------------------------------------------------------
    # IPsec mode
    # ---------------------------------------------------------

    expected_mode = mode.upper()

    if expected_mode in sa_status:
        checks.append(
            f"IPsec mode matches expected mode: {mode}."
        )
    else:
        failures.append(
            f"IPsec mode mismatch. Expected {mode}."
        )

    # ---------------------------------------------------------
    # IKE DH
    # ---------------------------------------------------------

    actual_ike_dh = _extract_ike_dh(sa_status)

    expected_ike_dh_map = {
        14: "modp2048",
        19: "ecp256",
    }

    expected_ike_dh = expected_ike_dh_map.get(dh)

    if expected_ike_dh is None:
        failures.append(
            f"Unsupported DH group requested: DH{dh}."
        )
    elif actual_ike_dh == expected_ike_dh:
        checks.append(
            f"IKE DH group matches: DH{dh}."
        )
    else:
        failures.append(
            f"IKE DH mismatch. "
            f"Expected DH{dh}, "
            f"got {actual_ike_dh or 'unknown'}."
        )

    # ---------------------------------------------------------
    # ESP cipher
    # ---------------------------------------------------------

    try:
        expected_cipher = _expected_esp_cipher(cipher)
    except ValueError as exc:
        failures.append(str(exc))
        expected_cipher = None

    child_proposal = _extract_child_proposal(sa_status)

    if expected_cipher is not None:
        if child_proposal and expected_cipher in child_proposal:
            checks.append(
                f"ESP cipher matches: {expected_cipher}."
            )
        else:
            failures.append(
                f"ESP cipher mismatch. "
                f"Expected {expected_cipher}, "
                f"got {child_proposal or 'unknown'}."
            )

    # ---------------------------------------------------------
    # ESP integrity
    # ---------------------------------------------------------

    expected_integrity = _expected_integrity(
        cipher,
        integrity,
    )

    if cipher.endswith("-gcm"):
        # AES-GCM is an AEAD cipher.
        # It provides encryption + authentication itself.
        # Therefore there must NOT be a separate HMAC.

        if (
            child_proposal
            and "AES_GCM_16" in child_proposal
            and "HMAC_" not in child_proposal
        ):
            checks.append(
                "GCM authenticated encryption is used "
                "without separate HMAC."
            )
        else:
            failures.append(
                "GCM integrity verification failed."
            )

    else:
        if (
            child_proposal
            and expected_integrity
            and expected_integrity in child_proposal
        ):
            checks.append(
                f"ESP integrity matches: "
                f"{expected_integrity}."
            )
        else:
            failures.append(
                f"ESP integrity mismatch. "
                f"Expected {expected_integrity or 'unknown'}, "
                f"got {child_proposal or 'unknown'}."
            )

    # ---------------------------------------------------------
    # PFS / CHILD_SA DH
    # ---------------------------------------------------------

    actual_child_dh = _extract_child_dh(sa_status)

    if pfs == "on":
        if expected_ike_dh is None:
            failures.append(
                "PFS verification skipped because "
                "the requested DH group is unsupported."
            )
        elif actual_child_dh == expected_ike_dh:
            checks.append(
                f"PFS is enabled with DH{dh}."
            )
        else:
            failures.append(
                f"PFS mismatch. "
                f"Expected CHILD_SA DH{dh}, "
                f"got {actual_child_dh or 'none'}."
            )

    elif pfs == "off":
        if actual_child_dh is None:
            checks.append(
                "PFS is disabled; "
                "CHILD_SA has no DH group."
            )
        else:
            failures.append(
                f"PFS mismatch. "
                f"Expected no CHILD_SA DH, "
                f"but found {actual_child_dh}."
            )

    else:
        failures.append(
            f"Unsupported PFS value: {pfs}. "
            f"Expected 'on' or 'off'."
        )

    return checks, failures


def verify_ping(traffic_output):
    checks = []
    failures = []

    match = re.search(
        r"(\d+)\s+packets transmitted,\s+"
        r"(\d+)\s+received",
        traffic_output,
    )

    if not match:
        failures.append(
            "Could not determine packet transmission "
            "result from ping output."
        )
        return checks, failures

    transmitted = int(match.group(1))
    received = int(match.group(2))

    if transmitted == 5 and received == 5:
        checks.append(
            "ICMP traffic succeeded: "
            "5 transmitted, 5 received."
        )
    else:
        failures.append(
            f"ICMP traffic failed. "
            f"Expected 5/5 packets, "
            f"got {transmitted}/{received}."
        )

    return checks, failures


def verify_xfrm(
    xfrm_state,
    mode,
):
    checks = []
    failures = []

    # ---------------------------------------------------------
    # ESP state
    # ---------------------------------------------------------

    xfrm_lower = xfrm_state.lower()

    if "proto esp" not in xfrm_lower:
        failures.append(
            "Linux XFRM does not show an ESP state."
        )
        return checks, failures

    checks.append(
        "Linux XFRM contains an active ESP state."
    )

    # ---------------------------------------------------------
    # XFRM mode
    # ---------------------------------------------------------

    expected_xfrm_mode = f"mode {mode.lower()}"

    if expected_xfrm_mode in xfrm_lower:
        checks.append(
            f"Linux XFRM mode matches expected mode: {mode}."
        )
    else:
        failures.append(
            f"Linux XFRM mode mismatch. "
            f"Expected '{expected_xfrm_mode}'."
        )

    # ---------------------------------------------------------
    # ESP traffic verification
    #
    # `ip xfrm state` does not expose a "packets" counter.
    #
    # Instead, Linux exposes ESP sequence numbers through:
    #
    #     anti-replay context:
    #         seq 0x5, oseq 0x0
    #
    # For outbound traffic:
    #     oseq > 0
    #
    # For inbound traffic:
    #     seq > 0
    #
    # Therefore we use these values as evidence that
    # protected ESP traffic has actually passed through XFRM.
    # ---------------------------------------------------------

    anti_replay_matches = re.findall(
        r"anti-replay context:\s*"
        r"seq\s+(0x[0-9a-fA-F]+),\s*"
        r"oseq\s+(0x[0-9a-fA-F]+)",
        xfrm_state,
        re.IGNORECASE,
    )

    if not anti_replay_matches:
        failures.append(
            "Could not find XFRM anti-replay sequence counters."
        )
        return checks, failures

    inbound_sequences = []
    outbound_sequences = []

    for seq_hex, oseq_hex in anti_replay_matches:
        inbound_sequences.append(int(seq_hex, 16))
        outbound_sequences.append(int(oseq_hex, 16))

    inbound_active = any(
        sequence > 0
        for sequence in inbound_sequences
    )

    outbound_active = any(
        sequence > 0
        for sequence in outbound_sequences
    )

    if inbound_active or outbound_active:
        checks.append(
            "XFRM anti-replay sequence counters show "
            "protected ESP traffic."
        )
    else:
        failures.append(
            "XFRM anti-replay sequence counters are zero."
        )

    return checks, failures
def verify_test(
    sa_status,
    xfrm_state,
    traffic_output,
    mode,
    cipher,
    integrity,
    dh,
    pfs,
):
    checks = []
    failures = []

    sa_checks, sa_failures = verify_sa_status(
        sa_status=sa_status,
        mode=mode,
        cipher=cipher,
        integrity=integrity,
        dh=dh,
        pfs=pfs,
    )

    ping_checks, ping_failures = verify_ping(
        traffic_output=traffic_output,
    )

    xfrm_checks, xfrm_failures = verify_xfrm(
        xfrm_state=xfrm_state,
        mode=mode,
    )

    checks.extend(sa_checks)
    checks.extend(ping_checks)
    checks.extend(xfrm_checks)

    failures.extend(sa_failures)
    failures.extend(ping_failures)
    failures.extend(xfrm_failures)

    return VerificationResult(
        passed=len(failures) == 0,
        checks=checks,
        failures=failures,
    )