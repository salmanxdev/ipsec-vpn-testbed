from core.test_matrix import TEST_CASES

VALID_MODES = {"tunnel", "transport"}
VALID_CIPHERS = {"aes128-cbc", "aes256-cbc", "aes128-gcm", "aes256-gcm"}
VALID_INTEGRITY = {"hmac-sha256", None}
VALID_DH_GROUPS = {14, 19}
VALID_PFS = {"on", "off"}

def validate_parameters(mode, cipher, integrity, dh, pfs):
    errors = []

    if mode not in VALID_MODES:
        errors.append(
            f"Invalid mode '{mode}'. Choose: tunnel or transport."
        )

    if cipher not in VALID_CIPHERS:
        errors.append(
            f"Invalid cipher '{cipher}'. "
            f"Choose: {', '.join(sorted(VALID_CIPHERS))}."
        )

    # GCM is AEAD, so it must not use a separate HMAC.
    if cipher.endswith("-gcm"):
        if integrity is not None:
            errors.append(
                "GCM already provides authenticated encryption. "
                "Integrity must not be specified separately."
            )

    # CBC requires HMAC-SHA256.
    if cipher.endswith("-cbc"):
        if integrity != "hmac-sha256":
            errors.append(
                "CBC requires integrity='hmac-sha256'."
            )

    if dh not in VALID_DH_GROUPS:
        errors.append(
            f"Invalid DH group '{dh}'. Choose: 14 or 19."
        )

    if pfs not in VALID_PFS:
        errors.append(
            f"Invalid PFS value '{pfs}'. Choose: on or off."
        )

    if errors:
        raise ValueError("\n".join(errors))


def find_test_id(mode, cipher, integrity, dh, pfs):
    for test_id, case in TEST_CASES.items():
        if (
            case["mode"] == mode
            and case["cipher"] == cipher
            and case["integrity"] == integrity
            and case["dh"] == dh
            and case["pfs"] == pfs
        ):
            return test_id

    return None