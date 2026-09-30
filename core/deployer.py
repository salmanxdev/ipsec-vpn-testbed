import subprocess
from pathlib import Path


SSH_USER = "kali"

VM1_HOST = "192.168.56.101"
VM2_HOST = "192.168.56.102"

REMOTE_TEMP_FILE = "/tmp/ipsec-test.conf"
REMOTE_CONFIG_FILE = "/etc/swanctl/conf.d/ipsec-test.conf"


def get_vm_host(vm_number):
    """Return the SSH management IP for the selected VM."""

    if vm_number == 1:
        return VM1_HOST

    if vm_number == 2:
        return VM2_HOST

    raise ValueError(f"Invalid VM number: {vm_number}")


def run_command(command):
    """Run a local command and return its standard output."""

    print()
    print("Running command:")
    print(" ".join(command))
    print()

    result = subprocess.run(
        command,
        text=True,
        capture_output=True,
    )

    if result.stdout:
        print(result.stdout)

    if result.stderr:
        print(result.stderr)

    if result.returncode != 0:
        raise RuntimeError(
            f"Command failed with exit code {result.returncode}"
        )

    return result.stdout


def run_remote_command(vm_number, remote_command):
    """Execute a command on a remote VM through SSH."""

    vm_host = get_vm_host(vm_number)

    command = [
        "ssh",
        f"{SSH_USER}@{vm_host}",
        remote_command,
    ]

    return run_command(command)


def scp_to_vm(vm_number, local_file):
    """Copy a local configuration file to a VM."""

    local_file = Path(local_file)

    if not local_file.exists():
        raise FileNotFoundError(
            f"Configuration file not found: {local_file}"
        )

    vm_host = get_vm_host(vm_number)

    command = [
        "scp",
        str(local_file),
        f"{SSH_USER}@{vm_host}:{REMOTE_TEMP_FILE}",
    ]

    return run_command(command)


def install_config_on_vm(vm_number):
    """Install the copied configuration in strongSwan's config directory."""

    command = (
        f"sudo -n install -m 644 "
        f"{REMOTE_TEMP_FILE} "
        f"{REMOTE_CONFIG_FILE}"
    )

    return run_remote_command(vm_number, command)


def deploy_vm_config(vm_number, local_file):
    """Copy and install a VM's strongSwan configuration."""

    print()
    print(f"Deploying configuration to VM{vm_number}...")

    scp_to_vm(vm_number, local_file)

    install_config_on_vm(vm_number)

    print(f"Configuration deployed successfully to VM{vm_number}.")


def ensure_strongswan_running(vm_number):
    """Ensure the strongSwan service is running."""

    print()
    print(f"Checking strongSwan on VM{vm_number}...")

    check_command = (
        "systemctl is-active --quiet strongswan-starter"
    )

    vm_host = get_vm_host(vm_number)

    command = [
        "ssh",
        f"{SSH_USER}@{vm_host}",
        check_command,
    ]

    result = subprocess.run(
        command,
        text=True,
        capture_output=True,
    )

    if result.returncode == 0:
        print(f"strongSwan is already running on VM{vm_number}.")
        return

    print(f"Starting strongSwan on VM{vm_number}...")

    run_remote_command(
        vm_number,
        "sudo -n systemctl start strongswan-starter",
    )

    print(f"strongSwan started on VM{vm_number}.")


def load_swanctl_config(vm_number):
    """Load the strongSwan configuration on a VM."""

    print()
    print(f"Loading configuration on VM{vm_number}...")

    return run_remote_command(
        vm_number,
        "sudo -n swanctl --load-all",
    )


def terminate_child_sa(vm_number):
    """
    Terminate the existing CHILD_SA named 'net'.

    A missing CHILD_SA is not treated as a fatal error.
    """

    print()
    print(f"Terminating existing CHILD_SA on VM{vm_number}...")

    vm_host = get_vm_host(vm_number)

    command = [
        "ssh",
        f"{SSH_USER}@{vm_host}",
        "sudo -n swanctl --terminate --child net",
    ]

    result = subprocess.run(
        command,
        text=True,
        capture_output=True,
    )

    if result.stdout:
        print(result.stdout)

    if result.stderr:
        print(result.stderr)

    if result.returncode == 0:
        print(f"VM{vm_number}: CHILD_SA termination command completed.")
    else:
        print(
            f"VM{vm_number}: no existing CHILD_SA was terminated."
        )


def terminate_ike_sa(vm_number):
    """
    Terminate the existing IKE_SA named 'ipsec-test'.

    Terminating an IKE_SA also removes its associated CHILD_SAs.
    A missing IKE_SA is not treated as a fatal error.
    """

    print()
    print(f"Terminating existing IKE_SA on VM{vm_number}...")

    vm_host = get_vm_host(vm_number)

    command = [
        "ssh",
        f"{SSH_USER}@{vm_host}",
        "sudo -n swanctl --terminate --ike ipsec-test",
    ]

    result = subprocess.run(
        command,
        text=True,
        capture_output=True,
    )

    if result.stdout:
        print(result.stdout)

    if result.stderr:
        print(result.stderr)

    if result.returncode == 0:
        print(f"VM{vm_number}: IKE_SA termination command completed.")
    else:
        print(
            f"VM{vm_number}: no existing IKE_SA was terminated."
        )


def initiate_ike_sa(vm_number):
    """Initiate the IKE_SA named 'ipsec-test'."""

    print()
    print(f"Initiating IKE_SA on VM{vm_number}...")

    return run_remote_command(
        vm_number,
        "sudo -n swanctl --initiate --ike ipsec-test",
    )


def initiate_child_sa(vm_number):
    """Initiate the CHILD_SA named 'net'."""

    print()
    print(f"Initiating CHILD_SA on VM{vm_number}...")

    return run_remote_command(
        vm_number,
        "sudo -n swanctl --initiate --child net",
    )


def get_sa_status(vm_number):
    """Return the current strongSwan security association status."""

    print()
    print(f"Getting SA status from VM{vm_number}...")

    return run_remote_command(
        vm_number,
        "sudo -n swanctl --list-sas",
    )


def get_xfrm_state(vm_number):
    """Return the Linux kernel's IPsec XFRM state."""

    print()
    print(f"Getting XFRM state from VM{vm_number}...")

    return run_remote_command(
        vm_number,
        "sudo -n ip -s xfrm state",
    )