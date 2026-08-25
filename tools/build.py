#!/usr/bin/env python3
"""Build immutable cloud-init snippets and self-contained Proxmox scripts."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import datetime
import hashlib
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile

from render import (
    APPDATA_MOUNT,
    CONFIG,
    CONFIG_FILE,
    DEFAULT_RELEASE,
    LOCAL_CONFIG,
    PROFILES,
    PRIVATE_SOURCE_MARKER,
    ROOT,
    SSH_ALLOW_USERS,
    Image,
    LxcTemplate,
    Profile,
    expand_template,
    load_image,
    load_lxc_template,
    lxc_template_name,
    profile_flags,
    render,
    render_lxc,
    resolve_config_path,
    template_name,
)


COMMAND_TEMPLATE = ROOT / "templates" / "proxmox-create.sh.tmpl"
LXC_COMMAND_TEMPLATE = ROOT / "templates" / "proxmox-lxc-create.sh.tmpl"
BUNDLE_MARKER = ".kasa-cloud-init-bundle"

@dataclass(frozen=True)
class VendorArtifact:
    vmid: int
    template_name: str
    filename: str
    digest: str
    content: str


@dataclass(frozen=True)
class LxcArtifact:
    """One profile's container pair: what the host runs, and what the guest runs.

    The guest bootstrap is deliberately usable on its own against an already
    created container, so the two are separate files rather than one script.
    """

    ctid: int
    name: str
    bootstrap_filename: str
    command_filename: str
    bootstrap: str
    command: str


def fail(message: str) -> None:
    raise SystemExit(f"ERROR: {message}")


def run(command: list[str], *, input_text: str | None = None) -> str:
    result = subprocess.run(
        command,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        if result.stdout:
            print(result.stdout, file=sys.stderr, end="")
        if result.stderr:
            print(result.stderr, file=sys.stderr, end="")
        fail(f"command failed: {shlex.join(command)}")
    return result.stdout


def sha256(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def source_provenance() -> dict[str, str]:
    """Describe the working tree this build came from.

    Template names carry no version, so this is the only way a running VM can
    say which build produced it. A dirty tree is recorded rather than rejected;
    iterating locally is normal, shipping from a dirty tree should be visible.
    """
    git = shutil.which("git")
    commit = "unknown"
    dirty = "unknown"
    if git:
        result = subprocess.run(
            [git, "-C", str(ROOT), "rev-parse", "HEAD"],
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode == 0:
            commit = result.stdout.strip()
            status = subprocess.run(
                [git, "-C", str(ROOT), "status", "--porcelain"],
                text=True,
                capture_output=True,
                check=False,
            )
            if status.returncode == 0:
                dirty = "true" if status.stdout.strip() else "false"
    return {
        "SOURCE_COMMIT": commit,
        "SOURCE_TREE_DIRTY": dirty,
        "BUILT_AT": datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat(),
    }


def render_command(
    *,
    profile: Profile,
    vendor: VendorArtifact,
    image: Image,
    public_key: str,
) -> str:
    """Render one VM's Proxmox creation script.

    Goes through expand_template rather than plain substitution so the script can carry
    `#% if ssh_user_ca`: a CA-only template must not pass --sshkeys, and must not assert
    that Proxmox generated authorized keys it was never given. This is the same path
    render_lxc_command already uses.
    """
    replacements = {
        "@@VMID@@": str(vendor.vmid),
        "@@NAME@@": vendor.template_name,
        "@@CPU@@": CONFIG["CPU"],
        "@@MEM_MIN@@": CONFIG["MEM_MIN"],
        "@@MEM_MAX@@": CONFIG["MEM_MAX"],
        "@@BRIDGE@@": CONFIG["BRIDGE"],
        "@@VM_STORAGE_NAME@@": CONFIG["VM_STORAGE_NAME"],
        "@@SNIPPET_STORAGE_NAME@@": CONFIG["SNIPPET_STORAGE_NAME"],
        "@@ISO_STORAGE_PATH@@": CONFIG["ISO_STORAGE_PATH"],
        "@@ROOT_DISK_SIZE@@": CONFIG["ROOT_DISK_SIZE"],
        "@@APPDATA_DISK_SIZE@@": CONFIG["APPDATA_DISK_SIZE"],
        "@@APPDATA_SERIAL@@": CONFIG["APPDATA_SERIAL"],
        "@@APPDATA_WWN@@": CONFIG["APPDATA_WWN"],
        "@@VENDOR_SNIPPET_NAME@@": vendor.filename,
        "@@VENDOR_SHA256@@": vendor.digest,
        "@@SSH_PUBLIC_KEY@@": public_key,
        "@@IMAGE_NAME@@": image.name,
        "@@IMAGE_SHA512@@": image.sha512,
        "@@IMAGE_URL@@": image.url,
    }
    quoted = {marker: shlex.quote(value) for marker, value in replacements.items()}
    try:
        return expand_template(COMMAND_TEMPLATE, profile_flags(profile), quoted)
    except ValueError as error:
        fail(f"Proxmox command template: {error}")


def render_lxc_command(
    *,
    profile: Profile,
    ctid: int,
    name: str,
    pin: LxcTemplate,
    bootstrap_filename: str,
    bootstrap_digest: str,
    public_key: str,
) -> str:
    values = {
        "CTID": str(ctid),
        "HOSTNAME": name,
        "PROFILE_NAME": profile.name,
        "LXC_TEMPLATE": pin.template,
        "LXC_TEMPLATE_STORAGE": CONFIG["LXC_TEMPLATE_STORAGE"],
        "LXC_ROOTFS_STORAGE": CONFIG["LXC_ROOTFS_STORAGE"],
        "LXC_ROOT_DISK_SIZE": CONFIG["LXC_ROOT_DISK_SIZE"],
        "LXC_APPDATA_STORAGE": CONFIG["LXC_APPDATA_STORAGE"],
        "LXC_APPDATA_DISK_SIZE": CONFIG["LXC_APPDATA_DISK_SIZE"],
        "APPDATA_MOUNT": APPDATA_MOUNT,
        "LXC_CPU": CONFIG["LXC_CPU"],
        "LXC_MEMORY": CONFIG["LXC_MEMORY"],
        "LXC_SWAP": CONFIG["LXC_SWAP"],
        "BRIDGE": CONFIG["BRIDGE"],
        "LXC_VLAN_TAG": CONFIG["LXC_VLAN_TAG"],
        "LXC_NAMESERVER": CONFIG["LXC_NAMESERVER"],
        "TIMEZONE": CONFIG["TIMEZONE"],
        "SSH_PUBLIC_KEY": public_key,
        "BOOTSTRAP_NAME": bootstrap_filename,
        "BOOTSTRAP_SHA256": bootstrap_digest,
    }
    replacements = {
        f"@@{key}@@": shlex.quote(value) for key, value in values.items()
    }
    return expand_template(
        LXC_COMMAND_TEMPLATE, profile_flags(profile), replacements
    )


def validate_generated_lxc(profile: Profile, artifact: LxcArtifact) -> None:
    """Check the container pair before either file reaches the output directory.

    The separation these assertions defend is the whole point of having four
    profiles: a base container that quietly gained Docker's feature set would
    still work, which is exactly why nothing downstream would notice.
    """
    command = artifact.command
    name = artifact.command_filename

    # Read the options the script actually passes to pct. Scanning the whole
    # file would trip over the script's own post-create assertions, which name
    # the very features they exist to reject.
    features = re.findall(r"--features\s+(\S+)", command)
    granted = {token for value in features for token in value.split(",")}

    if not re.search(r"--unprivileged\s+1\b", command):
        fail(f"{name}: container must be created unprivileged")
    if re.search(r"--unprivileged\s+0\b", command):
        fail(f"{name}: container must never be created privileged")

    if profile.docker:
        if granted != {"keyctl=1", "nesting=1"}:
            fail(
                f"{name}: a Docker profile must grant exactly keyctl=1 and "
                f"nesting=1, found {sorted(granted) or 'nothing'}"
            )
    elif features:
        fail(
            f"{name}: a base profile must pass no --features at all; Proxmox "
            f"already defaults every one of them to off, found {features}"
        )

    for token in sorted(granted):
        if token.split("=")[0] in ("fuse", "mknod", "mount", "force_rw_sys"):
            fail(f"{name}: must not grant {token}")
    if "unconfined" in command:
        fail(f"{name}: must not weaken the container's AppArmor profile")
    # Look for the capability, not the word: the script explains in prose that
    # it has no replace path, and that sentence must not trip this check.
    if re.search(r"^\s*--replace\)", command, re.MULTILINE):
        fail(f"{name}: must not accept a replace flag that destroys a container")
    if "pct destroy" in command:
        fail(f"{name}: must not destroy a container")
    mount_points = re.findall(r"--mp(\d+)\s", command)
    if mount_points != ["0"]:
        fail(
            f"{name}: must attach exactly one mount point, mp0; "
            f"found {mount_points or 'none'}"
        )

    shellcheck = shutil.which("shellcheck")
    for filename, content in (
        (artifact.bootstrap_filename, artifact.bootstrap),
        (artifact.command_filename, command),
    ):
        try:
            run(["bash", "-n"], input_text=content)
        except SystemExit:
            fail(f"{filename}: generated script is not valid bash")
        if shellcheck:
            run([shellcheck, "--shell", "bash", "-"], input_text=content)


def validate_generated_command(vendor: VendorArtifact, command: str) -> None:
    appdata_volume = (
        "${VM_STORAGE_NAME}:${APPDATA_DISK_SIZE},"
        "ssd=1,discard=on,iothread=1,backup=1,"
        "serial=${APPDATA_SERIAL},wwn=${APPDATA_WWN}"
    )
    assignments = (
        f"APPDATA_DISK_SIZE={shlex.quote(CONFIG['APPDATA_DISK_SIZE'])}",
        f"APPDATA_SERIAL={shlex.quote(CONFIG['APPDATA_SERIAL'])}",
        f"APPDATA_WWN={shlex.quote(CONFIG['APPDATA_WWN'])}",
    )
    if (
        command.count("--scsi1") != 1
        or appdata_volume not in command
        or any(assignment not in command for assignment in assignments)
    ):
        fail("generated Proxmox command must attach exactly one configured APPDATA disk")
    if "NEEDS_APPDATA" in command or "needs_appdata" in command:
        fail("generated Proxmox command must not make APPDATA optional")
    if "poweroff" in command or "powers off" in command:
        fail("generated Proxmox command must not tell the operator the VM powers off")
    if "the VM remains running afterward" not in command:
        fail("generated Proxmox command must describe first-boot running state")

    cloud_init = shutil.which("cloud-init")
    if cloud_init:
        with tempfile.TemporaryDirectory(prefix="kasa-bundle-check.") as temp_dir:
            vendor_path = Path(temp_dir) / vendor.filename
            vendor_path.write_text(vendor.content, encoding="utf-8")
            run([cloud_init, "schema", "--config-file", str(vendor_path)])
    run(["bash", "-n"], input_text=command)
    shellcheck = shutil.which("shellcheck")
    if shellcheck:
        run([shellcheck, "--shell", "bash", "-"], input_text=command)


def install_artifact(directory: Path, name: str, content: str, mode: int) -> Path:
    destination = directory / name
    encoded = content.encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{name}.", dir=directory)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as artifact:
            artifact.write(encoded)
            artifact.flush()
            os.fsync(artifact.fileno())
        temporary.chmod(mode)
        os.replace(temporary, destination)
        if not destination.exists() or destination.read_bytes() != encoded:
            fail(f"artifact installation verification failed: {destination}")
    finally:
        temporary.unlink(missing_ok=True)
    return destination


def prepare_output_directory() -> Path:
    """Resolve ARTIFACT_OUTPUT_DIR and take ownership of it.

    The directory holds generated output and nothing else. A marker file
    records that a build owns it, so a mistyped path cannot scatter artifacts
    into a directory that holds real work, and a rebuild starts clean instead
    of leaving scripts behind from an earlier NAME_PREFIX for scp to pick up.
    """
    directory = Path(CONFIG["ARTIFACT_OUTPUT_DIR"]).expanduser()
    if not directory.is_absolute():
        directory = ROOT / directory

    if directory.exists() and not directory.is_dir():
        fail(f"ARTIFACT_OUTPUT_DIR is not a directory: {directory}")
    if not directory.is_dir():
        try:
            directory.mkdir(parents=True)
        except OSError as error:
            fail(f"could not create ARTIFACT_OUTPUT_DIR {directory}: {error}")
    if not os.access(directory, os.W_OK):
        fail(f"ARTIFACT_OUTPUT_DIR is not writable: {directory}")

    marker = directory / BUNDLE_MARKER
    existing = sorted(directory.iterdir())
    if existing and not marker.is_file():
        fail(
            f"ARTIFACT_OUTPUT_DIR is not empty and has no {BUNDLE_MARKER} marker: "
            f"{directory}; point it at a directory dedicated to generated files"
        )
    for entry in existing:
        if entry == marker:
            continue
        if entry.is_dir() and not entry.is_symlink():
            fail(f"unexpected directory in the bundle output: {entry}")
        entry.unlink()

    marker.write_text(
        "Generated by tools/build.py.\n"
        "Every file here is rebuilt from scratch; do not keep anything in it.\n",
        encoding="utf-8",
    )
    return directory


def read_public_keys() -> str:
    """Read every SSH public key to inject, newline-separated, or "" when unconfigured.

    Multiple keys are supported because a fleet has more than one operator and more than
    one control host: tools/keys.pub carries a workstation key and the controller's. Both
    `qm set --sshkeys` and `pct create --ssh-public-keys` read one key per line, and the
    generated scripts already write the value with `printf '%s\\n'`, so nothing on the
    Proxmox side has to know how many there are.

    Empty is legitimate when SSH_USER_CA_PUBLIC_KEY is set -- a CA-only template. render.py
    refuses the both-empty case, so reaching here with no keys and no CA is impossible.
    """
    configured = CONFIG["SSH_PUBLIC_KEY_FILE"]
    if not configured:
        return ""
    key_path = resolve_config_path(configured)
    if not key_path.is_file():
        # Name the resolved path and what it was resolved against. A relative value is
        # resolved against tools/, not the repository root, so `./tools/keys.pub` becomes
        # tools/tools/keys.pub -- and the configured string alone makes that look correct.
        fail(
            f"SSH public key file is missing: {key_path} "
            f"(SSH_PUBLIC_KEY_FILE={configured!r}, resolved against {CONFIG_FILE.parent})"
        )

    keys = [
        line.strip()
        for line in key_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not keys:
        fail(f"{key_path} contains no public keys")

    # One call reports every key in the file, so this validates all of them.
    run(["ssh-keygen", "-l", "-f", str(key_path)])

    for key in keys:
        if "-cert-v01@openssh.com " in key:
            fail(
                f"{key_path} contains a signed OpenSSH certificate. A certificate cannot "
                "be an authorized key. To have hosts accept certificates, set "
                "SSH_USER_CA_PUBLIC_KEY to the CA public key instead."
            )
    if len(keys) != len(set(keys)):
        fail(f"{key_path} contains duplicate public keys")
    return "\n".join(keys)


def verify_root_ca() -> None:
    """Parse the configured root CA and refuse one that has already expired.

    render.py has already checked the file is a single certificate with no private key.
    This is the part that needs openssl: a structurally valid but expired anchor would be
    baked into an image that outlives the build, and update-ca-certificates installs it
    without complaint.
    """
    configured = CONFIG["KASA_ROOT_CA_FILE"]
    if not configured:
        return
    ca_path = resolve_config_path(configured)
    run(["openssl", "x509", "-noout", "-in", str(ca_path)])
    result = subprocess.run(
        ["openssl", "x509", "-noout", "-checkend", "0", "-in", str(ca_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        fail(f"{ca_path}: the root CA certificate has expired")


def build_vendor(profile: Profile, release: str, provenance: dict[str, str]) -> str:
    image = load_image(release)
    return render(
        profile,
        release,
        DEBIAN_IMAGE_BUILD=image.build,
        **provenance,
    )


def build_lxc_bootstrap(
    profile: Profile, release: str, provenance: dict[str, str], pin: LxcTemplate
) -> str:
    # RENDERED_AT, not BUILT_AT: this bootstraps a container Proxmox already
    # created, and calling that a build would overstate what happened.
    return render_lxc(
        profile,
        release,
        LXC_TEMPLATE=pin.template,
        SOURCE_COMMIT=provenance["SOURCE_COMMIT"],
        SOURCE_TREE_DIRTY=provenance["SOURCE_TREE_DIRTY"],
        RENDERED_AT=provenance["BUILT_AT"],
    )


def lxc_artifacts(
    release: str, provenance: dict[str, str], public_key: str
) -> tuple[LxcArtifact, ...]:
    pin = load_lxc_template(release)
    ctid_start = int(CONFIG["LXC_CTID_START"])
    prefix = CONFIG["NAME_PREFIX"]
    artifacts: list[LxcArtifact] = []
    for profile in PROFILES:
        bootstrap = build_lxc_bootstrap(profile, release, provenance, pin)
        name = lxc_template_name(profile, release, prefix)
        bootstrap_filename = f"{name}-bootstrap.sh"
        artifacts.append(
            LxcArtifact(
                ctid=ctid_start + profile.vmid_offset,
                name=name,
                bootstrap_filename=bootstrap_filename,
                command_filename=f"create-{name}.sh",
                bootstrap=bootstrap,
                command=render_lxc_command(
                    profile=profile,
                    ctid=ctid_start + profile.vmid_offset,
                    name=name,
                    pin=pin,
                    bootstrap_filename=bootstrap_filename,
                    bootstrap_digest=sha256(bootstrap),
                    public_key=public_key,
                ),
            )
        )
    return tuple(artifacts)


def vendor_artifacts(release: str, provenance: dict[str, str]) -> tuple[VendorArtifact, ...]:
    vmid_start = int(CONFIG["VMID_START"])
    prefix = CONFIG["NAME_PREFIX"]
    artifacts: list[VendorArtifact] = []
    for profile in PROFILES:
        vendor_data = build_vendor(profile, release, provenance)
        artifact_name = template_name(profile, release, prefix)
        artifacts.append(
            VendorArtifact(
                vmid=vmid_start + profile.vmid_offset,
                template_name=artifact_name,
                filename=f"{artifact_name}-vendor.yml",
                digest=sha256(vendor_data),
                content=vendor_data,
            )
        )
    return tuple(artifacts)


def build(release: str) -> None:
    if "KASA_ENV_FILE" not in os.environ and not LOCAL_CONFIG.is_file():
        fail("copy tools/env.example to tools/.env and edit it first")
    if PRIVATE_SOURCE_MARKER.is_file() and not SSH_ALLOW_USERS:
        fail("private source builds require SSH_ALLOW_USERS in tools/.env")
    required = ["bash", "ssh-keygen"]
    if CONFIG["KASA_ROOT_CA_FILE"]:
        required.append("openssl")
    for command in required:
        if not shutil.which(command):
            fail(f"required local command is missing: {command}")

    run([sys.executable, str(ROOT / "tools" / "validate.py")])

    image = load_image(release)
    public_key = read_public_keys()
    verify_root_ca()
    provenance = source_provenance()
    if provenance["SOURCE_TREE_DIRTY"] == "true":
        print(
            "WARNING: building from a dirty working tree; "
            "/etc/kasa-image-release will record SOURCE_TREE_DIRTY=true",
            file=sys.stderr,
        )

    vendors = vendor_artifacts(release, provenance)
    commands = tuple(
        (
            f"create-{vendor.template_name}.sh",
            render_command(
                profile=profile, vendor=vendor, image=image, public_key=public_key
            ),
            vendor,
        )
        for profile, vendor in zip(PROFILES, vendors)
    )
    for _, command, vendor in commands:
        validate_generated_command(vendor, command)

    containers = lxc_artifacts(release, provenance, public_key)
    for profile, container in zip(PROFILES, containers):
        validate_generated_lxc(profile, container)

    output_directory = prepare_output_directory()

    yaml_mode = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH
    paths = [
        install_artifact(output_directory, vendor.filename, vendor.content, yaml_mode)
        for vendor in vendors
    ]
    command_mode = (
        stat.S_IRUSR
        | stat.S_IWUSR
        | stat.S_IXUSR
        | stat.S_IRGRP
        | stat.S_IXGRP
        | stat.S_IROTH
        | stat.S_IXOTH
    )
    paths.extend(
        install_artifact(output_directory, name, command, command_mode)
        for name, command, _ in commands
    )
    lxc_paths = [
        install_artifact(
            output_directory,
            container.bootstrap_filename,
            container.bootstrap,
            command_mode,
        )
        for container in containers
    ] + [
        install_artifact(
            output_directory,
            container.command_filename,
            container.command,
            command_mode,
        )
        for container in containers
    ]

    print(f"Built template bundle for {release} ({image.name})")
    for path in paths:
        print(path)
    print(
        "Copy every file to the snippets directory of "
        f"{CONFIG['SNIPPET_STORAGE_NAME']} on Proxmox, then run any one of these:"
    )
    for command_name, _, _ in commands:
        print(f"  bash {command_name}")
    print("Add --replace to rebuild over an existing template.")

    print(f"\nBuilt LXC bundle for {release} ({load_lxc_template(release).template})")
    for path in lxc_paths:
        print(path)
    print(
        "Copy each create script and its matching bootstrap to a Proxmox node, "
        "keeping the pair in the same directory, then run any one of these:"
    )
    for container in containers:
        print(f"  bash {container.command_filename}   # container {container.ctid}")
    print(
        "Each script creates and starts its container, then prints the pct exec "
        "command that completes it."
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--release",
        default=DEFAULT_RELEASE,
        help=f"Debian release directory under templates/ (default: {DEFAULT_RELEASE})",
    )
    arguments = parser.parse_args()
    build(arguments.release)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
