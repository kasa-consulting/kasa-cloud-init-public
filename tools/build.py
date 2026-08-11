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
    CONFIG,
    CONFIG_FILE,
    DEFAULT_RELEASE,
    LOCAL_CONFIG,
    PROFILES,
    ROOT,
    Image,
    Profile,
    load_image,
    render,
    template_name,
)


COMMAND_TEMPLATE = ROOT / "templates" / "proxmox-create.sh.tmpl"
BUNDLE_MARKER = ".kasa-cloud-init-bundle"

@dataclass(frozen=True)
class VendorArtifact:
    vmid: int
    template_name: str
    filename: str
    digest: str
    content: str


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
    vendor: VendorArtifact,
    image: Image,
    public_key: str,
) -> str:
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
    content = COMMAND_TEMPLATE.read_text(encoding="utf-8")
    for marker, value in replacements.items():
        content = content.replace(marker, shlex.quote(value))
    unresolved = sorted(set(re.findall(r"@@[A-Z0-9_]+@@", content)))
    if unresolved:
        fail(f"unresolved Proxmox command markers: {unresolved}")
    return content


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


def read_public_key() -> str:
    key_path = Path(CONFIG["SSH_PUBLIC_KEY_FILE"]).expanduser()
    if not key_path.is_absolute():
        key_path = CONFIG_FILE.parent / key_path
    if not key_path.is_file():
        fail(f"SSH public key is missing: {key_path}")
    lines = key_path.read_text(encoding="utf-8").splitlines()
    if len(lines) != 1 or not lines[0]:
        fail("SSH_PUBLIC_KEY_FILE must contain exactly one public key line")
    run(["ssh-keygen", "-l", "-f", str(key_path)])
    if "-cert-v01@openssh.com " in lines[0]:
        fail("signed OpenSSH certificates require trusted-CA server configuration")
    return lines[0]


def build_vendor(profile: Profile, release: str, provenance: dict[str, str]) -> str:
    image = load_image(release)
    return render(
        profile,
        release,
        DEBIAN_IMAGE_BUILD=image.build,
        **provenance,
    )


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
    for command in ("bash", "ssh-keygen"):
        if not shutil.which(command):
            fail(f"required local command is missing: {command}")

    run([sys.executable, str(ROOT / "tools" / "validate.py")])

    image = load_image(release)
    public_key = read_public_key()
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
            render_command(vendor=vendor, image=image, public_key=public_key),
            vendor,
        )
        for vendor in vendors
    )
    for _, command, vendor in commands:
        validate_generated_command(vendor, command)

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
