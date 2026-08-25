#!/usr/bin/env python3
"""Render the agent cloud-init profiles from one template per Debian release."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import os
from pathlib import Path
import re
import shlex

import yaml

from debian_image_updater import ImagePinError, load_image_pin


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "templates"
DOCKER_KEY = ROOT / "assets" / "docker-release.asc"
PROFILE_MANIFEST = TEMPLATES / "profiles.yaml"
LOCAL_CONFIG = ROOT / "tools" / ".env"
EXAMPLE_CONFIG = ROOT / "tools" / "env.example"
PRIVATE_SOURCE_MARKER = ROOT / ".kasa-private-source"

DEFAULT_RELEASE = "deb13"

# Flags a template may test with `#% if <flag>`.
KNOWN_FLAGS = frozenset({"docker", "remote_syslog"})

# One LXC guest bootstrap and one Proxmox-side creation script per profile, from
# the same profile flags the VM templates use. LXC-ness is which template gets
# rendered, not a flag, so KNOWN_FLAGS is unchanged.
CLOUD_CONFIG_TEMPLATE = "cloud-config.yml.tmpl"
LXC_BOOTSTRAP_TEMPLATE = "lxc-bootstrap.sh.tmpl"
LXC_TEMPLATE_MANIFEST = "lxc-template.yaml"

# Proxmox mounts APPDATA here on every profile, VM and LXC alike.
APPDATA_MOUNT = "/mnt/appdata"

SITE_KEYS = {
    "BRIDGE",
    "SYSLOG_SERVER",
    "SYSLOG_PORT",
    "FAIL2BAN_IGNORE_IPS",
    "TIMEZONE",
    "APPDATA_WWN",
    "APPDATA_SERIAL",
    "SSH_ALLOW_USERS",
    "SSH_USER_CA_PUBLIC_KEY",
}
BUILD_KEYS = {
    "VMID_START",
    "NAME_PREFIX",
    "SSH_PUBLIC_KEY_FILE",
    "KASA_ROOT_CA_FILE",
    "ARTIFACT_OUTPUT_DIR",
    "SNIPPET_STORAGE_NAME",
    "ISO_STORAGE_PATH",
    "VM_STORAGE_NAME",
    "CPU",
    "MEM_MIN",
    "MEM_MAX",
    "ROOT_DISK_SIZE",
    "APPDATA_DISK_SIZE",
}
# LXC inputs are optional. An existing tools/.env predates them, so a missing
# key takes the default below instead of failing the build. Unknown keys are
# still rejected and every value is validated as strictly as a required one.
LXC_KEY_DEFAULTS = {
    "LXC_CTID_START": "9100",
    "LXC_TEMPLATE_STORAGE": "local",
    # Not "local": on a standard install that storage carries
    # content iso,vztmpl,backup and cannot hold a container rootfs. local-lvm is
    # Proxmox's default rootdir storage. The generated script re-checks this on
    # the node, because no default is right for every install.
    "LXC_ROOTFS_STORAGE": "local-lvm",
    "LXC_APPDATA_STORAGE": "local-lvm",
    "LXC_ROOT_DISK_SIZE": "8",
    "LXC_APPDATA_DISK_SIZE": "16",
    "LXC_CPU": "2",
    "LXC_MEMORY": "2048",
    "LXC_SWAP": "512",
    "LXC_VLAN_TAG": "",
    "LXC_NAMESERVER": "",
}
LXC_KEYS = frozenset(LXC_KEY_DEFAULTS)

# Trust anchors, optional for the same reason the LXC keys are: an existing tools/.env
# predates them, and a missing key must select "not configured" rather than fail a build
# that worked yesterday. Empty is a supported, published state -- it is what the public
# mirror renders.
TRUST_KEY_DEFAULTS = {
    "SSH_USER_CA_PUBLIC_KEY": "",
    "KASA_ROOT_CA_FILE": "",
}
TRUST_KEYS = frozenset(TRUST_KEY_DEFAULTS)

CONFIG_KEYS = SITE_KEYS | BUILD_KEYS | LXC_KEYS | TRUST_KEYS

# An empty value means "not configured" rather than a malformed line.
#
# SSH_PUBLIC_KEY_FILE is optional only in company: load_config refuses a build with
# neither an injected key nor a CA, because that VM would be unreachable. Either one
# alone is a supported shape -- key-only is what every existing template is, and
# CA-only is the point of trusting the CA at first boot.
OPTIONAL_EMPTY_KEYS = frozenset(
    {
        "SSH_ALLOW_USERS",
        "SSH_PUBLIC_KEY_FILE",
        "SSH_USER_CA_PUBLIC_KEY",
        "KASA_ROOT_CA_FILE",
        "LXC_VLAN_TAG",
        "LXC_NAMESERVER",
    }
)


@dataclass(frozen=True)
class Profile:
    name: str
    description: str
    vmid_offset: int
    flags: frozenset[str]

    @property
    def docker(self) -> bool:
        return "docker" in self.flags

    @property
    def remote_syslog(self) -> bool:
        return "remote_syslog" in self.flags


@dataclass(frozen=True)
class Image:
    codename: str
    build: str
    name: str
    url: str
    sha512: str


@dataclass(frozen=True)
class LxcTemplate:
    codename: str
    template: str


def template_name(profile: Profile, release: str, prefix: str) -> str:
    """Build the Proxmox template name from release and profile capabilities."""
    role = "docker" if profile.docker else "base"
    syslog_suffix = "-syslog" if profile.remote_syslog else ""
    return f"{prefix}-{release}-{role}{syslog_suffix}"


def lxc_template_name(profile: Profile, release: str, prefix: str) -> str:
    """Name the LXC artifact pair, using the VM naming convention plus `lxc`.

    The `lxc` segment is what keeps these eight filenames from colliding with
    the eight VM ones in a flat build directory.
    """
    role = "docker" if profile.docker else "base"
    syslog_suffix = "-syslog" if profile.remote_syslog else ""
    return f"{prefix}-{release}-lxc-{role}{syslog_suffix}"


def _config_path() -> Path:
    override = os.environ.get("KASA_ENV_FILE")
    if override:
        return Path(override).expanduser().resolve()
    if LOCAL_CONFIG.exists():
        return LOCAL_CONFIG
    return EXAMPLE_CONFIG


CONFIG_FILE = _config_path()


def _parse_config_value(
    raw_value: str, line_number: int, *, allow_empty: bool = False
) -> str:
    try:
        values = shlex.split(raw_value, comments=False, posix=True)
    except ValueError as error:
        raise ValueError(f"{CONFIG_FILE}:{line_number}: {error}") from error
    if len(values) != 1 or (not values[0] and not allow_empty):
        raise ValueError(
            f"{CONFIG_FILE}:{line_number}: values containing spaces must be quoted"
        )
    return values[0]


def _valid_hostname(value: str) -> bool:
    if len(value) > 253 or value.endswith("."):
        return False
    labels = value.split(".")
    return all(
        1 <= len(label) <= 63
        and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
        for label in labels
    )


def load_profiles() -> tuple[Profile, ...]:
    if not PROFILE_MANIFEST.is_file():
        raise ValueError(f"Profile manifest is missing: {PROFILE_MANIFEST}")
    document = yaml.safe_load(PROFILE_MANIFEST.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or not isinstance(
        document.get("profiles"), list
    ):
        raise ValueError(f"{PROFILE_MANIFEST}: expected a top-level 'profiles' list")

    profiles: list[Profile] = []
    seen_names: set[str] = set()
    seen_offsets: set[int] = set()
    for entry in document["profiles"]:
        if not isinstance(entry, dict):
            raise ValueError(f"{PROFILE_MANIFEST}: each profile must be a mapping")
        missing = {"name", "description", "vmid_offset", "flags"} - entry.keys()
        if missing:
            raise ValueError(
                f"{PROFILE_MANIFEST}: profile is missing keys: {sorted(missing)}"
            )

        name = entry["name"]
        if not isinstance(name, str) or not re.fullmatch(
            r"[a-z0-9][a-z0-9-]{0,48}", name
        ):
            raise ValueError(f"{PROFILE_MANIFEST}: invalid profile name: {name!r}")
        if name in seen_names:
            raise ValueError(f"{PROFILE_MANIFEST}: duplicate profile name: {name}")
        seen_names.add(name)

        offset = entry["vmid_offset"]
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            raise ValueError(
                f"{PROFILE_MANIFEST}: {name}: vmid_offset must be a non-negative integer"
            )
        if offset in seen_offsets:
            raise ValueError(
                f"{PROFILE_MANIFEST}: duplicate vmid_offset {offset} on {name}"
            )
        seen_offsets.add(offset)

        flags = entry["flags"] or []
        if not isinstance(flags, list) or not all(
            isinstance(flag, str) for flag in flags
        ):
            raise ValueError(f"{PROFILE_MANIFEST}: {name}: flags must be a list of strings")
        unknown = sorted(set(flags) - KNOWN_FLAGS)
        if unknown:
            raise ValueError(f"{PROFILE_MANIFEST}: {name}: unknown flags: {unknown}")

        description = entry["description"]
        if not isinstance(description, str) or not description.strip():
            raise ValueError(f"{PROFILE_MANIFEST}: {name}: description cannot be empty")

        profiles.append(
            Profile(
                name=name,
                description=description.strip(),
                vmid_offset=offset,
                flags=frozenset(flags),
            )
        )

    if not profiles:
        raise ValueError(f"{PROFILE_MANIFEST}: at least one profile is required")
    return tuple(profiles)


def load_image(release: str) -> Image:
    if not re.fullmatch(r"[a-z0-9]{1,16}", release):
        raise ValueError(f"Invalid release name: {release!r}")
    image_file = TEMPLATES / release / "image.yaml"
    if not image_file.is_file():
        raise ValueError(f"Image pin is missing: {image_file}")
    try:
        pin = load_image_pin(image_file)
    except ImagePinError as error:
        raise ValueError(f"{image_file}: {error}") from error

    return Image(
        codename=pin.codename,
        build=pin.build,
        name=pin.name,
        url=pin.url,
        sha512=pin.sha512,
    )


def load_lxc_template(release: str) -> LxcTemplate:
    """Read the container template pin for one release.

    There is no checksum to verify here, unlike the VM image pin. Container
    templates come from Proxmox's signed appliance catalog, so `pveam download`
    already owns that trust path; see the manifest for the full reasoning.
    """
    if not re.fullmatch(r"[a-z0-9]{1,16}", release):
        raise ValueError(f"Invalid release name: {release!r}")
    manifest = TEMPLATES / release / LXC_TEMPLATE_MANIFEST
    if not manifest.is_file():
        raise ValueError(f"LXC template pin is missing: {manifest}")
    document = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"{manifest}: expected a mapping")

    missing = {"codename", "template"} - document.keys()
    if missing:
        raise ValueError(f"{manifest}: missing keys: {sorted(missing)}")
    unknown = sorted(document.keys() - {"codename", "template"})
    if unknown:
        raise ValueError(f"{manifest}: unknown keys: {unknown}")

    codename = document["codename"]
    template = document["template"]
    if not isinstance(codename, str) or not re.fullmatch(r"[a-z]{1,32}", codename):
        raise ValueError(f"{manifest}: invalid codename: {codename!r}")
    # Pin one exact appliance filename. A wildcard or a bare name would let the
    # catalog move the container underneath a rebuild without anyone noticing.
    if not isinstance(template, str) or not re.fullmatch(
        r"[a-z0-9][a-z0-9._+-]{0,127}\.tar\.(zst|gz|xz)", template
    ):
        raise ValueError(f"{manifest}: invalid template filename: {template!r}")

    return LxcTemplate(codename=codename, template=template)


def load_config(profiles: tuple[Profile, ...]) -> dict[str, str]:
    if not CONFIG_FILE.is_file():
        raise ValueError(
            f"Configuration file is missing: {CONFIG_FILE}; copy env.example to .env"
        )

    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(
        CONFIG_FILE.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Z][A-Z0-9_]*)=(.*)", line)
        if not match:
            raise ValueError(f"{CONFIG_FILE}:{line_number}: expected KEY=value")
        key, raw_value = match.groups()
        if key not in CONFIG_KEYS:
            raise ValueError(f"{CONFIG_FILE}:{line_number}: unknown key {key}")
        if key in values:
            raise ValueError(f"{CONFIG_FILE}:{line_number}: duplicate key {key}")
        values[key] = _parse_config_value(
            raw_value, line_number, allow_empty=key in OPTIONAL_EMPTY_KEYS
        )

    missing = sorted(CONFIG_KEYS - LXC_KEYS - TRUST_KEYS - values.keys())
    if missing:
        raise ValueError(f"{CONFIG_FILE}: missing required keys: {missing}")
    for defaults in (LXC_KEY_DEFAULTS, TRUST_KEY_DEFAULTS):
        for key, default in defaults.items():
            values.setdefault(key, default)

    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}", values["BRIDGE"]):
        raise ValueError(f"{CONFIG_FILE}: BRIDGE contains unsupported characters")

    try:
        ipaddress.ip_address(values["SYSLOG_SERVER"])
    except ValueError:
        if not _valid_hostname(values["SYSLOG_SERVER"]):
            raise ValueError(
                f"{CONFIG_FILE}: SYSLOG_SERVER is not a valid IP address or hostname"
            ) from None

    try:
        syslog_port = int(values["SYSLOG_PORT"])
    except ValueError as error:
        raise ValueError(f"{CONFIG_FILE}: SYSLOG_PORT must be an integer") from error
    if not 1 <= syslog_port <= 65535:
        raise ValueError(f"{CONFIG_FILE}: SYSLOG_PORT must be between 1 and 65535")

    ignore_ips = values["FAIL2BAN_IGNORE_IPS"].split()
    if not ignore_ips:
        raise ValueError(f"{CONFIG_FILE}: FAIL2BAN_IGNORE_IPS cannot be empty")
    for network in ignore_ips:
        try:
            ipaddress.ip_network(network, strict=False)
        except ValueError as error:
            raise ValueError(
                f"{CONFIG_FILE}: invalid FAIL2BAN_IGNORE_IPS entry {network}"
            ) from error
    if "127.0.0.1/8" not in ignore_ips or "::1" not in ignore_ips:
        raise ValueError(
            f"{CONFIG_FILE}: FAIL2BAN_IGNORE_IPS must include IPv4 and IPv6 loopback"
        )

    ssh_allow_users = values["SSH_ALLOW_USERS"].split()
    if len(ssh_allow_users) != len(set(ssh_allow_users)):
        raise ValueError(f"{CONFIG_FILE}: SSH_ALLOW_USERS must not contain duplicates")
    for entry in ssh_allow_users:
        match = re.fullmatch(r"admin@(.+)", entry)
        if not match:
            raise ValueError(
                f"{CONFIG_FILE}: SSH_ALLOW_USERS entries must be exact admin@IP addresses"
            )
        try:
            address = ipaddress.ip_address(match.group(1))
        except ValueError as error:
            raise ValueError(
                f"{CONFIG_FILE}: SSH_ALLOW_USERS entry is not an exact IP address: {entry}"
            ) from error
        if address.version != 4:
            raise ValueError(
                f"{CONFIG_FILE}: SSH_ALLOW_USERS currently supports IPv4 only: {entry}"
            )

    # The SSH user CA public key, baked into the guest as a trust anchor.
    #
    # Same regex kasa-ansible's roles/kasa_ssh_ca asserts, deliberately: the two write the
    # same file on the same hosts, and a key one accepts and the other rejects would mean a
    # host trusting something Ansible would then refuse to converge.
    #
    # A certificate is rejected explicitly. It is the most plausible wrong value here --
    # `bao read ssh/config/ca` and a signed cert are both "the SSH CA thing" to anyone who
    # has not read the docs -- and TrustedUserCAKeys pointed at a certificate silently
    # trusts nothing.
    ca_key = values["SSH_USER_CA_PUBLIC_KEY"]
    if ca_key:
        if "-cert-v01@openssh.com" in ca_key:
            raise ValueError(
                f"{CONFIG_FILE}: SSH_USER_CA_PUBLIC_KEY is a signed certificate, not a CA "
                "public key. Read the CA public half: "
                "curl -fsS https://<openbao>/v1/ssh/public_key"
            )
        if not re.fullmatch(
            r"(ssh-ed25519|ssh-rsa|ecdsa-sha2-[a-z0-9-]+) [A-Za-z0-9+/]+=*( .*)?",
            ca_key,
        ):
            raise ValueError(
                f"{CONFIG_FILE}: SSH_USER_CA_PUBLIC_KEY is not an OpenSSH public key"
            )

    # Refuse a template nobody can reach. Either anchor alone is fine; neither is not.
    if not values["SSH_PUBLIC_KEY_FILE"] and not ca_key:
        raise ValueError(
            f"{CONFIG_FILE}: set SSH_PUBLIC_KEY_FILE, SSH_USER_CA_PUBLIC_KEY, or both. "
            "With neither, the built template has no way to authenticate anyone and the "
            "first boot fails on purpose rather than producing an unreachable VM."
        )

    # A bad timezone only surfaces at first boot, where it is expensive to see.
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9+_-]*(?:/[A-Za-z0-9+_-]+){0,2}", values["TIMEZONE"]):
        raise ValueError(f"{CONFIG_FILE}: TIMEZONE is not a valid IANA zone name")

    if not re.fullmatch(r"0x[0-9A-Fa-f]{16}", values["APPDATA_WWN"]):
        raise ValueError(
            f"{CONFIG_FILE}: APPDATA_WWN must be 0x followed by 16 hex digits"
        )
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", values["APPDATA_SERIAL"]):
        raise ValueError(
            f"{CONFIG_FILE}: APPDATA_SERIAL contains unsupported characters"
        )

    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,48}", values["NAME_PREFIX"]):
        raise ValueError(
            f"{CONFIG_FILE}: NAME_PREFIX must be lowercase alphanumeric with hyphens"
        )
    for key in ("SNIPPET_STORAGE_NAME", "VM_STORAGE_NAME"):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", values[key]):
            raise ValueError(f"{CONFIG_FILE}: {key} contains unsupported characters")
    if not Path(values["ISO_STORAGE_PATH"]).expanduser().is_absolute():
        raise ValueError(f"{CONFIG_FILE}: ISO_STORAGE_PATH must be an absolute path")

    for key in (
        "VMID_START",
        "CPU",
        "MEM_MIN",
        "MEM_MAX",
        "ROOT_DISK_SIZE",
        "APPDATA_DISK_SIZE",
    ):
        if not values[key].isdigit() or int(values[key]) <= 0:
            raise ValueError(f"{CONFIG_FILE}: {key} must be a positive integer")
    highest = int(values["VMID_START"]) + max(p.vmid_offset for p in profiles)
    if highest > 999999999:
        raise ValueError(f"{CONFIG_FILE}: generated VM IDs exceed Proxmox limits")
    if int(values["MEM_MIN"]) > int(values["MEM_MAX"]):
        raise ValueError(f"{CONFIG_FILE}: MEM_MIN cannot exceed MEM_MAX")

    for key in (
        "LXC_TEMPLATE_STORAGE",
        "LXC_ROOTFS_STORAGE",
        "LXC_APPDATA_STORAGE",
    ):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", values[key]):
            raise ValueError(f"{CONFIG_FILE}: {key} contains unsupported characters")

    for key in (
        "LXC_CTID_START",
        "LXC_ROOT_DISK_SIZE",
        "LXC_APPDATA_DISK_SIZE",
        "LXC_CPU",
        "LXC_MEMORY",
    ):
        if not values[key].isdigit() or int(values[key]) <= 0:
            raise ValueError(f"{CONFIG_FILE}: {key} must be a positive integer")
    # Proxmox accepts a container with no swap, so zero is legal here.
    if not values["LXC_SWAP"].isdigit():
        raise ValueError(
            f"{CONFIG_FILE}: LXC_SWAP must be a non-negative integer"
        )

    # Proxmox rejects IDs below 100 and shares one numberspace between VMs and
    # containers, so an overlapping range would collide at create time rather
    # than at build time, on whichever host happened to have the ID already.
    offsets = [p.vmid_offset for p in profiles]
    ctid_start = int(values["LXC_CTID_START"])
    vmid_start = int(values["VMID_START"])
    if ctid_start < 100:
        raise ValueError(f"{CONFIG_FILE}: LXC_CTID_START must be at least 100")
    if vmid_start < 100:
        raise ValueError(f"{CONFIG_FILE}: VMID_START must be at least 100")
    if ctid_start + max(offsets) > 999999999:
        raise ValueError(
            f"{CONFIG_FILE}: generated container IDs exceed Proxmox limits"
        )
    claimed_vmids = {vmid_start + offset for offset in offsets}
    claimed_ctids = {ctid_start + offset for offset in offsets}
    collisions = sorted(claimed_vmids & claimed_ctids)
    if collisions:
        raise ValueError(
            f"{CONFIG_FILE}: LXC_CTID_START overlaps the VM ID range on {collisions}; "
            "VM and container IDs share one Proxmox numberspace"
        )

    vlan_tag = values["LXC_VLAN_TAG"]
    if vlan_tag and not (vlan_tag.isdigit() and 1 <= int(vlan_tag) <= 4094):
        raise ValueError(
            f"{CONFIG_FILE}: LXC_VLAN_TAG must be a VLAN ID between 1 and 4094"
        )

    if values["LXC_NAMESERVER"]:
        try:
            ipaddress.ip_address(values["LXC_NAMESERVER"])
        except ValueError:
            raise ValueError(
                f"{CONFIG_FILE}: LXC_NAMESERVER is not a valid IP address"
            ) from None

    return values


# Importers read these at module scope, so a bad .env or manifest surfaces here.
# Exit on the message rather than letting a traceback bury it: a misconfigured
# file is the operator's problem to fix, not a bug to report.
try:
    PROFILES = load_profiles()
    CONFIG = load_config(PROFILES)
except ValueError as error:
    raise SystemExit(f"ERROR: {error}") from None

SITE = {key: CONFIG[key] for key in SITE_KEYS}
SSH_ALLOW_USERS = tuple(CONFIG["SSH_ALLOW_USERS"].split())


def _ssh_allow_users_directive() -> str:
    """Render the sshd AllowUsers line, or the comment that stands in for it.

    Both template families write the same sshd drop-in, and both must be safe to
    publish: with no configured sources this is a comment, never a directive.
    """
    if SSH_ALLOW_USERS:
        return "AllowUsers " + " ".join(SSH_ALLOW_USERS)
    return "# AllowUsers source restriction is not configured"


def resolve_config_path(value: str) -> Path:
    """Resolve a path named in .env, relative to the .env file rather than the cwd.

    Shared with build.py so both agree. Relative-to-tools/ is not the obvious reading --
    `./tools/keys.pub` in tools/.env resolves to tools/tools/keys.pub -- so callers report
    the resolved path in their errors rather than the configured string.
    """
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = CONFIG_FILE.parent / path
    return path


def _root_ca_pem() -> str:
    """Read the CA named by KASA_ROOT_CA_FILE, or return "" when unconfigured.

    Structural checks only. The certificate is parsed and its expiry checked in build.py,
    which already shells out to openssl; this module runs no subprocesses.
    """
    configured = CONFIG["KASA_ROOT_CA_FILE"]
    if not configured:
        return ""
    path = resolve_config_path(configured)
    if not path.is_file():
        raise ValueError(
            f"{CONFIG_FILE}: KASA_ROOT_CA_FILE does not exist: {path} "
            f"(configured as {configured!r}, resolved against {CONFIG_FILE.parent})"
        )
    pem = path.read_text(encoding="utf-8").strip()
    if "PRIVATE KEY" in pem:
        raise ValueError(
            f"{path}: contains a private key. KASA_ROOT_CA_FILE is the CA certificate, "
            "which is public; the private half never leaves OpenBao."
        )
    count = pem.count("-----BEGIN CERTIFICATE-----")
    if count != 1:
        raise ValueError(
            f"{path}: expected exactly one PEM certificate, found {count}. The root CA is "
            "a single self-signed certificate, not a chain."
        )
    return pem


try:
    ROOT_CA_PEM = _root_ca_pem()
except ValueError as error:
    # Same shape as the load_config failure above: operators see one ERROR line, not a
    # traceback, because this is a configuration mistake rather than a bug.
    raise SystemExit(f"ERROR: {error}") from None


def _ssh_user_ca_configured() -> bool:
    return bool(CONFIG["SSH_USER_CA_PUBLIC_KEY"])


def expand_template(
    template: Path, flags: dict[str, bool], replacements: dict[str, str]
) -> str:
    """Expand one template in memory.

    Public because build.py renders the Proxmox-side LXC script through the same
    engine: that script needs `#% if docker` so a base profile's `pct create`
    genuinely has no --features argument, rather than one built at run time.

    This module never writes a file. build.py is the only artifact writer, so
    there is exactly one place that decides where generated files land.
    """
    if not template.is_file():
        raise ValueError(f"Template is missing: {template}")

    output: list[str] = []
    active_stack = [True]

    for raw_line in template.read_text(encoding="utf-8").splitlines():
        directive = raw_line.strip()
        if directive.startswith("#% if "):
            flag = directive.removeprefix("#% if ").strip()
            if flag not in flags:
                raise ValueError(f"Unknown template flag: {flag}")
            active_stack.append(active_stack[-1] and flags[flag])
            continue
        if directive == "#% endif":
            if len(active_stack) == 1:
                raise ValueError("Unexpected template endif")
            active_stack.pop()
            continue
        if not active_stack[-1]:
            continue

        line = raw_line

        # A multi-line value -- an armoured GPG key, a PEM certificate, a list of SSH
        # public keys -- has to be re-indented onto every line it produces, or it lands
        # unindented inside a YAML block scalar and the document silently changes shape.
        #
        # Only when the text before the placeholder is *indentation*. That text is repeated
        # on every line, so for `SSH_PUBLIC_KEY=@@SSH_PUBLIC_KEY@@` in a shell script it
        # would prefix each key after the first with a literal `SSH_PUBLIC_KEY=`, producing
        # a file bash still parses and Proxmox then rejects one key at a time. A shell
        # assignment wants the value substituted whole; shlex.quote has already made it a
        # single valid multi-line literal.
        block = next(
            (
                (placeholder, value)
                for placeholder, value in replacements.items()
                if "\n" in value
                and placeholder in line
                and not line[: line.index(placeholder)].strip()
            ),
            None,
        )
        if block is not None:
            placeholder, value = block
            prefix = line[: line.index(placeholder)]
            output.extend(
                f"{prefix}{value_line}" if value_line else prefix.rstrip()
                for value_line in value.splitlines()
            )
            continue

        for placeholder, value in replacements.items():
            line = line.replace(placeholder, value)
        unresolved = re.findall(r"@@[A-Z0-9_]+@@", line)
        if unresolved:
            raise ValueError(f"Unresolved template placeholders: {unresolved}")
        output.append(line)

    if len(active_stack) != 1:
        raise ValueError("Unclosed template conditional")

    compacted: list[str] = []
    for line in output:
        if not line and compacted and not compacted[-1]:
            continue
        compacted.append(line)

    return "\n".join(compacted).rstrip() + "\n"


def profile_flags(profile: Profile) -> dict[str, bool]:
    """Flags a template may test, from the profile and from configuration.

    KNOWN_FLAGS gates what templates/profiles.yaml may declare. This dict gates what a
    template may test, and expand_template checks against this -- so `ssh_user_ca` and
    `kasa_root_ca` are driven by whether the operator configured an anchor, not by which
    profile is building. The profile matrix is unchanged.

    Unconfigured renders the blocks away entirely rather than emitting an empty file. That
    matters twice: an empty /etc/ssh/kasa_user_ca.pub under a live TrustedUserCAKeys is a
    host that looks configured and trusts nothing, and this template is published, so the
    public render must carry no anchor at all.
    """
    return {
        **{flag: flag in profile.flags for flag in KNOWN_FLAGS},
        "ssh_user_ca": _ssh_user_ca_configured(),
        "kasa_root_ca": bool(ROOT_CA_PEM),
        # Whether any operator key is injected at all. A CA-only build must not pass
        # --sshkeys, and must not assert that Proxmox generated authorized keys it was
        # never given.
        "ssh_public_key": bool(CONFIG["SSH_PUBLIC_KEY_FILE"]),
    }


def render(profile: Profile, release: str = DEFAULT_RELEASE, **extra: str) -> str:
    """Render one profile's cloud-config in memory."""
    replacements = {
        "@@PROFILE_NAME@@": profile.name,
        "@@PROFILE_DESCRIPTION@@": profile.description,
        "@@RELEASE@@": release,
        "@@FAIL2BAN_IGNORE_IPS@@": SITE["FAIL2BAN_IGNORE_IPS"],
        "@@SYSLOG_SERVER@@": SITE["SYSLOG_SERVER"],
        "@@SYSLOG_PORT@@": SITE["SYSLOG_PORT"],
        "@@TIMEZONE@@": SITE["TIMEZONE"],
        "@@APPDATA_WWN@@": SITE["APPDATA_WWN"],
        "@@APPDATA_SERIAL@@": SITE["APPDATA_SERIAL"],
        "@@SSH_ALLOW_USERS_DIRECTIVE@@": _ssh_allow_users_directive(),
        "@@SSH_USER_CA_PUBLIC_KEY@@": CONFIG["SSH_USER_CA_PUBLIC_KEY"],
        "@@KASA_ROOT_CA_PEM@@": ROOT_CA_PEM,
        "@@DOCKER_GPG_KEY@@": DOCKER_KEY.read_text(encoding="utf-8"),
    }
    replacements.update({f"@@{key}@@": value for key, value in extra.items()})
    return expand_template(
        TEMPLATES / release / CLOUD_CONFIG_TEMPLATE,
        profile_flags(profile),
        replacements,
    )


def render_lxc(profile: Profile, release: str = DEFAULT_RELEASE, **extra: str) -> str:
    """Render one profile's LXC guest bootstrap in memory.

    APPDATA_WWN and APPDATA_SERIAL are deliberately absent. A container never
    sees a raw device, so a bootstrap that referenced them would be describing a
    disk it cannot reach; leaving them out means such a template fails to render
    rather than emitting a check that can never pass.
    """
    replacements = {
        "@@PROFILE_NAME@@": profile.name,
        "@@PROFILE_DESCRIPTION@@": profile.description,
        "@@RELEASE@@": release,
        "@@FAIL2BAN_IGNORE_IPS@@": SITE["FAIL2BAN_IGNORE_IPS"],
        "@@SYSLOG_SERVER@@": SITE["SYSLOG_SERVER"],
        "@@SYSLOG_PORT@@": SITE["SYSLOG_PORT"],
        "@@TIMEZONE@@": SITE["TIMEZONE"],
        "@@APPDATA_MOUNT@@": APPDATA_MOUNT,
        "@@SSH_ALLOW_USERS_DIRECTIVE@@": _ssh_allow_users_directive(),
        "@@SSH_USER_CA_PUBLIC_KEY@@": CONFIG["SSH_USER_CA_PUBLIC_KEY"],
        "@@KASA_ROOT_CA_PEM@@": ROOT_CA_PEM,
        "@@DOCKER_GPG_KEY@@": DOCKER_KEY.read_text(encoding="utf-8"),
    }
    replacements.update({f"@@{key}@@": value for key, value in extra.items()})
    return expand_template(
        TEMPLATES / release / LXC_BOOTSTRAP_TEMPLATE,
        profile_flags(profile),
        replacements,
    )
