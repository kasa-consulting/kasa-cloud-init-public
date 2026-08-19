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


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "templates"
DOCKER_KEY = ROOT / "assets" / "docker-release.asc"
PROFILE_MANIFEST = ROOT / "profiles.yaml"
LOCAL_CONFIG = ROOT / "tools" / ".env"
EXAMPLE_CONFIG = ROOT / "tools" / "env.example"
PRIVATE_SOURCE_MARKER = ROOT / ".kasa-private-source"

DEFAULT_RELEASE = "deb13"

# Flags a template may test with `#% if <flag>`.
KNOWN_FLAGS = frozenset({"docker", "remote_syslog"})

SITE_KEYS = {
    "BRIDGE",
    "SYSLOG_SERVER",
    "SYSLOG_PORT",
    "FAIL2BAN_IGNORE_IPS",
    "TIMEZONE",
    "APPDATA_WWN",
    "APPDATA_SERIAL",
    "SSH_ALLOW_USERS",
}
BUILD_KEYS = {
    "VMID_START",
    "NAME_PREFIX",
    "SSH_PUBLIC_KEY_FILE",
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
CONFIG_KEYS = SITE_KEYS | BUILD_KEYS


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


def template_name(profile: Profile, release: str, prefix: str) -> str:
    """Build the Proxmox template name from release and profile capabilities."""
    role = "docker" if profile.docker else "base"
    syslog_suffix = "-syslog" if profile.remote_syslog else ""
    return f"{prefix}-{release}-{role}{syslog_suffix}"


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
    document = yaml.safe_load(image_file.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"{image_file}: expected a mapping")
    missing = {"codename", "build", "name", "url", "sha512"} - document.keys()
    if missing:
        raise ValueError(f"{image_file}: missing keys: {sorted(missing)}")

    sha512 = str(document["sha512"]).strip()
    if not re.fullmatch(r"[0-9a-f]{128}", sha512):
        raise ValueError(f"{image_file}: sha512 must be 128 lowercase hex digits")
    url = str(document["url"]).strip()
    if not url.startswith("https://"):
        raise ValueError(f"{image_file}: url must be https")

    return Image(
        codename=str(document["codename"]).strip(),
        build=str(document["build"]).strip(),
        name=str(document["name"]).strip(),
        url=url,
        sha512=sha512,
    )


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
            raw_value, line_number, allow_empty=key == "SSH_ALLOW_USERS"
        )

    missing = sorted(CONFIG_KEYS - values.keys())
    if missing:
        raise ValueError(f"{CONFIG_FILE}: missing required keys: {missing}")

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


def render(profile: Profile, release: str = DEFAULT_RELEASE, **extra: str) -> str:
    """Render one profile's cloud-config in memory.

    This module never writes a file. build.py is the only artifact writer, so
    there is exactly one place that decides where generated files land.
    """
    template = TEMPLATES / release / "cloud-config.yml.tmpl"
    if not template.is_file():
        raise ValueError(f"Template is missing: {template}")

    flags = {flag: flag in profile.flags for flag in KNOWN_FLAGS}
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
        "@@SSH_ALLOW_USERS_DIRECTIVE@@": (
            "AllowUsers " + " ".join(SSH_ALLOW_USERS)
            if SSH_ALLOW_USERS
            else "# AllowUsers source restriction is not configured"
        ),
    }
    replacements.update({f"@@{key}@@": value for key, value in extra.items()})

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
        for placeholder, value in replacements.items():
            line = line.replace(placeholder, value)
        if "@@DOCKER_GPG_KEY@@" in line:
            prefix = line[: line.index("@@DOCKER_GPG_KEY@@")]
            output.extend(
                f"{prefix}{key_line}" if key_line else prefix.rstrip()
                for key_line in DOCKER_KEY.read_text(encoding="utf-8").splitlines()
            )
        else:
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
