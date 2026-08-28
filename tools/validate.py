#!/usr/bin/env python3
"""Validate the rendered agent profiles before anything is written or built.

The checks here assert the absence of the wrong thing as much as the presence
of the right one: most of the failure modes this image has are things that
silently come back (a disk spool, a rootful daemon, a persistent journal)
rather than things that go missing.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import shutil
import subprocess
import sys

import yaml

from build import (
    lxc_artifacts,
    render_command,
    validate_generated_command,
    validate_generated_lxc,
    vendor_artifacts,
)
import debian_image_updater
from image_pin import load_image_pin
import render as render_module
import ubuntu_image_updater
from render import (
    CONFIG,
    DEFAULT_RELEASE,
    PROFILES,
    RELEASES,
    ROOT,
    SITE,
    TEMPLATES,
    SSH_ALLOW_USERS,
    Profile,
    load_image,
    load_release,
    lxc_template_name,
    render,
    template_name,
)


STUB_PROVENANCE = {
    "SOURCE_COMMIT": "0" * 40,
    "SOURCE_TREE_DIRTY": "false",
    "BUILT_AT": "1970-01-01T00:00:00+00:00",
}

TEST_SSH_PUBLIC_KEY = (
    "ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAIB4YrFhM2yPVzO+3kI14mYw3V91sCi1qdtB2bWjBv7E4 "
    "bundle-validation@example.invalid"
)

STRICT_RP_FILTER_KEYS = (
    "net.ipv4.conf.all.rp_filter",
    "net.ipv4.conf.default.rp_filter",
)
HARDENING_SYSCTL_PATH = "/etc/sysctl.d/60-hardening.conf"
VENDOR_SYSCTL_BASELINE = "50-default.conf"

# The sshd drop-ins, in the order OpenSSH reads them. 60- before 99- matters: OpenSSH
# takes the first value it sees for most keywords, so the CA drop-in must not be able to
# shadow the hardening one.
HARDENING_SSHD_PATH = "/etc/ssh/sshd_config.d/99-harden.conf"
SSH_USER_CA_KEY_PATH = "/etc/ssh/kasa_user_ca.pub"
SSH_USER_CA_DROPIN_PATH = "/etc/ssh/sshd_config.d/60-kasa-user-ca.conf"

# Same shape kasa-ansible/roles/kasa_ssh_ca asserts, so a key one accepts and the other
# rejects cannot exist.
OPENSSH_PUBLIC_KEY = r"(ssh-ed25519|ssh-rsa|ecdsa-sha2-[a-z0-9-]+) [A-Za-z0-9+/]+=*( .*)?"

# Paths that must appear only in the docker profile.
DOCKER_ONLY_PATHS = (
    "/etc/apt/sources.list.d/docker.sources",
    "/etc/systemd/system/user@.service.d/10-delegate.conf",
    "/etc/modules-load.d/60-rootless-docker.conf",
    "/etc/tmpfiles.d/60-appdata-docker.conf",
    "/home/admin/.config/docker/daemon.json",
    "/home/admin/.config/systemd/user/docker.service.d/10-require-appdata.conf",
)

APPDATA_PATHS = (
    "/usr/local/sbin/appdata-verify",
    "/etc/systemd/system/appdata-verify.service",
)

REMOTE_SYSLOG_PATHS = (
    "/etc/systemd/journald.conf.d/60-remote-syslog.conf",
    "/etc/rsyslog.d/01-remote.conf",
    "/etc/fail2ban/fail2ban.local",
)

# Cloud-init fills a short or None-holding mounts row from mount_default_fields,
# at every index. cc_mounts.sanitize_mounts_configuration() substitutes
# default_fields[index] for each None token and appends default_fields for each
# missing trailing field, so fs_spec and fs_file inherit exactly like the rest.
# The upstream default vfstype is "auto", so a row can mount a tmpfs without the
# word tmpfs appearing in the row itself.
CLOUD_INIT_MOUNT_DEFAULT_FIELDS = (None, None, "auto", "defaults,nofail", "0", "2")

# A tmpfs on /var/log hides every directory a package created at install time,
# which breaks nginx, Apache, Supervisor and friends across reboot. A persistent
# filesystem mounted there is fine and must keep validating, so these match the
# backing store rather than the name of any unit or mountpoint.
VAR_LOG_TMPFS_COMMANDS = (
    re.compile(r"\bmount\b.*-t[ \t]+tmpfs.*/var/log"),
    re.compile(r"\bmount\b.*/var/log.*-t[ \t]+tmpfs"),
    re.compile(r"\bsystemd-mount\b.*--tmpfs.*/var/log"),
)

REQUIRED_RSYSLOG_FRAGMENTS = (
    'load="imjournal"',
    'StateFile="/run/rsyslog/imjournal.state"',
    'Ratelimit.Interval="60"',
    'Ratelimit.Burst="25000"',
    'type="omfwd"',
    'protocol="tcp"',
    'TCP_Framing="traditional"',
    'template="RSYSLOG_SyslogProtocol23Format"',
    'queue.type="LinkedList"',
    'queue.timeoutEnqueue="0"',
    'queue.saveOnShutdown="off"',
    'queue.discardSeverity="7"',
)

# Naming a spool file is what makes an rsyslog queue disk-assisted. A
# memory-only forwarding queue is a stated property of the remote-syslog
# profiles, so these are build failures.
FORBIDDEN_RSYSLOG_FRAGMENTS = (
    "queue.filename",
    "queue.maxDiskSpace",
    "workDirectory",
    "/var/spool/",
)

# Plain TCP is a deliberate, documented choice. A half-configured TLS setup is
# worse than none, so adding any of these must be an explicit, reviewed change.
FORBIDDEN_TLS_FRAGMENTS = (
    "DefaultNetstreamDriverCAFile",
    "StreamDriver",
    "x509/",
    "ossl",
    "gtls",
)

errors: list[str] = []


def report(profile: str, message: str) -> None:
    errors.append(f"{profile}: {message}")


class UniqueKeyLoader(yaml.SafeLoader):
    """Reject duplicate mapping keys instead of silently keeping the last one."""


def _no_duplicates(loader: UniqueKeyLoader, node: yaml.MappingNode) -> dict:
    seen: set = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=True)
        if key in seen:
            raise yaml.YAMLError(f"duplicate key in cloud-config: {key}")
        seen.add(key)
    return loader.construct_mapping(node, deep=True)


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_duplicates
)


def files_by_path(document: dict) -> dict[str, dict]:
    return {entry["path"]: entry for entry in document.get("write_files", [])}


def strip_comments(text: str) -> str:
    return "\n".join(
        line for line in text.splitlines() if not line.strip().startswith("#")
    )


def validate_ssh_source_restriction(profile: Profile, document: dict) -> None:
    """Require the exact additive AllowUsers policy on every profile."""
    name = profile.name
    sshd = files_by_path(document).get(
        HARDENING_SSHD_PATH, {}
    ).get("content", "")
    entries: list[str] = []
    for line in strip_comments(sshd).splitlines():
        fields = line.split()
        if fields and fields[0].lower() == "allowusers":
            # OpenSSH appends every AllowUsers occurrence, so validate the
            # combined effective list rather than only one physical line.
            entries.extend(fields[1:])

    if len(entries) != len(SSH_ALLOW_USERS) or set(entries) != set(SSH_ALLOW_USERS):
        report(
            name,
            "AllowUsers must match the private policy exactly: "
            + (" ".join(SSH_ALLOW_USERS) or "no active entries"),
        )


def validate_strict_rp_filter(profile: Profile, document: dict) -> None:
    """Require strict rp_filter values to win generated sysctl load order."""
    name = profile.name
    files = files_by_path(document)
    hardening = files.get(HARDENING_SYSCTL_PATH, {}).get("content", "")
    active = strip_comments(hardening)
    hardening_name = Path(HARDENING_SYSCTL_PATH).name

    if hardening_name <= VENDOR_SYSCTL_BASELINE:
        report(
            name,
            f"{HARDENING_SYSCTL_PATH} must sort after {VENDOR_SYSCTL_BASELINE}",
        )

    for key in STRICT_RP_FILTER_KEYS:
        values = re.findall(
            rf"^\s*{re.escape(key)}\s*=\s*(\S+)\s*$",
            active,
            re.MULTILINE,
        )
        if values != ["1"]:
            report(
                name,
                f"{key} must have exactly one active strict-mode assignment (= 1); "
                f"found {values}",
            )

        for path, entry in sorted(files.items()):
            candidate = Path(path)
            if (
                candidate.parent.name != "sysctl.d"
                or candidate.suffix != ".conf"
                or candidate.name <= hardening_name
            ):
                continue
            later_values = re.findall(
                rf"^\s*{re.escape(key)}\s*=\s*(\S+)\s*$",
                strip_comments(entry.get("content", "")),
                re.MULTILINE,
            )
            if later_values:
                report(
                    name,
                    f"{path} sorts after {HARDENING_SYSCTL_PATH} and reassigns "
                    f"{key}: {later_values}",
                )


def validate_ssh_user_ca(profile: Profile, document: dict) -> None:
    """Check SSH user CA trust: both files or neither, and exactly one directive.

    The failure this exists to prevent is a host that looks configured and trusts
    nothing -- a live TrustedUserCAKeys pointing at a file that is absent, empty or
    malformed. sshd -t exits 0 in every one of those cases.

    Paths and content must match kasa-ansible/roles/kasa_ssh_ca, which writes the same
    files on the same hosts. A difference there makes that role rewrite them and reload
    sshd on every host this template builds.
    """
    name = profile.name
    files = files_by_path(document)
    key_entry = files.get(SSH_USER_CA_KEY_PATH)
    dropin_entry = files.get(SSH_USER_CA_DROPIN_PATH)

    configured = bool(CONFIG["SSH_USER_CA_PUBLIC_KEY"])
    if not configured:
        # Nothing may appear from anywhere but configuration. A hardcoded anchor would
        # reach the public mirror, which publishes this template.
        for path, entry in ((SSH_USER_CA_KEY_PATH, key_entry),
                            (SSH_USER_CA_DROPIN_PATH, dropin_entry)):
            if entry is not None:
                report(name, f"{path} is present but SSH_USER_CA_PUBLIC_KEY is not set")
        return

    if key_entry is None or dropin_entry is None:
        missing = SSH_USER_CA_KEY_PATH if key_entry is None else SSH_USER_CA_DROPIN_PATH
        report(
            name,
            f"SSH user CA trust is half-installed: {missing} is missing. The key and the "
            "sshd drop-in must appear together or not at all.",
        )
        return

    key_lines = [
        line.strip()
        for line in key_entry.get("content", "").splitlines()
        if line.strip()
    ]
    if len(key_lines) != 1:
        report(
            name,
            f"{SSH_USER_CA_KEY_PATH} must hold exactly one public key line, "
            f"found {len(key_lines)}",
        )
    elif "-cert-v01@openssh.com" in key_lines[0]:
        report(name, f"{SSH_USER_CA_KEY_PATH} holds a certificate, not a CA public key")
    elif not re.fullmatch(OPENSSH_PUBLIC_KEY, key_lines[0]):
        report(name, f"{SSH_USER_CA_KEY_PATH} is not an OpenSSH public key")
    elif key_lines[0] != CONFIG["SSH_USER_CA_PUBLIC_KEY"].strip():
        report(
            name,
            f"{SSH_USER_CA_KEY_PATH} does not match SSH_USER_CA_PUBLIC_KEY. The anchor "
            "must come from configuration, so a hardcoded key cannot reach the published "
            "template.",
        )

    directives = [
        line.strip()
        for line in strip_comments(dropin_entry.get("content", "")).splitlines()
        if line.strip()
    ]
    expected = [f"TrustedUserCAKeys {SSH_USER_CA_KEY_PATH}"]
    if directives != expected:
        report(
            name,
            f"{SSH_USER_CA_DROPIN_PATH} must contain exactly {expected}, found {directives}",
        )

    # AllowUsers and AuthenticationMethods belong to 99-harden.conf, whose source of
    # truth is SSH_ALLOW_USERS. Emitting either here forks that, and OpenSSH takes the
    # first value it sees -- so the fork would win.
    for forbidden in (
        "AllowUsers",
        "AuthenticationMethods",
        "PasswordAuthentication",
        "PermitRootLogin",
    ):
        if any(re.match(rf"(?i){forbidden}\b", line) for line in directives):
            report(
                name,
                f"{SSH_USER_CA_DROPIN_PATH} must not set {forbidden}; that belongs to "
                f"{HARDENING_SSHD_PATH}",
            )

    if Path(SSH_USER_CA_DROPIN_PATH).name >= Path(HARDENING_SSHD_PATH).name:
        report(
            name,
            f"{SSH_USER_CA_DROPIN_PATH} must sort before {HARDENING_SSHD_PATH}",
        )

    finalize = files.get("/usr/local/sbin/cloud-init-finalize", {}).get("content", "")
    for required in (
        f"ssh-keygen -l -f {SSH_USER_CA_KEY_PATH}",
        "trustedusercakeys",
    ):
        if required not in finalize:
            report(
                name,
                f"finalize must prove the CA trust is live; missing: {required}",
            )


def validate_ca_certs(profile: Profile, document: dict) -> None:
    """Check the X.509 trust anchor block.

    remove_defaults is the dangerous one: it drops Debian's CA bundle, which breaks apt
    over HTTPS and every other fetch in the same boot -- and it fails at first boot on a
    clone, not at build time.
    """
    name = profile.name
    anchors = document.get("ca_certs")
    configured = bool(CONFIG["KASA_ROOT_CA_FILE"])

    if anchors is None:
        if configured:
            report(name, "KASA_ROOT_CA_FILE is set but the render has no ca_certs block")
        return
    if not configured:
        report(name, "ca_certs is present but KASA_ROOT_CA_FILE is not set")
        return
    if not isinstance(anchors, dict):
        report(name, "ca_certs must be a mapping")
        return
    if anchors.get("remove_defaults"):
        report(
            name,
            "ca_certs must not set remove_defaults: dropping Debian's CA bundle breaks "
            "apt over HTTPS in the same boot",
        )

    trusted = anchors.get("trusted")
    if not isinstance(trusted, list) or not trusted:
        report(name, "ca_certs.trusted must be a non-empty list")
        return
    for entry in trusted:
        if not isinstance(entry, str):
            report(name, "ca_certs.trusted entries must be PEM strings")
            continue
        if "PRIVATE KEY" in entry:
            report(name, "ca_certs.trusted contains a private key")
        count = entry.count("-----BEGIN CERTIFICATE-----")
        if count != 1:
            report(
                name,
                f"ca_certs.trusted entry must hold exactly one PEM certificate, "
                f"found {count}",
            )


def validate_common(
    profile: Profile, document: dict, rendered: str, release: str
) -> None:
    name = profile.name

    for key, expected in (
        ("ssh_pwauth", False),
        ("disable_root", True),
        ("package_update", True),
        ("package_upgrade", True),
        ("preserve_hostname", False),
        ("resize_rootfs", True),
    ):
        if document.get(key) != expected:
            report(name, f"{key} must be {expected!r}, found {document.get(key)!r}")

    if document.get("timezone") != SITE["TIMEZONE"]:
        report(name, "timezone does not match TIMEZONE from .env")

    if document.get("growpart") != {"mode": "auto"}:
        report(name, "growpart must explicitly use auto mode")

    if document.get("runcmd") != [["/usr/local/sbin/cloud-init-finalize"]]:
        report(name, "runcmd must invoke only /usr/local/sbin/cloud-init-finalize")

    packages = document.get("packages", [])
    if len(packages) != len(set(packages)):
        report(name, "duplicate entries in packages")
    required_packages = {
        "cloud-guest-utils",
        "fail2ban",
        "nftables",
        "qemu-guest-agent",
        "rsyslog",
        "unattended-upgrades",
    }
    if release == "deb13":
        required_packages.add("systemd-zram-generator")
    for required in required_packages:
        if required not in packages:
            report(name, f"missing required package: {required}")

    files = files_by_path(document)
    required_paths = {
        "/etc/kasa-image-release",
        "/etc/ssh/sshd_config.d/99-harden.conf",
        HARDENING_SYSCTL_PATH,
        "/etc/fail2ban/jail.local",
        "/usr/local/sbin/cloud-init-finalize",
        "/usr/local/sbin/cloud-init-post-verify",
        "/etc/systemd/system/cloud-init-post-verify.service",
    }
    if release == "deb13":
        required_paths.add("/etc/systemd/zram-generator.conf")
    for required_path in required_paths:
        if required_path not in files:
            report(name, f"missing required file: {required_path}")

    for entry in document.get("write_files", []):
        if "owner" not in entry or "permissions" not in entry:
            report(name, f"{entry['path']}: owner and permissions must be explicit")
        elif not isinstance(entry["permissions"], str):
            report(
                name,
                f"{entry['path']}: permissions must be quoted so 0644 is not octal-parsed",
            )

    sshd = files.get(HARDENING_SSHD_PATH, {}).get("content", "")
    for directive in (
        "PasswordAuthentication no",
        "PermitRootLogin no",
        "AuthenticationMethods publickey",
        "KbdInteractiveAuthentication no",
        "MaxAuthTries 3",
    ):
        if directive not in sshd:
            report(name, f"sshd hardening is missing: {directive}")

    hardening = files.get(HARDENING_SYSCTL_PATH, {}).get("content", "")
    for setting in (
        "kernel.kptr_restrict = 2",
        "kernel.yama.ptrace_scope = 1",
        "net.ipv4.tcp_syncookies = 1",
        "net.ipv4.conf.*.accept_redirects = 0",
        "net.ipv4.conf.*.send_redirects = 0",
        "net.ipv6.conf.*.accept_redirects = 0",
    ):
        if setting not in hardening:
            report(name, f"kernel hardening is missing: {setting}")
    # Rootless Docker needs unprivileged user namespaces. A future tightening
    # pass that adds one of these would break the docker profile at boot.
    for forbidden in ("max_user_namespaces", "apparmor_restrict_unprivileged_userns"):
        if forbidden in hardening:
            report(name, f"{forbidden} breaks rootless Docker; do not restrict userns")

    finalize = files.get("/usr/local/sbin/cloud-init-finalize", {}).get("content", "")
    if "/usr/lib/systemd/systemd-sysctl" not in finalize:
        report(name, "finalize must apply systemd sysctl glob settings")
    for fragment in (
        "for rp_filter_key in",
        *STRICT_RP_FILTER_KEYS,
        'rp_filter_value="$(/usr/sbin/sysctl -n "$rp_filter_key")"',
        '[ "$rp_filter_value" = 1 ]',
    ):
        if fragment not in finalize:
            report(name, f"finalize live rp_filter verification is missing: {fragment}")

    zram_path = "/etc/systemd/zram-generator.conf"
    if release == "deb13":
        zram = files.get(zram_path, {}).get("content", "")
        if "compression-algorithm = zstd" not in zram or "zram-size" not in zram:
            report(name, "zram generator configuration is incomplete")
    elif "systemd-zram-generator" in packages or zram_path in files:
        report(name, "Ubuntu must not carry an unusable zram generator configuration")

    jail = files.get("/etc/fail2ban/jail.local", {}).get("content", "")
    if SITE["FAIL2BAN_IGNORE_IPS"] not in jail:
        report(name, "fail2ban ignoreip does not match FAIL2BAN_IGNORE_IPS")
    if "backend = systemd" not in jail:
        report(name, "fail2ban must read the journal, not a log file")

    finalize = files.get("/usr/local/sbin/cloud-init-finalize", {}).get("content", "")
    if "passwd --lock admin" not in finalize:
        report(name, "finalize must lock the admin password")
    if "ssh-keygen -l -f /home/admin/.ssh/authorized_keys" not in finalize:
        report(name, "finalize must validate the supplied SSH key")
    if "set -Eeuo pipefail" not in finalize:
        report(name, "finalize must use set -Eeuo pipefail")
    for required in (
        "/usr/sbin/rsyslogd -N1",
        "systemctl enable rsyslog.service",
        "systemctl restart rsyslog.service",
        "systemctl is-active --quiet rsyslog.service",
    ):
        if required not in finalize:
            report(name, f"logging setup is missing: {required}")

    post_verify = files.get("/usr/local/sbin/cloud-init-post-verify", {}).get(
        "content", ""
    )
    for required in ('touch "$success_marker"',):
        if required not in post_verify:
            report(
                name,
                f"post-verify is missing successful completion step: {required}",
            )
    post_verify_code = strip_comments(post_verify)
    if "/usr/local/sbin/cloud-init-report success" in post_verify_code:
        report(name, "post-verify must not dump logs after successful bootstrap")
    for forbidden in ("shutdown", "poweroff"):
        if forbidden in post_verify_code:
            report(name, f"post-verify must leave the VM running: found {forbidden}")

    service = files.get(
        "/etc/systemd/system/cloud-init-post-verify.service", {}
    ).get("content", "")
    if "ConditionPathExists=!/var/lib/cloud/instance/boot-success" not in service:
        report(
            name,
            "post-verify must be gated on the absent boot-success marker, "
            "or every clone would power itself off",
        )

    if "@@" in rendered:
        report(name, "rendered output still contains @@ placeholders")


def validate_image_release(
    profile: Profile, document: dict, release: str = DEFAULT_RELEASE
) -> None:
    name = profile.name
    content = files_by_path(document).get("/etc/kasa-image-release", {}).get(
        "content", ""
    )
    keys = {
        line.split("=", 1)[0]
        for line in content.splitlines()
        if "=" in line
    }
    expected = {
        "ID",
        "DESCRIPTION",
        "RELEASE",
        "OS",
        "OS_VERSION",
        "OS_CODENAME",
        "IMAGE_BUILD",
        "SOURCE_COMMIT",
        "SOURCE_TREE_DIRTY",
        "BUILT_AT",
    }
    missing = sorted(expected - keys)
    if missing:
        report(name, f"/etc/kasa-image-release is missing keys: {missing}")
    # Provenance, not a versioning scheme: template names are stable and a
    # rebuild replaces, so a version key here would imply a guarantee we do
    # not make.
    if "TEMPLATE_VERSION" in keys:
        report(name, "/etc/kasa-image-release must not carry TEMPLATE_VERSION")
    if f"ID={profile.name}" not in content:
        report(name, "/etc/kasa-image-release ID does not match the profile")
    release_info = load_release(release)
    for field, expected_value in (
        ("RELEASE", release_info.name),
        ("OS", release_info.os),
        ("OS_VERSION", release_info.version),
        ("OS_CODENAME", release_info.codename),
    ):
        if f"{field}={expected_value}" not in content.splitlines():
            report(name, f"/etc/kasa-image-release {field} does not match {release}")


def validate_rsyslog(profile: Profile, document: dict) -> None:
    name = profile.name
    content = files_by_path(document).get("/etc/rsyslog.d/01-remote.conf", {}).get(
        "content", ""
    )
    if not profile.remote_syslog:
        if content:
            report(name, "local logging profile must not configure remote forwarding")
        return

    if not content:
        report(name, "remote syslog forwarding is not configured")
        return

    for fragment in REQUIRED_RSYSLOG_FRAGMENTS:
        if fragment not in content:
            report(name, f"rsyslog forwarder is missing {fragment}")
    if f'target="{SITE["SYSLOG_SERVER"]}"' not in content:
        report(name, "rsyslog target does not match SYSLOG_SERVER")
    if f'port="{SITE["SYSLOG_PORT"]}"' not in content:
        report(name, "rsyslog port does not match SYSLOG_PORT")
    if not content.rstrip().endswith("stop"):
        report(name, "rsyslog config must end with stop, or logs land in /var/log")

    body = strip_comments(content)
    for fragment in FORBIDDEN_RSYSLOG_FRAGMENTS:
        if fragment in body:
            report(name, f"rsyslog must not spool to disk: found {fragment}")
    for fragment in FORBIDDEN_TLS_FRAGMENTS:
        if fragment in body:
            report(name, f"rsyslog TLS is not configured here: found {fragment}")


def _mount_unit_is_var_log_tmpfs(content: str) -> bool:
    """Does this systemd mount unit put a tmpfs on /var/log?

    Type= is optional in a mount unit — systemd can determine the filesystem
    automatically — so What=tmpfs alone is still the prohibited configuration.
    """
    body = strip_comments(content)
    directives = {
        line.strip().replace(" ", "") for line in body.splitlines() if "=" in line
    }
    if "Where=/var/log" not in directives:
        return False
    return "Type=tmpfs" in directives or "What=tmpfs" in directives


def _mounts_row_is_var_log_tmpfs(row: object, defaults: list) -> bool:
    """Does this cloud-init mounts row resolve to a tmpfs on /var/log?

    Every one of the three fields inherits from mount_default_fields, fs_spec and
    fs_file included. Verified against cloud-init 25.1.4, the version Debian 13
    ships and the pinned image carries: sanitize_mounts_configuration() replaces
    each None token with default_fields[index] and appends default_fields for
    every missing trailing field, both without exempting index 0 or 1.

    The upstream schema says a declaration with only fs_spec and no fs_file is
    skipped, which is true only while mount_default_fields[1] is None — its stock
    value. remove_nonexistent_devices() tests line[1] after the default has
    already been substituted, so a configuration naming a mountpoint there makes
    ["tmpfs"] a real mount. Resolving only fs_vfstype from the defaults would let
    that configuration validate while the shipped runtime still mounts the tmpfs.
    """
    if not isinstance(row, (list, tuple)):
        return False
    resolved = []
    for index in range(3):
        value = row[index] if index < len(row) else None
        if value is None:
            value = defaults[index] if index < len(defaults) else None
        resolved.append(str(value) if value is not None else "")
    fs_spec, fs_file, fs_vfstype = resolved
    if fs_file.rstrip("/") != "/var/log":
        return False
    return "tmpfs" in (fs_spec, fs_vfstype)


def validate_var_log_persistence(profile: Profile, document: dict) -> None:
    """Reject a tmpfs-backed /var/log on every profile.

    The invariant is the backing store, not the name of a unit or mountpoint: a
    persistent filesystem mounted at /var/log satisfies the durability contract
    and must keep validating.
    """
    name = profile.name

    for entry in document.get("write_files", []):
        if _mount_unit_is_var_log_tmpfs(entry.get("content", "")):
            report(
                name,
                f"{entry['path']}: mounts a tmpfs on /var/log, which hides "
                "package-created log directories across reboot",
            )

    defaults = document.get("mount_default_fields")
    if not isinstance(defaults, (list, tuple)):
        defaults = CLOUD_INIT_MOUNT_DEFAULT_FIELDS
    for row in document.get("mounts", []) or []:
        if _mounts_row_is_var_log_tmpfs(row, list(defaults)):
            report(name, f"mounts row puts a tmpfs on /var/log: {row}")

    commands = [document.get("bootcmd", []), document.get("runcmd", [])]
    texts = [
        entry.get("content", "") for entry in document.get("write_files", [])
    ]
    for command in commands:
        for item in command or []:
            texts.append(item if isinstance(item, str) else " ".join(map(str, item)))
    for text in texts:
        for line in strip_comments(text).splitlines():
            if any(pattern.search(line) for pattern in VAR_LOG_TMPFS_COMMANDS):
                report(name, f"command mounts a tmpfs on /var/log: {line.strip()}")


def validate_remote_syslog(
    profile: Profile, document: dict, release: str = DEFAULT_RELEASE
) -> None:
    """Check the profile-level remote-logging contract.

    Its three enforceable properties are a volatile journal, a forwarding queue
    with no disk spool, and fail2ban ban state under /run. /var/log persistence
    is profile-agnostic and belongs to validate_var_log_persistence.
    """
    name = profile.name
    files = files_by_path(document)

    if not profile.remote_syslog:
        for path in REMOTE_SYSLOG_PATHS:
            if path in files:
                report(name, f"local logging profile must not include {path}")
        finalize = files.get("/usr/local/sbin/cloud-init-finalize", {}).get(
            "content", ""
        )
        for forbidden in (
            "systemctl restart systemd-journald.service",
            "/run/rsyslog/imjournal.state",
            "remote syslog forwarding smoke test",
            "</dev/tcp/",
        ):
            if forbidden in finalize:
                report(
                    name,
                    f"local logging profile contains remote-only step: {forbidden}",
                )
        return

    for path in REMOTE_SYSLOG_PATHS:
        if path not in files:
            report(name, f"remote logging is missing {path}")

    journald = files.get(
        "/etc/systemd/journald.conf.d/60-remote-syslog.conf", {}
    ).get("content", "")
    if "Storage=volatile" not in journald:
        report(name, "journald Storage must be volatile")
    if "ForwardToSyslog=no" not in journald:
        report(name, "journald must not forward to syslog; rsyslog reads the journal")

    if release == "ubuntu24":
        tmpfiles = files.get("/etc/tmpfiles.d/60-kasa-rsyslog.conf", {}).get(
            "content", ""
        )
        if "d /run/rsyslog 0750 syslog adm -" not in tmpfiles:
            report(name, "Ubuntu rsyslog tmpfiles ownership rule is missing")

        runtime = files.get(
            "/etc/systemd/system/rsyslog.service.d/10-runtime-dir.conf", {}
        ).get("content", "")
        fragment = (
            "ExecStartPre=/usr/bin/systemd-tmpfiles --create "
            "/etc/tmpfiles.d/60-kasa-rsyslog.conf"
        )
        if fragment not in runtime:
            report(name, f"Ubuntu rsyslog runtime directory is missing: {fragment}")
        if "RuntimeDirectory=" in runtime:
            report(
                name,
                "Ubuntu rsyslog must not reset the volatile cursor to root ownership",
            )

        apparmor = files.get(
            "/etc/apparmor.d/local/usr.sbin.rsyslogd", {}
        ).get("content", "")
        for rule in (
            "@{run}/log/journal/*/ r,",
            "@{run}/log/journal/*/** r,",
            "@{run}/rsyslog/ rw,",
            "@{run}/rsyslog/** rwk,",
        ):
            if rule not in apparmor:
                report(name, f"Ubuntu rsyslog AppArmor exception is missing: {rule}")

        rsyslog = files.get("/etc/rsyslog.d/01-remote.conf", {}).get("content", "")
        if 'PersistStateInterval="1"' not in rsyslog:
            report(name, "Ubuntu imjournal must persist its volatile cursor promptly")

    # fail2ban writes its own log file and ban database under /var by default.
    # Both must stay off disk for the memory-only guarantee to mean anything.
    fail2ban = strip_comments(
        files.get("/etc/fail2ban/fail2ban.local", {}).get("content", "")
    )
    # Anchored so a commented-out directive cannot satisfy the check, and
    # case-insensitive because fail2ban compares target.upper() in its own
    # setLogTarget, making logtarget=systemd-journal the same configuration.
    if not re.search(
        r"^\s*logtarget\s*=\s*SYSTEMD-JOURNAL\s*$",
        fail2ban,
        re.MULTILINE | re.IGNORECASE,
    ):
        report(name, "fail2ban must log to the journal, not to a file")
    if not re.search(r"^\s*dbfile\s*=\s*/run/", fail2ban, re.MULTILINE):
        report(name, "fail2ban ban database must be volatile, under /run")

    for entry in document.get("write_files", []):
        body = strip_comments(entry.get("content", ""))
        for forbidden in ("/var/spool/", "/var/log/journal"):
            if forbidden in body:
                report(
                    name,
                    f"{entry['path']}: {forbidden} makes system logging durable "
                    "on disk",
                )


def validate_appdata(profile: Profile, document: dict) -> None:
    name = profile.name
    files = files_by_path(document)
    expected_mount = [
        f"/dev/disk/by-id/wwn-{CONFIG['APPDATA_WWN']}",
        "/mnt/appdata",
        "ext4",
        "defaults,noatime,x-systemd.growfs,nodev,x-systemd.device-timeout=30s",
        "0",
        "2",
    ]
    if expected_mount not in document.get("mounts", []):
        report(name, "APPDATA must be mounted by WWN at /mnt/appdata with growfs")

    bootcmd = "\n".join(
        entry if isinstance(entry, str) else " ".join(entry)
        for entry in document.get("bootcmd", [])
    )
    for fragment in (
        f"app_link=/dev/disk/by-id/wwn-{CONFIG['APPDATA_WWN']}",
        f'[ "$app_serial" = "{CONFIG["APPDATA_SERIAL"]}" ]',
        'root_source="$(findmnt -n -o SOURCE /)"',
        'root_chain="$(lsblk -s -n -o PATH "$root_source")"',
        'app_children="$(printf \'%s\\n\' "$app_tree" | sed -n \'2,$p\')"',
        'app_pttype="$(blkid -p -s PTTYPE -o value "$app_dev" 2>/dev/null || true)"',
        'wipefs -n --noheadings --output TYPE "$app_dev"',
        'mkfs.ext4 -F -L APPDATA "$app_dev"',
        'elif [ "$app_fstype" != ext4 ] || [ "$app_label" != APPDATA ]',
        "install -d -m 0755 /mnt/appdata",
    ):
        if fragment not in bootcmd:
            report(name, f"APPDATA initialization is missing safety check: {fragment}")

    for path in APPDATA_PATHS:
        if path not in files:
            report(name, f"APPDATA verification is missing {path}")

    verify = files.get("/usr/local/sbin/appdata-verify", {}).get("content", "")
    for fragment in (
        f"expected_link=/dev/disk/by-id/wwn-{CONFIG['APPDATA_WWN']}",
        f'[ "$expected_serial" = "{CONFIG["APPDATA_SERIAL"]}" ]',
        "mountpoint -q /mnt/appdata",
        'app_mount_count="$(findmnt -rn --mountpoint /mnt/appdata -o TARGET | wc -l)"',
        'mounted_id="$(lsblk -dn -o MAJ:MIN -- "$mounted_dev" | xargs)"',
        '[ "$(findmnt -rn --mountpoint /mnt/appdata -o FSTYPE)" = ext4 ]',
        '[ "$(blkid -s LABEL -o value "$mounted_dev")" = APPDATA ]',
    ):
        if fragment not in verify:
            report(name, f"APPDATA verifier is missing check: {fragment}")

    service = files.get("/etc/systemd/system/appdata-verify.service", {}).get(
        "content", ""
    )
    for fragment in (
        "RequiresMountsFor=/mnt/appdata",
        "ExecStart=/usr/local/sbin/appdata-verify",
        "WantedBy=multi-user.target",
    ):
        if fragment not in service:
            report(name, f"APPDATA verifier service is missing: {fragment}")

    finalize = files.get("/usr/local/sbin/cloud-init-finalize", {}).get("content", "")
    for fragment in (
        "systemctl enable appdata-verify.service",
        "systemctl start appdata-verify.service",
        "systemctl is-active --quiet appdata-verify.service",
    ):
        if fragment not in finalize:
            report(name, f"finalize must activate APPDATA verification: {fragment}")


def validate_docker_rootless(
    profile: Profile, document: dict, release: str = DEFAULT_RELEASE
) -> None:
    name = profile.name
    files = files_by_path(document)
    finalize = files.get("/usr/local/sbin/cloud-init-finalize", {}).get("content", "")
    packages = document.get("packages", [])

    if not profile.docker:
        for path in DOCKER_ONLY_PATHS:
            if path in files:
                report(name, f"non-docker profile must not carry {path}")
        for package in ("docker-ce", "containerd.io", "uidmap"):
            if package in packages:
                report(name, f"non-docker profile must not install {package}")
        verify = files.get("/usr/local/sbin/appdata-verify", {}).get("content", "")
        if "/mnt/appdata/docker" in verify:
            report(name, "non-docker profile must not validate a Docker data-root")
        return

    for path in DOCKER_ONLY_PATHS:
        if path not in files:
            report(name, f"docker profile is missing {path}")

    docker_source = files.get("/etc/apt/sources.list.d/docker.sources", {}).get(
        "content", ""
    )
    expected_repository = {
        "deb13": (
            "URIs: https://download.docker.com/linux/debian",
            "Suites: trixie",
        ),
        "ubuntu24": (
            "URIs: https://download.docker.com/linux/ubuntu",
            "Suites: noble",
        ),
    }[release]
    for fragment in expected_repository:
        if fragment not in docker_source:
            report(name, f"Docker repository is missing {fragment}")

    modules_load = files.get(
        "/etc/modules-load.d/60-rootless-docker.conf", {}
    ).get("content", "")
    # nf_tables is the whole list on both releases. Ubuntu's iptables is
    # iptables-nft, so the legacy x_tables modules would be loaded surface that
    # carries no rules.
    if modules_load.strip() != "nf_tables":
        report(name, "Docker profile must load nf_tables and nothing else on every boot")
    for package in (
        "dbus-user-session",
        "docker-ce",
        "docker-ce-rootless-extras",
        "slirp4netns",
        "uidmap",
    ):
        if package not in packages:
            report(name, f"rootless Docker requires the {package} package")
    if release == "ubuntu24" and "apparmor" not in packages:
        report(name, "Ubuntu rootless Docker requires the apparmor package")

    # Rootless means rootless: the system daemon must never run.
    if "systemctl mask docker.service docker.socket" not in finalize:
        report(name, "the rootful docker units must be masked")
    if "usermod -aG docker admin" in finalize or "usermod -a -G docker" in finalize:
        report(
            name,
            "adding admin to the docker group grants root-equivalent access to a "
            "daemon this image does not run",
        )
    if "/var/lib/docker" not in finalize:
        report(name, "finalize must assert that /var/lib/docker was never created")

    bootcmd = "\n".join(
        entry if isinstance(entry, str) else " ".join(entry)
        for entry in document.get("bootcmd", [])
    )
    if "systemctl mask docker.service docker.socket" not in bootcmd:
        report(
            name,
            "mask the rootful units in bootcmd, before the packages install, or "
            "the daemon starts once and creates /var/lib/docker",
        )

    daemon = files.get("/home/admin/.config/docker/daemon.json", {})
    if daemon.get("defer") is not True:
        report(
            name,
            "the admin-owned daemon.json must be deferred; the user does not "
            "exist when write-files runs",
        )
    if daemon.get("owner") != "admin:admin":
        report(name, "daemon.json must be owned by admin")
    if '"data-root": "/mnt/appdata/docker"' not in daemon.get("content", ""):
        report(name, "daemon.json data-root must be /mnt/appdata/docker")
    if "/etc/docker/daemon.json" in files:
        report(name, "a rootless daemon reads ~/.config/docker/daemon.json, not /etc")

    drop_in = files.get(
        "/home/admin/.config/systemd/user/docker.service.d/10-require-appdata.conf", {}
    )
    if "ExecStartPre=/usr/bin/test -O /mnt/appdata/docker" not in drop_in.get(
        "content", ""
    ):
        report(name, "the user docker unit must refuse to start without APPDATA")

    delegate = files.get(
        "/etc/systemd/system/user@.service.d/10-delegate.conf", {}
    ).get("content", "")
    if "Delegate=cpu cpuset io memory pids" not in delegate:
        report(name, "cgroup v2 delegation is required for --cpus and --memory")

    tmpfiles = files.get("/etc/tmpfiles.d/60-appdata-docker.conf", {}).get("content", "")
    if "d /mnt/appdata/docker 0700 admin admin" not in tmpfiles:
        report(name, "the data-root must be created by tmpfiles.d, owned by admin")

    verify = files.get("/usr/local/sbin/appdata-verify", {}).get("content", "")
    for fragment in (
        "[ -d /mnt/appdata/docker ]",
        "stat -c '%U' /mnt/appdata/docker",
        'docker_root_mode="$(stat -c \'%a\' /mnt/appdata/docker)"',
    ):
        if fragment not in verify:
            report(name, f"Docker APPDATA verification is missing: {fragment}")

    create_data_root = "systemd-tmpfiles --create /etc/tmpfiles.d/60-appdata-docker.conf"
    start_verify = "systemctl start appdata-verify.service"
    if create_data_root not in finalize:
        report(name, "finalize must create the Docker data-root with tmpfiles.d")
    elif finalize.index(create_data_root) > finalize.index(start_verify):
        report(name, "the Docker data-root must exist before APPDATA verification starts")

    if "loginctl enable-linger admin" not in finalize:
        report(name, "lingering is required for the daemon to start without a login")

    # write-files creates the parents of the deferred admin-owned files as root,
    # so dockerd-rootless-setuptool.sh cannot write ~/.config/systemd/user until
    # the recursive chown has run. Verified the hard way: without it the install
    # dies with "Permission denied".
    chown = "chown -R admin:admin /home/admin"
    if chown not in finalize:
        report(name, f"finalize must run {chown!r} before installing rootless Docker")
    elif finalize.index(chown) > finalize.index("dockerd-rootless-setuptool.sh"):
        report(name, f"{chown!r} must come before the rootless Docker install")
    # Comments stripped: both of these are named in prose explaining why they
    # are not used, and matching that prose would be a false positive.
    finalize_code = strip_comments(finalize)
    if "machinectl" in finalize_code:
        report(
            name,
            "machinectl shell does not propagate exit status; use runuser so a "
            "failed install is not reported as success",
        )
    if "sudo su" in finalize_code:
        report(name, "sudo su does not set up XDG_RUNTIME_DIR for the setup tool")
    if "dockerd-rootless-setuptool.sh install" not in finalize:
        report(name, "finalize must install the rootless daemon")
    if release == "ubuntu24":
        for fragment in (
            "kernel.apparmor_restrict_unprivileged_userns)",
            "/etc/apparmor.d/rootlesskit",
            "/usr/sbin/apparmor_parser -r",
            "/sys/kernel/security/apparmor/profiles",
        ):
            if fragment not in finalize:
                report(name, f"Ubuntu rootless Docker setup is missing: {fragment}")
        for forbidden in (
            "kernel.apparmor_restrict_unprivileged_userns=0",
            "kernel.apparmor_restrict_unprivileged_userns = 0",
            "apparmor=0",
        ):
            if forbidden in strip_comments(finalize) or forbidden in modules_load:
                report(name, f"Ubuntu Docker must not weaken AppArmor: {forbidden}")
    modprobe = "/usr/sbin/modprobe nf_tables"
    module_check = "[ -d /sys/module/nf_tables ]"
    installer = "dockerd-rootless-setuptool.sh install"
    for fragment in (modprobe, module_check):
        if fragment not in finalize:
            report(name, f"rootless Docker setup is missing: {fragment}")
    if modprobe in finalize and finalize.index(modprobe) > finalize.index(installer):
        report(name, "nf_tables must load before the rootless Docker installer")
    if "--add-subuids" not in finalize or "--add-subgids" not in finalize:
        report(name, "finalize must assert admin has subordinate ID ranges")

    # A hardcoded 1000 is correct until it is not, and the failure is silent.
    for match in re.findall(r"/run/user/(\d+)", finalize):
        report(name, f"hardcoded uid {match} in /run/user path; derive it with id -u")


def validate_release_specific(
    profile: Profile, document: dict, rendered: str, release: str
) -> None:
    """Validate a distro-specific mechanism for a shared security property."""
    if release != "ubuntu24":
        return
    name = profile.name
    bootcmd = "\n".join(str(command) for command in document.get("bootcmd", []))
    for fragment in (
        "if ! getent passwd admin",
        "getent group admin",
        "/usr/sbin/useradd",
        "--gid admin",
        "--groups adm,cdrom,dip,lxd,sudo",
        "passwd --lock admin",
    ):
        if fragment not in bootcmd:
            report(name, f"Ubuntu existing-admin-group handling is missing: {fragment}")
    finalize = files_by_path(document).get(
        "/usr/local/sbin/cloud-init-finalize", {}
    ).get("content", "")
    for fragment in (
        "systemctl disable --now ssh.socket",
        "systemctl enable ssh.service",
        "systemctl restart ssh.service",
    ):
        if fragment not in finalize:
            report(name, f"Ubuntu SSH service handling is missing: {fragment}")
    body = strip_comments(rendered)
    for forbidden in (
        "kernel.apparmor_restrict_unprivileged_userns=0",
        "kernel.apparmor_restrict_unprivileged_userns = 0",
        "apparmor=0",
    ):
        if forbidden in body:
            report(name, f"Ubuntu must not weaken AppArmor: {forbidden}")


# --- LXC profile checks ------------------------------------------------------
# The container artifacts are shell, not YAML, so these read rendered text
# rather than a parsed document. Everything else follows the house style:
# comment-stripped, so a commented directive never satisfies a positive check
# and an explanatory comment never trips a negative one, and every profile-only
# feature gets a matching assertion that the other profiles do not carry it.

LXC_APPDATA = "/mnt/appdata"

# VM mechanisms. A container shares the host kernel and never sees a raw
# device, so each of these would describe hardware it cannot reach.
LXC_FORBIDDEN_FRAGMENTS = (
    "qemu-guest-agent",
    "cloud-init",
    "cloud-guest-utils",
    "growpart",
    "resize_rootfs",
    "zram",
    "/dev/disk/by-id",
    "mkfs",
    "wipefs",
    "fstrim.timer",
    "vm.swappiness",
    "APPDATA_WWN",
    "APPDATA_SERIAL",
    "lsblk",
    "blkid",
)

# Settings a container cannot own. Writing them here would either fail or be
# silently ignored; they belong on the Proxmox host and are documented there.
LXC_HOST_OWNED_SYSCTL_PREFIXES = ("kernel.", "fs.", "vm.", "user.")

# For both redirect settings the kernel ORs conf/all with conf/<interface>, so
# `all = 0` on its own leaves an existing eth0 or docker0 at its default of 1.
# The wildcard is what reaches those interfaces. rp_filter is deliberately not
# here: it takes the maximum of all and the interface, so all = 1 is enough.
LXC_REQUIRED_WILDCARD_SYSCTLS = (
    "net.ipv4.conf.*.accept_redirects = 0",
    "net.ipv4.conf.*.send_redirects = 0",
    "net.ipv6.conf.*.accept_redirects = 0",
)

LXC_REQUIRED_SSHD_DIRECTIVES = (
    "PasswordAuthentication no",
    "PermitRootLogin no",
    "AuthenticationMethods publickey",
    "KbdInteractiveAuthentication no",
    "PermitUserEnvironment no",
    "AllowAgentForwarding no",
    "X11Forwarding no",
    "PrintLastLog yes",
    "MaxAuthTries 3",
    "LoginGraceTime 30s",
    "MaxSessions 5",
    "MaxStartups 10:30:100",
)

LXC_DOCKER_PACKAGES = frozenset(
    {
        "containerd.io",
        "docker-buildx-plugin",
        "docker-ce",
        "docker-ce-cli",
        "docker-compose-plugin",
    }
)

# The VM installs these only because its Docker is rootless. Carrying them into
# a container that runs a rootful daemon would be cargo, not parity.
LXC_ROOTLESS_ONLY_PACKAGES = frozenset(
    {
        "docker-ce-rootless-extras",
        "uidmap",
        "slirp4netns",
        "dbus-user-session",
    }
)

# Units whose configuration this bootstrap rewrites. `systemctl enable --now`
# starts a stopped unit but is a no-op for a running one, so on a re-run these
# would keep serving the configuration that was just replaced -- and any check
# that follows would exercise the old policy while reporting the new one. The
# bootstrap advertises that re-running is safe, which has to mean it converges,
# not merely that it does not crash.
LXC_RECONFIGURED_UNITS = (
    "containerd.service",
    "docker.service",
    "fail2ban.service",
    "kasa-appdata-guard.service",
    "rsyslog.service",
    "ssh.service",
)

LXC_PROVENANCE_KEYS = (
    "ID",
    "DESCRIPTION",
    "RELEASE",
    "EXPECTED_LXC_TEMPLATE",
    "DOCKER",
    "LOGGING",
    "SOURCE_COMMIT",
    "SOURCE_TREE_DIRTY",
    "RENDERED_AT",
    "BOOTSTRAPPED_AT",
)


def lxc_written_file(bootstrap: str, path: str) -> str:
    """Return the content the bootstrap writes to one path.

    Configuration goes in through `install_file <path> <mode> <<EOF`, so a check
    can look at one file on its own instead of at the whole script, where an
    unrelated line could satisfy it.
    """
    match = re.search(
        rf"^install_file {re.escape(path)} [0-7]{{4}} <<'?(\w+)'?\n(.*?)^\1$",
        bootstrap,
        re.MULTILINE | re.DOTALL,
    )
    return match.group(2) if match else ""


def lxc_installed_packages(bootstrap: str) -> set[str]:
    """Collect the packages the bootstrap installs.

    Compared as whole tokens on purpose: `"docker-ce" in text` cannot tell a
    missing docker-ce from a present docker-ce-cli.
    """
    packages: set[str] = set()
    # Walk backslash continuations explicitly. A greedy [^\n]* would swallow the
    # trailing backslash, match zero continuations, and succeed on line one.
    for match in re.finditer(r"apt-get install(?:[^\n\\]|\\\n)*", bootstrap):
        for token in match.group(0).split():
            if token in ("apt-get", "install", "\\") or token.startswith("-"):
                continue
            packages.add(token)
    return packages


def validate_lxc_ssh(profile: Profile, bootstrap: str) -> None:
    """Require the VM's sshd policy, and require it to land safely."""
    name = profile.name
    sshd = lxc_written_file(bootstrap, "/etc/ssh/sshd_config.d/99-harden.conf")
    if not sshd:
        report(name, "the LXC bootstrap does not write the sshd hardening drop-in")
        return

    stripped = strip_comments(sshd)
    for directive in LXC_REQUIRED_SSHD_DIRECTIVES:
        if directive not in stripped:
            report(name, f"LXC sshd policy is missing: {directive}")

    entries: list[str] = []
    for line in stripped.splitlines():
        fields = line.split()
        if fields and fields[0].lower() == "allowusers":
            entries.extend(fields[1:])
    if len(entries) != len(SSH_ALLOW_USERS) or set(entries) != set(SSH_ALLOW_USERS):
        report(
            name,
            "LXC AllowUsers must match the private policy exactly: "
            + (" ".join(SSH_ALLOW_USERS) or "no active entries"),
        )

    body = strip_comments(bootstrap)

    # A container whose sshd configuration is loaded before admin can use it is
    # a container nobody can log into. Order is the whole control here.
    for fragment, message in (
        ("ssh-keygen -l -f", "must validate SSH keys with ssh-keygen"),
        ("/usr/sbin/sshd -t", "must test the sshd configuration before loading it"),
        ("visudo -cf /etc/sudoers.d/90-admin", "must validate sudo with visudo"),
        ("admin ALL=(ALL) NOPASSWD:ALL", "must grant admin passwordless sudo"),
        ("useradd --create-home --shell /bin/bash", "must create the admin account"),
        ("--groups adm,sudo", "must place admin in adm and sudo"),
        ("usermod --lock admin", "must lock the admin password"),
        ("/home/admin/apps", "must create /home/admin/apps"),
        ("install -d -m 0700 -o admin -g admin /home/admin/.ssh", "must create .ssh 0700"),
        ("install -m 0600 -o admin -g admin", "must install authorized_keys 0600"),
        ("chmod 0700 /home/admin", "must set /home/admin to 0700"),
        ("sshd -T", "must read the effective sshd policy back"),
    ):
        if fragment not in body:
            report(name, f"the LXC bootstrap {message}")

    for earlier, later, message in (
        (
            "install -m 0600 -o admin -g admin",
            "systemctl restart ssh.service",
            "admin's key must be installed before sshd is restarted",
        ),
        (
            "visudo -cf /etc/sudoers.d/90-admin",
            "systemctl restart ssh.service",
            "sudo must be validated before sshd is restarted",
        ),
        (
            "/usr/sbin/sshd -t",
            "systemctl restart ssh.service",
            "sshd -t must run before sshd is restarted",
        ),
    ):
        if earlier in body and later in body and body.index(earlier) > body.index(later):
            report(name, f"LXC bootstrap ordering: {message}")

    if "systemctl disable --now ssh.socket" not in body:
        report(
            name,
            "the LXC bootstrap must disable ssh.socket before restarting "
            "ssh.service so systemd and sshd do not both own port 22",
        )


def validate_lxc_sysctl(profile: Profile, bootstrap: str) -> None:
    """Require strict rp_filter and only container-owned keys."""
    name = profile.name
    path = "/etc/sysctl.d/60-hardening.conf"
    sysctl = lxc_written_file(bootstrap, path)
    if not sysctl:
        report(name, "the LXC bootstrap does not write the hardening sysctl file")
        return

    # Debian's own 50-default.conf sets rp_filter, so a lower-sorting name would
    # lose to it and the strict value would never take effect.
    if Path(path).name <= VENDOR_SYSCTL_BASELINE:
        report(name, f"LXC {path} must sort after {VENDOR_SYSCTL_BASELINE}")

    stripped = strip_comments(sysctl)
    for key in STRICT_RP_FILTER_KEYS:
        assignments = re.findall(
            rf"^\s*{re.escape(key)}\s*=\s*(\S+)\s*$", stripped, re.MULTILINE
        )
        if assignments != ["1"]:
            report(
                name,
                f"LXC {key} must have exactly one strict assignment of 1, "
                f"found {assignments or 'none'}",
            )

    for line in stripped.splitlines():
        key = line.split("=")[0].strip()
        if key and any(key.startswith(p) for p in LXC_HOST_OWNED_SYSCTL_PREFIXES):
            report(
                name,
                f"LXC sysctl file sets {key}, which the Proxmox host owns; a "
                "container cannot change it and must not appear to",
            )

    for setting in LXC_REQUIRED_WILDCARD_SYSCTLS:
        if setting not in stripped:
            report(
                name,
                f"LXC sysctl file is missing {setting!r}; without the per-interface "
                "wildcard the kernel ORs conf/all with each interface, and an "
                "existing eth0 or docker0 keeps redirects enabled",
            )

    body = strip_comments(bootstrap)
    if "/usr/lib/systemd/systemd-sysctl" not in body:
        report(name, "the LXC bootstrap must apply sysctls with systemd-sysctl")
    # Verifying all/default proves nothing about the interfaces carrying traffic.
    if "/proc/sys/net/ipv4/conf /proc/sys/net/ipv6/conf" not in body:
        report(
            name,
            "the LXC bootstrap must verify redirect settings on every interface, "
            "not only the all and default aggregates",
        )
    # Reading the values back is what turns "we wrote a file" into "the setting
    # is in effect"; a suppressed failure there would hide exactly that gap.
    if 'got=$(/usr/sbin/sysctl -n "$key")' not in body:
        report(name, "the LXC bootstrap must read each sysctl back after applying it")
    if re.search(r"sysctl[^\n]*\|\|\s*true", body):
        report(name, "the LXC bootstrap must not suppress a sysctl failure with || true")


def validate_lxc_packages(profile: Profile, bootstrap: str) -> None:
    """Match the VM's first-boot upgrade, and get the trust order right."""
    name = profile.name
    body = strip_comments(bootstrap)

    # The VM sets package_update and package_upgrade. A hand-pinned container
    # template can be months old, so skipping this would leave a finished
    # bootstrap sitting on stale packages.
    if "apt-get dist-upgrade" not in body:
        report(
            name,
            "the LXC bootstrap must upgrade the base system, matching the VM's "
            "package_upgrade",
        )

    if not profile.docker:
        return

    # ca-certificates must be in place before apt trusts a third-party HTTPS
    # repository, which is also the order Docker's own instructions use.
    certificates = body.find("no-install-recommends ca-certificates")
    docker_source = body.find("install_file /etc/apt/sources.list.d/docker.sources")
    if certificates == -1:
        report(name, "the LXC bootstrap must install ca-certificates explicitly")
    elif docker_source != -1 and certificates > docker_source:
        report(
            name,
            "ca-certificates must be installed before Docker's HTTPS repository "
            "is configured",
        )


def validate_lxc_logging(profile: Profile, bootstrap: str) -> None:
    """Port the VM's logging policy, including what the local profiles omit."""
    name = profile.name
    remote = lxc_written_file(bootstrap, "/etc/rsyslog.d/01-remote.conf")
    journald = lxc_written_file(
        bootstrap, "/etc/systemd/journald.conf.d/60-remote-syslog.conf"
    )
    fail2ban_local = lxc_written_file(bootstrap, "/etc/fail2ban/fail2ban.local")
    body = strip_comments(bootstrap)

    if not profile.remote_syslog:
        if remote:
            report(name, "a local-logging LXC profile must not forward to a collector")
        if journald:
            report(name, "a local-logging LXC profile must keep the journal durable")
        if fail2ban_local:
            report(name, "a local-logging LXC profile must keep fail2ban state on disk")
        if "Storage=volatile" in body:
            report(name, "a local-logging LXC profile must not make the journal volatile")
        if "/dev/tcp/" in body:
            report(name, "a local-logging LXC profile must not probe a collector")
        return

    if not remote:
        report(name, "a remote-syslog LXC profile must write /etc/rsyslog.d/01-remote.conf")
        return

    for fragment in REQUIRED_RSYSLOG_FRAGMENTS:
        if fragment not in remote:
            report(name, f"LXC remote rsyslog config is missing: {fragment}")
    for fragment in FORBIDDEN_RSYSLOG_FRAGMENTS:
        if fragment in strip_comments(remote):
            report(
                name,
                f"LXC remote rsyslog config must not spool to disk: found {fragment}",
            )
    for fragment in FORBIDDEN_TLS_FRAGMENTS:
        if fragment in remote:
            report(name, f"LXC remote rsyslog config must not configure TLS: {fragment}")
    if f'target="{SITE["SYSLOG_SERVER"]}"' not in remote:
        report(name, "LXC remote rsyslog target does not match the configured collector")
    if f'port="{SITE["SYSLOG_PORT"]}"' not in remote:
        report(name, "LXC remote rsyslog port does not match the configured collector")
    if strip_comments(remote).strip().splitlines()[-1].strip() != "stop":
        report(
            name,
            "LXC remote rsyslog config must end in stop, or messages continue "
            "into Debian's on-disk actions",
        )

    if "Storage=volatile" not in journald:
        report(name, "a remote-syslog LXC profile must set journald Storage=volatile")
    if "RuntimeMaxUse=64M" not in journald:
        report(name, "a remote-syslog LXC profile must cap the runtime journal at 64M")
    if "ForwardToSyslog=no" not in journald:
        report(name, "a remote-syslog LXC profile must not forward journal to syslog")
    if not re.search(r"(?mi)^\s*dbfile\s*=\s*/run/", fail2ban_local):
        report(name, "a remote-syslog LXC profile must keep fail2ban state under /run")
    if not re.search(r"(?mi)^\s*logtarget\s*=\s*SYSTEMD-JOURNAL", fail2ban_local):
        report(name, "a remote-syslog LXC profile must send fail2ban logs to the journal")

    # The container is live, not a template being built, so an unreachable
    # collector has to stop the run before the journal goes volatile.
    if "/dev/tcp/" not in body:
        report(name, "a remote-syslog LXC profile must test collector reachability")
    if "/run/rsyslog/imjournal.state" not in body:
        report(name, "a remote-syslog LXC profile must verify the imjournal state file")


def validate_lxc_var_log(profile: Profile, bootstrap: str) -> None:
    """/var/log stays on disk. A tmpfs there loses package log directories."""
    body = strip_comments(bootstrap)
    for pattern in VAR_LOG_TMPFS_COMMANDS:
        if pattern.search(body):
            report(profile.name, "the LXC bootstrap must not put /var/log on a tmpfs")


def validate_lxc_appdata(profile: Profile, bootstrap: str) -> None:
    """APPDATA is a Proxmox-managed mount the container only ever checks."""
    name = profile.name
    body = strip_comments(bootstrap)
    for fragment, message in (
        ("/usr/local/sbin/kasa-appdata-guard", "must install the APPDATA guard"),
        ('mountpoint -q -- "$APPDATA_MOUNT"', "must require APPDATA to be mounted"),
        ("kasa-appdata-guard.service", "must install the APPDATA guard unit"),
        (f"RequiresMountsFor={LXC_APPDATA}", "must order the guard after the mount"),
    ):
        if fragment not in body:
            report(name, f"the LXC bootstrap {message}")


def validate_lxc_host_keys(profile: Profile, bootstrap: str) -> None:
    """Every clone of a template must mint its own SSH host keys.

    Debian's sshd-keygen.service runs `ssh-keygen -A`, which creates only the keys that are
    missing, so a template shipping a full set gave every clone the same host identity and
    known_hosts could not tell one guest from another. The bootstrap installs a unit that
    re-keys when the recorded machine-id stops matching this machine's, which is exactly
    once per clone.
    """
    name = profile.name
    body = strip_comments(bootstrap)
    for fragment, message in (
        ("/usr/local/sbin/kasa-ssh-host-keys", "must install the host key script"),
        ("kasa-ssh-host-keys.service", "must install the host key unit"),
        ("Before=ssh.service", "must order host key generation before sshd"),
        ("/etc/ssh/kasa-host-key-identity", "must record the identity the keys belong to"),
        ("ssh-keygen -A", "must generate the replacement host keys"),
        (
            "systemctl enable kasa-ssh-host-keys.service",
            "must enable the host key unit at boot",
        ),
    ):
        if fragment not in body:
            report(name, f"the LXC bootstrap {message}")


def validate_lxc_omissions(profile: Profile, bootstrap: str) -> None:
    """Refuse VM-only mechanisms a container cannot honour."""
    body = strip_comments(bootstrap)
    for fragment in LXC_FORBIDDEN_FRAGMENTS:
        if fragment in body:
            report(
                profile.name,
                f"the LXC bootstrap carries the VM-only mechanism {fragment!r}",
            )


def validate_lxc_fail2ban(profile: Profile, bootstrap: str) -> None:
    """fail2ban that cannot enforce is not a control, so prove a ban lands."""
    name = profile.name
    jail = lxc_written_file(bootstrap, "/etc/fail2ban/jail.local")
    if not jail:
        report(name, "the LXC bootstrap does not configure fail2ban")
        return
    if "banaction = nftables-multiport" not in jail:
        report(name, "LXC fail2ban must ban through nftables")
    if "dummy" in jail:
        report(
            name,
            "LXC fail2ban must not use the dummy action, which detects without "
            "blocking and would be presented as a working control",
        )
    if "backend = systemd" not in jail:
        report(name, "LXC fail2ban must read the journal")
    if f"ignoreip = {SITE['FAIL2BAN_IGNORE_IPS']}" not in jail:
        report(name, "LXC fail2ban ignoreip does not match the configured value")

    body = strip_comments(bootstrap)
    if "fail2ban-client -t" not in body:
        report(name, "the LXC bootstrap must validate the fail2ban configuration")
    if "banip" not in body or "nft list ruleset" not in body:
        report(
            name,
            "the LXC bootstrap must prove a fail2ban ban reaches nftables rather "
            "than only checking that the service started",
        )


def validate_lxc_docker(profile: Profile, bootstrap: str) -> None:
    """Docker belongs to the Docker profiles and nowhere else."""
    name = profile.name
    body = strip_comments(bootstrap)
    daemon = lxc_written_file(bootstrap, "/etc/docker/daemon.json")
    sources = lxc_written_file(bootstrap, "/etc/apt/sources.list.d/docker.sources")

    packages = lxc_installed_packages(bootstrap)

    if not profile.docker:
        for package in sorted(LXC_DOCKER_PACKAGES & packages):
            report(name, f"a base LXC profile must not install {package}")
        if daemon or sources:
            report(name, "a base LXC profile must not configure Docker")
        for fragment in ("/etc/containerd", f"{LXC_APPDATA}/docker", "keyctl", "nesting"):
            if fragment in body:
                report(name, f"a base LXC profile must not reference {fragment}")
        return

    for package in sorted(LXC_DOCKER_PACKAGES - packages):
        report(name, f"the Docker LXC profile must install {package}")
    for package in sorted(LXC_ROOTLESS_ONLY_PACKAGES & packages):
        report(
            name,
            f"{package} exists only for the VM's rootless Docker; this profile "
            "runs a rootful daemon inside an unprivileged container",
        )

    if "Suites: trixie" not in sources:
        report(name, "the Docker LXC profile must use Docker's trixie repository")
    if "docker.io" in packages:
        report(name, "the Docker LXC profile must not install Debian's docker.io")
    if not lxc_written_file(bootstrap, "/etc/apt/keyrings/docker.asc"):
        report(name, "the Docker LXC profile must pin Docker's signing key")

    if f'"data-root": "{LXC_APPDATA}/docker"' not in daemon:
        report(name, f"Docker data-root must be {LXC_APPDATA}/docker")
    if '"log-driver": "journald"' not in daemon:
        report(name, "Docker must log to the journal, not to unbounded json-file")
    if "docker/{{.Name}}" not in daemon:
        report(name, "Docker journald logging must carry the container name tag")
    if "com.docker.compose.project" not in daemon:
        report(name, "Docker journald logging must carry the compose labels")

    # data-root does not move the containerd image store, so setting only that
    # would leave every pulled image on the container rootfs.
    if f'root = \\"${{APPDATA_MOUNT}}/containerd\\"' not in bootstrap:
        report(name, "the Docker LXC profile must relocate containerd's root to APPDATA")
    if f'ls -A -- "$APPDATA_MOUNT/containerd"' not in bootstrap:
        report(
            name,
            "the Docker LXC profile must confirm the running containerd populated "
            "its APPDATA root; `containerd config dump` only parses the file and "
            "would agree even if the live daemon still used the old root",
        )
    if "containerd config dump" not in body:
        report(
            name,
            "the Docker LXC profile must verify containerd's resolved root "
            "rather than trusting the edited config file",
        )
    if "containerd config default" not in body:
        report(name, "the Docker LXC profile must generate containerd's config")

    for unit in ("containerd.service", "docker.service"):
        drop_in = lxc_written_file(
            bootstrap, f"/etc/systemd/system/{unit}.d/10-kasa-appdata.conf"
        )
        if "ExecStartPre=/usr/local/sbin/kasa-appdata-guard" not in drop_in:
            report(
                name,
                f"{unit} must refuse to start without APPDATA; otherwise Docker "
                "silently falls back to filling the container rootfs",
            )

    if "systemctl mask docker.service docker.socket containerd.service" not in body:
        report(
            name,
            "the Docker LXC profile must mask the daemons across installation so "
            "neither starts against its default rootfs paths",
        )
    if "/var/lib/docker /var/lib/containerd" not in body:
        report(name, "the Docker LXC profile must assert nothing landed on the rootfs")
    if "docker compose version" not in body:
        report(name, "the Docker LXC profile must verify the Compose plugin")
    if "{{.DockerRootDir}}" not in body:
        report(name, "the Docker LXC profile must verify Docker's actual data root")
    if "{{.LoggingDriver}}" not in body:
        report(name, "the Docker LXC profile must verify the active logging driver")


def validate_lxc_idempotence(profile: Profile, bootstrap: str) -> None:
    """A re-run must converge, not just avoid crashing.

    Every unit whose configuration the bootstrap rewrites has to be restarted
    rather than merely started, and anything masked so it cannot run during
    installation has to actually be stopped first.
    """
    name = profile.name
    body = strip_comments(bootstrap)

    for unit in LXC_RECONFIGURED_UNITS:
        if unit not in body:
            continue
        if f"systemctl enable --now {unit}" in body:
            report(
                name,
                f"{unit}: use enable plus restart, not `enable --now`. Its "
                "configuration is rewritten above, and start does nothing to an "
                "already-running unit, so a re-run would leave the old one live",
            )
        restarted = (
            f"systemctl restart {unit}" in body
            or f"systemctl reload-or-restart {unit}" in body
        )
        if not restarted:
            report(
                name,
                f"{unit}: its configuration is rewritten, so the bootstrap must "
                "restart it for a re-run to take effect",
            )

    # mask blocks starting a unit; it does not stop one that is already running.
    if "systemctl mask " in body and "systemctl stop" not in body:
        report(
            name,
            "the LXC bootstrap masks units without stopping them; masking alone "
            "leaves a running daemon serving the configuration being replaced",
        )

    if not profile.docker:
        return

    # On a re-run Docker's repository is already on disk, so the system upgrade
    # can pull a new docker-ce or containerd.io. If the daemons are still up at
    # that point, dpkg restarts them against configuration this run is about to
    # replace -- outside the window the mask exists to create.
    stopped = body.find("systemctl stop")
    upgraded = body.find("apt-get dist-upgrade")
    if stopped == -1 or upgraded == -1 or stopped > upgraded:
        report(
            name,
            "the Docker daemons must be masked and stopped before the system "
            "upgrade, not only before their configuration is rewritten; on a "
            "re-run the upgrade can restart them behind the mask window",
        )


def validate_lxc_provenance(profile: Profile, bootstrap: str) -> None:
    """Record what the build knows, and do not call any of it an image."""
    name = profile.name
    release_file = lxc_written_file(bootstrap, "/etc/kasa-lxc-release")
    if not release_file:
        report(name, "the LXC bootstrap does not write /etc/kasa-lxc-release")
        return
    keys = [
        line.split("=", 1)[0]
        for line in release_file.splitlines()
        if "=" in line
    ]
    if keys != list(LXC_PROVENANCE_KEYS):
        report(
            name,
            f"/etc/kasa-lxc-release keys must be {list(LXC_PROVENANCE_KEYS)}, "
            f"found {keys}",
        )
    if f"ID=$PROFILE_NAME" not in release_file:
        report(name, "/etc/kasa-lxc-release must record the profile name")
    for forbidden in ("BUILT_AT", "TEMPLATE_VERSION", "IMAGE_BUILD"):
        if forbidden in release_file:
            report(
                name,
                f"/etc/kasa-lxc-release must not record {forbidden}: Proxmox "
                "created this container and the bootstrap configured it, which "
                "is not an image build",
            )


def validate_lxc_features(profile: Profile, command: str) -> None:
    """The host script is where a base container could gain Docker's powers."""
    name = profile.name
    features = re.findall(r"--features\s+(\S+)", command)
    granted = {token for value in features for token in value.split(",")}

    if not re.search(r"--unprivileged\s+1\b", command):
        report(name, "the LXC create script must create an unprivileged container")
    if re.search(r"--unprivileged\s+0\b", command):
        report(name, "the LXC create script must never create a privileged container")

    if profile.docker:
        if granted != {"keyctl=1", "nesting=1"}:
            report(
                name,
                "a Docker LXC profile must grant exactly keyctl=1 and nesting=1, "
                f"found {sorted(granted) or 'nothing'}",
            )
    elif features:
        report(
            name,
            "a base LXC profile must pass no --features at all; every one of "
            f"them already defaults to off, found {features}",
        )

    for token in sorted(granted):
        if token.split("=")[0] in ("fuse", "mknod", "mount", "force_rw_sys"):
            report(name, f"the LXC create script must not grant {token}")
    if "unconfined" in command:
        report(name, "the LXC create script must not weaken AppArmor confinement")
    if re.search(r"^\s*--replace\)", command, re.MULTILINE):
        report(name, "the LXC create script must not accept a destructive replace flag")
    if "pct destroy" in command:
        report(name, "the LXC create script must not destroy a container")
    # Being active is not the same as accepting container volumes. Proxmox's
    # default `local` carries iso,vztmpl,backup and no rootdir, so a script that
    # checked only availability would fail later, inside pct create.
    for variable, content, role in (
        ("TEMPLATE_STORAGE", "vztmpl", "template"),
        ("ROOTFS_STORAGE", "rootdir", "rootfs"),
        ("APPDATA_STORAGE", "rootdir", "APPDATA"),
    ):
        if f'require_storage "${variable}" {content}' not in command:
            report(
                name,
                f"the LXC create script must verify the {role} storage accepts "
                f"{content} content before creating the container",
            )

    # pvesm exits 0 for a storage that is defined but disabled or offline, so a
    # bare `pvesm status --storage` proves only that someone configured it once.
    if '$3 == "active"' not in command or "print $3; exit" not in command:
        report(
            name,
            "the LXC create script must require each storage to be active, not "
            "only defined; pvesm succeeds for a disabled or offline storage",
        )

    mount_points = re.findall(r"--mp(\d+)\s", command)
    if mount_points != ["0"]:
        report(
            name,
            "the LXC create script must attach exactly one mount point, mp0; "
            f"found {mount_points or 'none'}",
        )
    # The script assigns the path once and refers to it by variable, so check
    # both halves rather than a literal that never appears on the pct line.
    if f"APPDATA_MOUNT={LXC_APPDATA}\n" not in command:
        report(name, f"the LXC create script must set APPDATA_MOUNT to {LXC_APPDATA}")
    if "mp=${APPDATA_MOUNT}" not in command:
        report(name, "the LXC mount point must be attached at APPDATA_MOUNT")


def validate_lxc_artifact_names(release: str) -> None:
    """Eight container filenames that cannot collide with the eight VM ones."""
    prefix = CONFIG["NAME_PREFIX"]
    lxc_names = [lxc_template_name(p, release, prefix) for p in PROFILES]
    vm_names = [template_name(p, release, prefix) for p in PROFILES]
    if len(set(lxc_names)) != len(PROFILES):
        errors.append(f"LXC artifact names are not unique: {lxc_names}")
    overlap = sorted(set(lxc_names) & set(vm_names))
    if overlap:
        errors.append(f"LXC and VM artifact names collide: {overlap}")


def validate_generated_lxc_bundle(release: str) -> None:
    """Run every generated container pair through build.py's own gate."""
    for profile, container in zip(PROFILES, lxc_artifacts(
        release, dict(STUB_PROVENANCE), TEST_SSH_PUBLIC_KEY
    )):
        try:
            validate_generated_lxc(profile, container)
        except SystemExit as error:
            errors.append(f"{container.name}: {error}")


def validate_no_secrets(
    profile: Profile, rendered: str, *, exempt_ca_key: bool = False
) -> None:
    """Refuse key material in a rendered artifact.

    One exemption, and only one: the SSH user CA public key at
    /etc/ssh/kasa_user_ca.pub. It is a trust anchor rather than a credential -- holding it
    grants nothing, and hosts cannot trust the CA without it -- so it is distributed on
    purpose. Everything else this scans for stays forbidden, including a second copy of
    that same key, because exactly one occurrence is removed rather than all of them.

    Both artifact families carry the anchor -- the cloud-config as a write_files entry,
    the LXC bootstrap as an install_file heredoc -- so both pass exempt_ca_key. An
    operator key or a private key in either is still a failure.
    """
    scanned = rendered
    if exempt_ca_key:
        ca_key = CONFIG["SSH_USER_CA_PUBLIC_KEY"].strip()
        if ca_key:
            # One occurrence, not all of them: a second copy is not a trust anchor and
            # still trips the scan. validate_ssh_user_ca separately pins the anchor to
            # this exact configured value, so exempting the string cannot exempt
            # anything else.
            scanned = scanned.replace(ca_key, "", 1)

    for marker in ("ssh_authorized_keys", "PRIVATE KEY", "ssh-ed25519 AAAA", "ssh-rsa AAAA"):
        if marker in scanned:
            report(profile.name, f"rendered artifact contains key material: {marker}")


def validate_writer_boundary() -> None:
    """Only build.py may write artifacts, so there is one place to audit."""
    source = (ROOT / "tools" / "render.py").read_text(encoding="utf-8")
    for forbidden in ("write_text(", "write_bytes(", "mkdir(", "os.replace"):
        if forbidden in source:
            errors.append(f"render.py must not write files: found {forbidden}")


def validate_manifest_matches_config(release: str = DEFAULT_RELEASE) -> None:
    prefix = CONFIG["NAME_PREFIX"]
    names = {template_name(profile, release, prefix) for profile in PROFILES}
    if len(names) != len(PROFILES):
        errors.append("profile names collide after applying release and feature names")


def validate_image_pin_is_updater_output(release: str) -> None:
    """The committed pin must be exactly what its updater would write.

    The pin's own header says it is updater-managed, so a hand-edited comment
    turns the first automated bump into a diff that looks like an unrelated
    edit. Comparing the file against the updater's rendering catches that here
    rather than in the update pull request.
    """
    updaters = {"debian": debian_image_updater, "ubuntu": ubuntu_image_updater}
    path = TEMPLATES / release / "image.yaml"
    pin = load_image_pin(path)
    rendered = updaters[pin.os].render_image_pin(pin)
    if path.read_text(encoding="utf-8") != rendered:
        errors.append(
            f"{path} is not what tools/{pin.os}_image_updater.py would write; "
            "change the updater's IMAGE_FILE_HEADER instead of the file"
        )


def validate_release_vmid_ranges() -> None:
    """No two releases may claim the same VM ID.

    Each release claims `VMID_START + vmid_offset` plus one per profile, and the
    offsets are packed tight: Debian takes +0..3 and Ubuntu +4..7 for today's
    four profiles. So adding a fifth profile makes Debian claim Ubuntu's first
    ID. Proxmox shares one ID space across the cluster and `qm create` on a
    taken ID fails late, on a node, after an image download, so catch it here.
    """
    claimed: dict[int, str] = {}
    for name, release in sorted(RELEASES.items()):
        for profile in PROFILES:
            vmid = int(CONFIG["VMID_START"]) + release.vmid_offset + profile.vmid_offset
            owner = f"{name}/{profile.name}"
            if vmid in claimed:
                errors.append(
                    f"VM ID {vmid} is claimed by both {claimed[vmid]} and {owner}; "
                    "widen a release vmid_offset in render.RELEASES"
                )
            else:
                claimed[vmid] = owner


def validate_generated_bundle(release: str) -> None:
    """Validate every generated Proxmox script through the main validator."""
    image = load_image(release)
    vendors = vendor_artifacts(release, dict(STUB_PROVENANCE))
    for profile, vendor in zip(PROFILES, vendors):
        command = render_command(
            profile=profile,
            vendor=vendor,
            image=image,
            public_key=TEST_SSH_PUBLIC_KEY,
            release=release,
        )
        try:
            validate_generated_command(vendor, command, release)
        except SystemExit as error:
            errors.append(f"{vendor.template_name}: {error}")


def check_embedded_shell(name: str, document: dict, shellcheck: str) -> None:
    """Lint the shell inside write_files and bootcmd.

    These scripts run once, unattended, on a machine nobody is watching. They
    are the least observable code in the repository and get the same treatment
    as the generated Proxmox script.
    """
    scripts: list[tuple[str, str]] = []
    for entry in document.get("write_files", []):
        content = entry.get("content", "")
        if content.startswith("#!/bin/bash"):
            scripts.append((entry["path"], content))
    for index, entry in enumerate(document.get("bootcmd", [])):
        if isinstance(entry, str) and "\n" in entry:
            scripts.append((f"bootcmd[{index}]", "#!/bin/sh\n" + entry))

    if not scripts:
        return

    for path, content in scripts:
        syntax = subprocess.run(
            ["bash", "-n"], input=content, text=True, capture_output=True, check=False
        )
        if syntax.returncode:
            errors.append(f"{name}: {path} is not valid bash")
            print(syntax.stderr, file=sys.stderr, end="")
            continue
        result = subprocess.run(
            [shellcheck, "--shell", "bash", "-"],
            input=content,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode:
            errors.append(f"{name}: shellcheck rejected {path}")
            print(result.stdout + result.stderr, file=sys.stderr, end="")


def run_full_checks(rendered: dict[str, str]) -> None:
    """Checks that need real tools. Skipped tools are reported, not ignored."""
    missing: list[str] = []

    rsyslogd = shutil.which("rsyslogd") or (
        "/usr/sbin/rsyslogd" if Path("/usr/sbin/rsyslogd").exists() else None
    )
    cloud_init = shutil.which("cloud-init")
    yamllint = shutil.which("yamllint")
    shellcheck = shutil.which("shellcheck")

    for tool, path in (
        ("rsyslogd", rsyslogd),
        ("cloud-init", cloud_init),
        ("yamllint", yamllint),
        ("shellcheck", shellcheck),
    ):
        if not path:
            missing.append(tool)

    if missing:
        errors.append(f"--full requires these tools: {sorted(missing)}")
        return

    for name, content in rendered.items():
        document = yaml.load(content, Loader=UniqueKeyLoader)
        check_embedded_shell(name, document, shellcheck)
        config = files_by_path(document).get("/etc/rsyslog.d/01-remote.conf", {}).get(
            "content"
        )
        if config:
            result = subprocess.run(
                [rsyslogd, "-N1", "-f", "/dev/stdin"],
                input=config,
                text=True,
                capture_output=True,
                check=False,
            )
            if result.returncode:
                errors.append(f"{name}: rsyslogd -N1 rejected the forwarder config")
                print(result.stdout + result.stderr, file=sys.stderr, end="")

        with_header = content
        result = subprocess.run(
            [cloud_init, "schema", "--config-file", "/dev/stdin"],
            input=with_header,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode:
            errors.append(f"{name}: cloud-init schema rejected the config")
            print(result.stdout + result.stderr, file=sys.stderr, end="")

        result = subprocess.run(
            [yamllint, "-c", str(ROOT / ".yamllint.yml"), "-"],
            input=content,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode:
            errors.append(f"{name}: yamllint rejected the config")
            print(result.stdout + result.stderr, file=sys.stderr, end="")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--release",
        default=DEFAULT_RELEASE,
        help=f"OS release directory under templates/ (default: {DEFAULT_RELEASE})",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="also run rsyslogd, cloud-init and yamllint against the rendered output",
    )
    arguments = parser.parse_args()

    release_info = load_release(arguments.release)
    image = load_image(arguments.release)
    rendered: dict[str, str] = {}

    for profile in PROFILES:
        content = render(
            profile,
            arguments.release,
            OS=image.os,
            OS_VERSION=image.version,
            OS_CODENAME=image.codename,
            IMAGE_BUILD=image.build,
            **STUB_PROVENANCE,
        )
        rendered[profile.name] = content
        try:
            document = yaml.load(content, Loader=UniqueKeyLoader)
        except yaml.YAMLError as error:
            report(profile.name, f"rendered config is not valid YAML: {error}")
            continue
        if not isinstance(document, dict):
            report(profile.name, "rendered config is not a mapping")
            continue

        validate_common(profile, document, content, arguments.release)
        validate_ssh_source_restriction(profile, document)
        validate_strict_rp_filter(profile, document)
        validate_image_release(profile, document, arguments.release)
        validate_var_log_persistence(profile, document)
        validate_rsyslog(profile, document)
        validate_remote_syslog(profile, document, arguments.release)
        validate_appdata(profile, document)
        validate_docker_rootless(profile, document, arguments.release)
        validate_release_specific(profile, document, content, arguments.release)
        validate_ssh_user_ca(profile, document)
        validate_ca_certs(profile, document)
        validate_no_secrets(profile, content, exempt_ca_key=True)

    if release_info.lxc:
        containers = lxc_artifacts(
            arguments.release, dict(STUB_PROVENANCE), TEST_SSH_PUBLIC_KEY
        )
        for profile, container in zip(PROFILES, containers):
            bootstrap = container.bootstrap
            validate_lxc_ssh(profile, bootstrap)
            validate_lxc_sysctl(profile, bootstrap)
            validate_lxc_packages(profile, bootstrap)
            validate_lxc_logging(profile, bootstrap)
            validate_lxc_var_log(profile, bootstrap)
            validate_lxc_appdata(profile, bootstrap)
            validate_lxc_host_keys(profile, bootstrap)
            validate_lxc_omissions(profile, bootstrap)
            validate_lxc_fail2ban(profile, bootstrap)
            validate_lxc_docker(profile, bootstrap)
            validate_lxc_idempotence(profile, bootstrap)
            validate_lxc_provenance(profile, bootstrap)
            validate_lxc_features(profile, container.command)
            validate_no_secrets(profile, bootstrap, exempt_ca_key=True)

    validate_writer_boundary()
    validate_manifest_matches_config(arguments.release)
    validate_image_pin_is_updater_output(arguments.release)
    validate_release_vmid_ranges()
    if release_info.lxc:
        validate_lxc_artifact_names(arguments.release)
    validate_generated_bundle(arguments.release)
    if release_info.lxc:
        validate_generated_lxc_bundle(arguments.release)

    if arguments.full and not errors:
        run_full_checks(rendered)

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print(
        f"Validated {len(PROFILES)} profile(s) for {arguments.release}: "
        + ", ".join(profile.name for profile in PROFILES)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
