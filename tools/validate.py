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
    render_command,
    validate_generated_command,
    vendor_artifacts,
)
from render import (
    CONFIG,
    DEFAULT_RELEASE,
    PROFILES,
    ROOT,
    SITE,
    SSH_ALLOW_USERS,
    Profile,
    load_image,
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
        "/etc/ssh/sshd_config.d/99-harden.conf", {}
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
    """Require one strict reverse-path-filter assignment for each governed key."""
    name = profile.name
    hardening = files_by_path(document).get(
        "/etc/sysctl.d/20-hardening.conf", {}
    ).get("content", "")
    active = strip_comments(hardening)

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


def validate_common(profile: Profile, document: dict, rendered: str) -> None:
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
    for required in (
        "cloud-guest-utils",
        "fail2ban",
        "nftables",
        "qemu-guest-agent",
        "rsyslog",
        "systemd-zram-generator",
        "unattended-upgrades",
    ):
        if required not in packages:
            report(name, f"missing required package: {required}")

    files = files_by_path(document)
    for required_path in (
        "/etc/kasa-image-release",
        "/etc/ssh/sshd_config.d/99-harden.conf",
        "/etc/sysctl.d/20-hardening.conf",
        "/etc/systemd/zram-generator.conf",
        "/etc/fail2ban/jail.local",
        "/usr/local/sbin/cloud-init-finalize",
        "/usr/local/sbin/cloud-init-post-verify",
        "/etc/systemd/system/cloud-init-post-verify.service",
    ):
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

    sshd = files.get("/etc/ssh/sshd_config.d/99-harden.conf", {}).get("content", "")
    for directive in (
        "PasswordAuthentication no",
        "PermitRootLogin no",
        "AuthenticationMethods publickey",
        "KbdInteractiveAuthentication no",
        "MaxAuthTries 3",
    ):
        if directive not in sshd:
            report(name, f"sshd hardening is missing: {directive}")

    hardening = files.get("/etc/sysctl.d/20-hardening.conf", {}).get("content", "")
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

    zram = files.get("/etc/systemd/zram-generator.conf", {}).get("content", "")
    if "compression-algorithm = zstd" not in zram or "zram-size" not in zram:
        report(name, "zram generator configuration is incomplete")

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


def validate_image_release(profile: Profile, document: dict) -> None:
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
        "DEBIAN_IMAGE_BUILD",
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


def validate_remote_syslog(profile: Profile, document: dict) -> None:
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


def validate_docker_rootless(profile: Profile, document: dict) -> None:
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

    modules_load = files.get(
        "/etc/modules-load.d/60-rootless-docker.conf", {}
    ).get("content", "")
    if modules_load.strip() != "nf_tables":
        report(name, "Docker profile must load nf_tables on every boot")
    for package in (
        "dbus-user-session",
        "docker-ce",
        "docker-ce-rootless-extras",
        "slirp4netns",
        "uidmap",
    ):
        if package not in packages:
            report(name, f"rootless Docker requires the {package} package")

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


def validate_no_secrets(profile: Profile, rendered: str) -> None:
    for marker in ("ssh_authorized_keys", "PRIVATE KEY", "ssh-ed25519 AAAA", "ssh-rsa AAAA"):
        if marker in rendered:
            report(profile.name, f"rendered artifact contains key material: {marker}")


def validate_writer_boundary() -> None:
    """Only build.py may write artifacts, so there is one place to audit."""
    source = (ROOT / "tools" / "render.py").read_text(encoding="utf-8")
    for forbidden in ("write_text(", "write_bytes(", "mkdir(", "os.replace"):
        if forbidden in source:
            errors.append(f"render.py must not write files: found {forbidden}")


def validate_manifest_matches_config() -> None:
    prefix = CONFIG["NAME_PREFIX"]
    names = {
        template_name(profile, DEFAULT_RELEASE, prefix) for profile in PROFILES
    }
    if len(names) != len(PROFILES):
        errors.append("profile names collide after applying release and feature names")


def validate_generated_bundle(release: str) -> None:
    """Validate every generated Proxmox script through the main validator."""
    image = load_image(release)
    vendors = vendor_artifacts(release, dict(STUB_PROVENANCE))
    for vendor in vendors:
        command = render_command(
            vendor=vendor,
            image=image,
            public_key=TEST_SSH_PUBLIC_KEY,
        )
        try:
            validate_generated_command(vendor, command)
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
        help=f"Debian release directory under templates/ (default: {DEFAULT_RELEASE})",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="also run rsyslogd, cloud-init and yamllint against the rendered output",
    )
    arguments = parser.parse_args()

    image = load_image(arguments.release)
    rendered: dict[str, str] = {}

    for profile in PROFILES:
        content = render(
            profile,
            arguments.release,
            DEBIAN_IMAGE_BUILD=image.build,
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

        validate_common(profile, document, content)
        validate_ssh_source_restriction(profile, document)
        validate_strict_rp_filter(profile, document)
        validate_image_release(profile, document)
        validate_var_log_persistence(profile, document)
        validate_rsyslog(profile, document)
        validate_remote_syslog(profile, document)
        validate_appdata(profile, document)
        validate_docker_rootless(profile, document)
        validate_no_secrets(profile, content)

    validate_writer_boundary()
    validate_manifest_matches_config()
    validate_generated_bundle(arguments.release)

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
