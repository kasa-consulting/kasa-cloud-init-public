# KASA agent base images

Hardened Debian 13 cloud-init templates for Proxmox, built on years of
deployment and testing. They are base images for KASA services and agent hosts:
clone one to get a locked-down VM that logs either to your remote collector or
its local disk and, optionally, runs rootless Docker.

The images include fail2ban, zram, and automatic root-volume growth. Expand a
volume in the Proxmox GUI, reboot the VM, and the partition grows automatically.

| Template | Rootless Docker | APPDATA disk | Remote syslog |
| --- | --- | --- | --- |
| `kasa-deb13-base-syslog` | No | Yes | Always |
| `kasa-deb13-docker-syslog` | Yes | Yes | Always |
| `kasa-deb13-base` | No | Yes | No; durable local logs |
| `kasa-deb13-docker` | Yes | Yes | No; durable local logs |

Two things to understand before you use these, both deliberate:

> **Remote-syslog profiles keep system logging in memory.**
> For the templates ending in `-syslog`, the journal is volatile, the rsyslog
> forwarding queue has no disk spool, and fail2ban's ban database lives in
> `/run` — so the collector is the only durable copy of the system log stream.
> `/var/log` is a normal persistent directory on all four templates. The
> profiles without `-syslog` instead keep normal durable syslog files on their
> VM disks. See [Logging modes](#logging-modes).

> **Rootless Docker depends on unprivileged user namespaces.**
> Debian 13 leaves them open by default, unlike Ubuntu 24.04 and later. That is
> a real local-privilege-escalation surface and it is the price of not running a
> root daemon. Never add a `user.max_user_namespaces` or
> `kernel.apparmor_restrict_unprivileged_userns` restriction to the hardening
> sysctls; it would break Docker on this image. Keep in mind that rootless
> Docker cannot publish ports below 1024.

## How to use

### Build Template Files & Install Script

Edit and configure `tools/env.example` with your settings.

Then run from the repository root on any Linux box. You need Python 3 with PyYAML,
Bash, and `ssh-keygen`. Proxmox and root are not required to build.

```bash
cp tools/env.example tools/.env
chmod 0600 tools/.env
$EDITOR tools/.env
```

Set at least `SYSLOG_SERVER`, `SYSLOG_PORT`, `FAIL2BAN_IGNORE_IPS`, `BRIDGE`,
`VMID_START`, and `SSH_PUBLIC_KEY_FILE`. `VMID_START` must begin a range of
unused VM IDs — one per profile in `profiles.yaml`.

```bash
./tools/validate.sh          # structure and content checks
./tools/validate.sh --full   # also runs cloud-init, rsyslogd, yamllint, shellcheck
./tools/build.sh             # builds the template files and install scripts
```

`build/` will create one `*-vendor.yml` and one `create-*.sh` per profile. Each
script carries the SHA-256 of its own snippet and re-verifies it on Proxmox
before creating anything.

## Installing the Template on Proxmox

Snippets go in the storage named by `SNIPPET_STORAGE_NAME`. Find that directory
and make sure you saved the files we created with the build process there.

Then on the Proxmox host, from that directory:

```bash
bash create-kasa-deb13-base-syslog.sh
```

or

```bash
bash create-kasa-deb13-docker-syslog.sh
```

For durable local logging, use `create-kasa-deb13-base.sh` or
`create-kasa-deb13-docker.sh` instead.

Each script downloads and verifies the Debian image, checks the VM ID is free,
and creates the template. Boot it once: a successful first boot leaves the VM
running; a failed bootstrap writes diagnostics to the `~/logs` folder.
Keep the snippets available to Proxmox so the cloud-init drive can be
regenerated.

## Rebuilding

Template names carry no version, so a rebuild replaces:

```bash
bash create-kasa-deb13-docker.sh --replace
```

Without `--replace` the script refuses when the VM ID is in use. With it, the
script checks the ID really holds a template with the expected name, then
destroys it.

**Proxmox will not destroy a template that still has linked clones.** If your
agent VMs are linked clones, remove them or convert them to full clones before
rebuilding. The script reports this case explicitly rather than half-completing.

## How the repository is organised

Two axes, kept separate:

- **Features** are build-time flags. `templates/deb13/cloud-config.yml.tmpl` is
  one file with `docker` and `remote_syslog` conditionals, and `profiles.yaml`
  enumerates the templates that get built. Adding a feature is one flag plus one manifest
  entry; it does not double the number of templates, because profiles are listed
  explicitly rather than derived as a cross-product of every flag.
- **Debian releases** are directories. `templates/deb13/` holds the cloud-config
  and an `image.yaml` pinning that release's cloud image build and SHA512.
  Debian 14 becomes `templates/deb14/`; pass `--release deb14`.

There is deliberately **no template versioning**. Template names are stable and
a rebuild replaces the existing template (see [Rebuilding](#rebuilding)).
Provenance lives inside the guest instead, in `/etc/kasa-image-release`:

```
ID=docker
DESCRIPTION=Hardened Debian agent host with rootless Docker
RELEASE=deb13
DEBIAN_IMAGE_BUILD=20260722-2547
SOURCE_COMMIT=1f3c0c1e...
SOURCE_TREE_DIRTY=false
BUILT_AT=2026-08-05T20:14:03+00:00
```

| Path | Purpose |
| --- | --- |
| `tools/.env` | Your local settings, copied from `tools/env.example`. Gitignored. **Create this first.** |
| `profiles.yaml` | Which templates get built, and their flags. |
| `templates/deb13/` | The cloud-config template and the Debian image pin. |
| `templates/proxmox-create.sh.tmpl` | The `qm create` script emitted per template. |
| `tools/build.sh` | Build command. The only thing that writes artifacts. |
| `tools/validate.sh` | Validate without building. |
| `build/` | Generated output. Gitignored, rebuilt from scratch every time. |

## What is in the images

### Packages

Every template installs `ca-certificates`, `cloud-guest-utils`, `fail2ban`,
`nftables`, `openssh-server`, `qemu-guest-agent`, `rsyslog`, `sudo`,
`systemd-zram-generator`, and `unattended-upgrades`. First boot runs a full
update and upgrade before anything else is configured.

There are no language runtimes, build tools, or agent software. This is a base
image; agent payloads layer on top of a clone.

The docker profile adds `docker-ce`, `docker-ce-cli`, `containerd.io`,
`docker-buildx-plugin`, `docker-compose-plugin`, `docker-ce-rootless-extras`
from `download.docker.com` (key pinned to fingerprint
`9DC858229FC7DD38854AE2D88D81803C0EBFCD88`), plus `uidmap`,
`dbus-user-session`, `slirp4netns`, and `iptables`.

### Configuration

| Area | What is set | Where |
| --- | --- | --- |
| User | `admin`, key-only, password locked, `NOPASSWD` sudo, in `adm` and `sudo` | `qm create --ciuser --sshkeys`, verified in `cloud-init-finalize` |
| Hostname | From the Proxmox VM name, including after cloning and renaming | Proxmox-generated user-data |
| SSH | Public key only for `admin` from exactly `10.1.10.100`, `10.1.10.101`, `10.1.75.2`, `10.1.2.19`, and `10.1.11.105`; no root; `MaxAuthTries 3`; `LoginGraceTime 30s` | `/etc/ssh/sshd_config.d/99-harden.conf` |
| fail2ban | Aggressive `sshd` jail, escalating 30m bans, nftables actions | `/etc/fail2ban/jail.local` |
| Kernel | Restricted kptr and ptrace, unprivileged BPF off, redirects off, strict `rp_filter = 1`, SYN cookies | `/etc/sysctl.d/20-hardening.conf` |
| Updates | Debian unattended-upgrades defaults, enabled daily with no automatic reboot | `/etc/apt/apt.conf.d/20auto-upgrades` |
| Swap | zram only, `min(ram / 2, 512)` with zstd, `vm.swappiness = 100` | `/etc/systemd/zram-generator.conf` |
| Disk | Root grows on first boot, `fstrim.timer` enabled | cloud-init `growpart` |
| Remote syslog | Volatile journal forwarded to `SYSLOG_SERVER:SYSLOG_PORT` over plain TCP, memory-only queue | `/etc/rsyslog.d/01-remote.conf` |
| Local logging | profiles without `-syslog` use normal disk-backed rsyslog files and persistent fail2ban state | Debian package defaults |
| `/var/log` | Persistent on every profile; never a tmpfs, so package-created log directories survive a reboot | Debian package defaults |
| Docker | Rootless, `data-root` on `/mnt/appdata/docker`, journald log driver | `~admin/.config/docker/daemon.json` |
| APPDATA | Every VM gets a disk matched by WWN and serial, ext4 labelled `APPDATA`, mounted at `/mnt/appdata` | `bootcmd`, `appdata-verify.service` |
| First boot | Self-checks the bootstrap and remains running; failures write `/home/admin/logs/` | `cloud-init-post-verify.service` |

`templates/deb13/cloud-config.yml.tmpl` is the authority if this table falls
behind.

The SSH source policy uses OpenSSH's additive
[`AllowUsers USER@HOST`](https://man.openbsd.org/sshd_config#AllowUsers) matching. The two
governed `rp_filter` settings use Linux strict mode (`1`), not loose mode (`2`), as defined by
the [Linux kernel IP sysctl documentation](https://docs.kernel.org/networking/ip-sysctl.html).

### Rootless Docker

The daemon runs as `admin` through a systemd user service, started at boot by
lingering. The rootful `docker.service` and `docker.socket` are masked before
the packages install, so the root daemon never runs and `/var/lib/docker` is
never created — first boot fails if it finds one.

Consequences worth knowing:

- **Ports below 1024 cannot be published.** `ip_unprivileged_port_start` stays
  at its hardened default, so `-p 80:80` fails with
  `cannot expose privileged port 80`. Publish a high port and front it with a
  reverse proxy, or lower the sysctl deliberately.
- **On remote-syslog profiles, `journalctl --user` does not work.** With
  `Storage=volatile`, systemd keeps
  no per-user journal files. Container logs still reach the system journal and
  therefore the collector; read them locally with
  `journalctl -t docker/<container>` (`admin` is in `adm`).
- **`admin` is not in a `docker` group**, because there is no root daemon to
  grant access to. Use the user socket:
  `export DOCKER_HOST=unix:///run/user/$(id -u)/docker.sock`.
- AppArmor confinement of containers is not available in rootless mode. seccomp
  and cgroup namespaces are.

`docker --cpus` and `--memory` work: `/etc/systemd/system/user@.service.d/10-delegate.conf`
delegates the cgroup controllers that rootless mode otherwise cannot use.

### Logging modes

The profiles without `-syslog` use Debian's normal logging behavior: rsyslog writes to
disk under `/var/log`, fail2ban keeps its database under `/var/lib/fail2ban`,
and no remote collector is configured or tested. Standard log rotation remains
owned by the Debian packages.

The `-syslog` profiles deliberately keep their *system* logging state in memory
and send it to the collector instead. Three properties, and only these three:

- `systemd-journald` runs with `Storage=volatile`, so the journal lives in
  `/run/log/journal`.
- The rsyslog forwarding queue has no disk spool, and `01-remote.conf` ends in
  `stop` so the forwarded stream is not also written out by Debian's default
  on-disk rules.
- fail2ban logs to the journal and keeps its ban database in `/run`.

The only swap device is zram, so nothing pages to disk either. This cuts disk
writes considerably, but it is narrower than "nothing is written to disk", and
the boundary is worth being precise about.

`/var/log` is a **normal persistent directory on every profile**. It is not a
tmpfs. Anything that writes files there directly still lands on the VM disk —
`cloud-init.log` and `cloud-init-output.log` among them, along with any
application or package that does its own file logging rather than going through
syslog or the journal. That is deliberate: a volatile `/var/log` hides the log
directories Debian packages create at install time, and services such as nginx,
Apache and Supervisor fail to start after a reboot when their directory has
vanished.

What you give up:

- **An unreachable collector loses messages.** The queue holds about 25,000
  messages in RAM, then discards lowest severity first. There is no catch-up.
- **A sustained log storm is rate-limited** to 25,000 messages per 60 seconds.
- **Reboots lose the journal and the syslog stream.** Files an application wrote
  under `/var/log` itself survive.
- **fail2ban forgets its bans on reboot.** They survive a fail2ban restart.
- **Retention under `/var/log` is not KASA's.** Rotation there is owned by the
  application or package, if it configures any at all, and disk usage is no
  longer capped the way the former 128 MiB tmpfs capped it.

Because the collector matters this much, the first-boot self-test probes it. On
the template build boot an unreachable collector is a warning, so the template
is still buildable without one. On a clone it is fatal, because the VM would
otherwise run blind.

## How was AI used in this repo?

I began working on this project before I started using AI.
Today, I use AI as a research assistant and force multiplier. It helps me explore
concepts, and my agents test sandboxed VMs for compliance and vulnerabilities.
When AI generates code for me, I remain responsible for it and only deploy code
that I understand and have the ability to maintain.

## To do

- Replace plain TCP syslog with authenticated TLS or RELP.
- Benchmark `pasta` against `slirp4netns` and pin the faster one.
- Confirm `live-restore` behaves under rootless, and re-add it if so.

## License

Copyright 2026 KASA Consulting LLC.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
