# KASA agent base images

Hardened Debian 13 bootstrap artifacts for Proxmox, built on years of deployment
and testing. They are the base for KASA services and agent hosts: pick a profile
to get a locked-down machine that logs either to your remote collector or its
local disk and, optionally, runs Docker.

The same four profiles build two things, and you choose per deployment:

- **VM templates**, via cloud-init and `qm create`. Clone one to get a VM.
- **LXC containers**, via a `pct create` script and a guest bootstrap. See
  [LXC containers](#lxc-containers).

Everything below describes the VM templates unless it says otherwise. The
container profiles share the same SSH, logging, fail2ban and `rp_filter` policy,
and differ where a container genuinely differs from a VM.

The images include fail2ban, zram, and automatic root-volume growth. Expand a
volume in the Proxmox GUI, reboot the VM, and the partition grows automatically.

| Template | Rootless Docker | APPDATA disk | Remote syslog |
| --- | --- | --- | --- |
| `kasa-deb13-base-syslog` | No | Yes | Always |
| `kasa-deb13-docker-syslog` | Yes | Yes | Always |
| `kasa-deb13-base` | No | Yes | No; durable local logs |
| `kasa-deb13-docker` | Yes | Yes | No; durable local logs |

Things to understand before you use these, both deliberate:

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

> The published template has no active `AllowUsers` directive. Public-key-only
> authentication, disabled root login, `MaxAuthTries 3`, and
> `LoginGraceTime 30s` remain enforced. To restrict sources, set
> `SSH_ALLOW_USERS` in `tools/.env` to exact `admin@IP` entries for your
> environment. For example, `admin@10.10.10.100 admin@192.168.1.100`. The
> published default is empty; example addresses are never active authorization.

> `rp_filter` settings use Linux strict mode (`1`), change to `2` if you have multiple
> NIC's in the VM

> Rootless docker cannot expose ports below 1024

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
unused VM IDs — one per profile in `templates/profiles.yaml`. If you configure SSH source
authorization, use exact `admin@IP` entries in `SSH_ALLOW_USERS`.

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

**Proxmox will not destroy a template that still has linked clones.** If your
agent VMs are linked clones, remove them or convert them to full clones before
rebuilding. The script reports this case explicitly rather than half-completing.

## How the repository is organised

| Path | Purpose |
| --- | --- |
| `tools/.env` | Your local settings, copied from `tools/env.example`. Gitignored. **Create this first.** |
| `templates/profiles.yaml` | Which profiles get built, and their flags. One manifest drives both VMs and containers. |
| `templates/deb13/` | The cloud-config template, the LXC bootstrap template, the Debian image pin, and the container template pin. |
| `templates/proxmox-create.sh.tmpl` | The `qm create` script emitted per VM template. |
| `templates/proxmox-lxc-create.sh.tmpl` | The `pct create` script emitted per container profile. |
| `tools/build.sh` | Build command. The only thing that writes artifacts. |
| `tools/validate.sh` | Validate without building. |
| `build/` | Generated output. Gitignored, rebuilt from scratch every time. |

- `templates/deb13/cloud-config.yml.tmpl` and
  `templates/deb13/lxc-bootstrap.sh.tmpl` are each one maintained file with
  `docker` and `remote_syslog` conditionals, rather than one script per profile.
  `templates/profiles.yaml` enumerates the profiles that get built.
- `templates/deb13/` also holds `image.yaml`, pinning that release's cloud image
  build and SHA512, and `lxc-template.yaml`, pinning its container template.
  The container pin carries no checksum: container templates come from Proxmox's
  signed appliance catalogue, so `pveam` already owns that trust path.


There is deliberately no template versioning. Template names are stable and
a rebuild replaces the existing template (see [Rebuilding](#rebuilding)).
Provenance lives inside the guest instead, in `/etc/kasa-image-release`:

```
ID=docker
DESCRIPTION=Hardened Debian agent host with Docker
RELEASE=deb13
DEBIAN_IMAGE_BUILD=20260722-2547
SOURCE_COMMIT=1f3c0c1e...
SOURCE_TREE_DIRTY=false
BUILT_AT=2026-08-05T20:14:03+00:00
```

## What is in the images

### Packages

Every template installs `ca-certificates`, `cloud-guest-utils`, `fail2ban`,
`nftables`, `openssh-server`, `qemu-guest-agent`, `rsyslog`, `sudo`,
`systemd-zram-generator`, and `unattended-upgrades`. First boot runs a full
update and upgrade before anything else is configured.

There are no language runtimes, build tools, or agent software. This is a base
image; agent payloads layer on top of a clone.

### Trust anchors

Two optional inputs let a host trust your own certificate authorities from its
first boot, instead of after a configuration run that has to reach the host
first — which is the awkward part, because reaching it is what you were trying
to arrange.

Both are public material. Neither is a credential, and nothing secret belongs in
a cloud-init payload: the vendor-data snippet is shared by every clone of a
template, and the rendered config stays readable on the guest afterwards. Leave
either unset and it renders away completely.

| `tools/.env` key | Effect in the guest |
| --- | --- |
| `SSH_USER_CA_PUBLIC_KEY` | Writes the CA public key to `/etc/ssh/kasa_user_ca.pub` and one `TrustedUserCAKeys` directive to `/etc/ssh/sshd_config.d/60-kasa-user-ca.conf`. The host then accepts short-lived SSH user certificates signed by that CA. |
| `KASA_ROOT_CA_FILE` | Adds one PEM certificate to the system trust store through cloud-init's `ca_certs` module, so the guest can validate certificates issued by your internal PKI. |

`60-` rather than `99-`: OpenSSH takes the first value it sees for most
keywords, and `99-harden.conf` owns `AllowUsers` and `AuthenticationMethods`.
The CA drop-in carries exactly one directive so it cannot shadow them.

**An SSH certificate does not bypass `AllowUsers`.** If you set a source
allowlist, a valid certificate from an address outside it is still refused —
which looks exactly like a broken CA. Check the allowlist first.

First boot requires **at least one** way to authenticate: an injected public key,
a trusted user CA, or both. With neither, the boot fails deliberately rather than
producing a VM nobody can enter. Both is the ordinary case and the safest one,
since the injected key is break-glass for a certificate outage.

Host key verification is a separate problem and this does not solve it. These are
user certificates; the first connection to a new host still has to accept its
host key.

The docker profile adds `docker-ce`, `docker-ce-cli`, `containerd.io`,
`docker-buildx-plugin`, `docker-compose-plugin`, `docker-ce-rootless-extras`
from `download.docker.com` (key pinned to fingerprint
`9DC858229FC7DD38854AE2D88D81803C0EBFCD88`), plus `uidmap`,
`dbus-user-session`, `slirp4netns`, and `iptables`.

Containers install a smaller set, because several of these exist only for a VM
or only for rootless Docker. See
[LXC containers](#lxc-containers).

### Configuration

| Area | What is set | Where |
| --- | --- | --- |
| User | `admin`, key-only, password locked, `NOPASSWD` sudo, in `adm` and `sudo` | `qm create --ciuser --sshkeys`, verified in `cloud-init-finalize` |
| Hostname | From the Proxmox VM name, including after cloning and renaming | Proxmox-generated user-data |
| SSH | Public key only for `admin`; no root; optional exact source restriction from `SSH_ALLOW_USERS` in `tools/.env`; `MaxAuthTries 3`; `LoginGraceTime 30s` | `/etc/ssh/sshd_config.d/99-harden.conf` |
| fail2ban | Aggressive `sshd` jail, escalating 30m bans, nftables actions | `/etc/fail2ban/jail.local` |
| Kernel | Restricted kptr and ptrace, unprivileged BPF off, redirects off, strict `rp_filter = 1`, SYN cookies | `/etc/sysctl.d/60-hardening.conf` |
| Updates | Debian unattended-upgrades defaults, enabled daily with no automatic reboot | `/etc/apt/apt.conf.d/20auto-upgrades` |
| Swap | zram only, `min(ram / 2, 512)` with zstd, `vm.swappiness = 100` | `/etc/systemd/zram-generator.conf` |
| Disk | Root grows on first boot, `fstrim.timer` enabled | cloud-init `growpart` |
| Remote syslog | Volatile journal forwarded to `SYSLOG_SERVER:SYSLOG_PORT` over plain TCP, memory-only queue | `/etc/rsyslog.d/01-remote.conf` |
| Local logging | profiles without `-syslog` use normal disk-backed rsyslog files and persistent fail2ban state | Debian package defaults |
| `/var/log` | Persistent on every profile; never a tmpfs, so package-created log directories survive a reboot | Debian package defaults |
| Docker | Rootless, `data-root` on `/mnt/appdata/docker`, journald log driver | `~admin/.config/docker/daemon.json` |
| APPDATA | Every VM gets a disk matched by WWN and serial, ext4 labelled `APPDATA`, mounted at `/mnt/appdata` | `bootcmd`, `appdata-verify.service` |
| First boot | Self-checks the bootstrap and remains running; failures write `/home/admin/logs/` | `cloud-init-post-verify.service` |

`templates/deb13/cloud-config.yml.tmpl` owns the public-safe base;
`SSH_ALLOW_USERS` in `tools/.env` owns optional private SSH source entries.

The SSH source policy uses OpenSSH's additive
[`AllowUsers USER@HOST`](https://man.openbsd.org/sshd_config#AllowUsers) matching. The two
governed `rp_filter` settings use Linux strict mode (`1`), not loose mode (`2`), as defined by
the [Linux kernel IP sysctl documentation](https://docs.kernel.org/networking/ip-sysctl.html).

### Rootless Docker

The VM profiles run Docker rootless. The profile descriptions in
`templates/profiles.yaml` deliberately say only "with Docker", because the same
description is copied into both a VM's and a container's provenance file and the
two implement Docker differently.

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
and send it to the collector instead.

- `systemd-journald` runs with `Storage=volatile`, so the journal lives in
  `/run/log/journal`.
- The rsyslog forwarding queue has no disk spool, and `01-remote.conf` ends in
  `stop` so the forwarded stream is not also written out by Debian's default
  on-disk rules.
- fail2ban logs to the journal and keeps its ban database in `/run`.

Why memory only logs?

Fewer disk writes, especially if you have many VM's.

What you give up with Memory Only:

- **An unreachable collector loses messages.** The queue holds about 25,000
  messages in RAM, then discards lowest severity first. There is no catch-up.
- **A sustained log storm is rate-limited** to 25,000 messages per 60 seconds.
- **Reboots lose the journal and the syslog stream.** Files an application wrote
  under `/var/log` itself survive.

Because the collector matters, the first-boot self-test probes it. On
the template build boot an unreachable collector is a warning, so the template
is still buildable without one. On a clone it is fatal, because the VM would
otherwise run blind.

## LXC containers

The same four profiles also build Proxmox LXC containers. A container is not a
small VM, so these are not the cloud-config translated into shell: the profile
semantics are shared, and every mechanism that only makes sense for a VM is
replaced or dropped deliberately.

Each profile emits two files:

| File | Runs on | Owns |
| --- | --- | --- |
| `create-kasa-deb13-lxc-<profile>.sh` | the Proxmox node | container ID, template, storage, CPU, memory, swap, network, SSH key, LXC features |
| `kasa-deb13-lxc-<profile>-bootstrap.sh` | inside the container | admin account, sshd, sysctls, fail2ban, logging, Docker |

| Container | Docker | APPDATA mount | Remote syslog | LXC features |
| --- | --- | --- | --- | --- |
| `kasa-deb13-lxc-base-syslog` | No | Yes | Always | none |
| `kasa-deb13-lxc-docker-syslog` | Yes | Yes | Always | `keyctl=1,nesting=1` |
| `kasa-deb13-lxc-base` | No | Yes | No; durable local logs | none |
| `kasa-deb13-lxc-docker` | Yes | Yes | No; durable local logs | `keyctl=1,nesting=1` |

Every container is unprivileged. The bootstrap reads `/proc/self/uid_map` and
refuses to run if CT root maps to host root, because a privileged container
would only look hardened.

### What the host owns and what the container owns

A container shares the host kernel, so several VM controls move to Proxmox:

| Concern | VM | LXC |
| --- | --- | --- |
| Memory and swap | zram inside the guest | `pct --memory` / `--swap` on the host |
| Discard / trim | guest `fstrim.timer` | the backing storage's concern |
| `kernel.*`, `fs.*`, `vm.*` sysctls | set in the guest | **host-owned**; read-only in a container |
| APPDATA | raw disk matched by WWN and serial, formatted by the guest | Proxmox-managed `mp0` volume |
| Root filesystem growth | `growpart` + `resize_rootfs` | `pct resize` on the host |
| Guest agent | `qemu-guest-agent` | not applicable |
| Bootstrap delivery | cloud-init | one shell script, run once |

The container's `/etc/sysctl.d/60-hardening.conf` therefore carries only keys it
actually owns — the `net.ipv4.*` and `net.ipv6.*` redirect, `rp_filter`, and
`tcp_syncookies` settings, which are per-network-namespace. `rp_filter` stays at
strict `1`. The bootstrap applies the file and then reads every value back,
failing if one did not take; it never hides a sysctl failure behind `|| true`.

The file sets `conf.all`, `conf.default` **and** `conf.*` for both redirect
settings, and that third one is load-bearing rather than belt-and-braces. The
kernel enables `accept_redirects` for an interface if *either* `conf/all` or
`conf/<interface>` is true (when forwarding is off), and `send_redirects` on the
same or-semantics — so `all = 0` on its own would leave `eth0`, and `docker0`
created earlier by the daemon, still accepting and sending redirects.
`conf/default` covers interfaces created later, including the veth pairs Docker
makes per container. `rp_filter` needs no wildcard because the kernel takes the
*maximum* of `conf/all` and the interface, so `all = 1` already forces strict
mode everywhere. The bootstrap verifies every interface, not just the
aggregates.

> **`kernel.kptr_restrict`, `kernel.yama.ptrace_scope` and
> `kernel.unprivileged_bpf_disabled` are not set inside the container.** They
> are host-global. Set them on the Proxmox node if you want them; a container
> cannot, and writing them in the guest would look like hardening while
> changing nothing.

### Why Docker gets two extra features and base does not

Docker profiles are created with `--features keyctl=1,nesting=1`. That is the
complete list, and it is per-profile:

- **`keyctl`** lets the daemon use the kernel keyring from inside a user
  namespace. Without it dockerd fails to start in an unprivileged container.
- **`nesting`** exposes `procfs` and `sysfs` so the container can run containers
  of its own.

Base profiles pass **no** `--features` argument at all. Proxmox already defaults
every feature to off, so writing `keyctl=0,nesting=0` would imply a toggle where
there is none.

> **`nesting` is a real widening.** Exposing `procfs` and `sysfs` gives
> processes in the container more of a view of the host than a container without
> it has. That is the cost of running Docker here, and it is why the two base
> profiles do not pay it.

Nothing enables `fuse`, `mknod`, `mount=`, `force_rw_sys`, privileged mode, or
an AppArmor override. The container keeps its normal AppArmor profile. The
create script re-reads `pct config` after creation and fails if any of those
appear, or if the container is not unprivileged.

### Docker runs as root inside an unprivileged container

The VM profiles use rootless Docker because on a VM, Docker's root *is* real
root. That reason does not carry over. An unprivileged container already maps CT
root to an unprivileged host UID:

```text
host
└── unprivileged Proxmox LXC     <- CT root is an unprivileged host user
    └── Docker daemon            <- rootful inside that namespace
        └── application containers
```

The outer user namespace is the boundary that matters, and it is already there.
Running rootless Docker inside it would nest a second user namespace, requiring
subordinate ID ranges, lingering, `dbus-user-session` and `slirp4netns`, without
improving isolation from the host. So these profiles run a normal rootful
daemon: Compose works, cgroup v2 resource limits work through the subtree
Proxmox delegates, the daemon starts at boot with nobody logged in, and the VM's
rootless-only packages are deliberately absent.

Unlike the VM profiles, a container's Docker **can** publish ports below 1024,
and `admin` is still not in a `docker` group — use `sudo docker`.

> **This is a KASA-supported Docker-in-unprivileged-LXC profile.** Upstream
> Proxmox documentation still recommends running application containers such as
> Docker inside a QEMU VM, even though Proxmox exposes `keyctl` for exactly this
> case. Nothing here claims that nested Docker is Proxmox's recommended
> production architecture. If you want the vendor-recommended shape, use the
> `kasa-deb13-docker-syslog` VM template instead.

### APPDATA and where Docker actually stores things

`/mnt/appdata` is a Proxmox-managed mount point (`mp0`) on all four container
profiles. The container never runs `mkfs`, inspects a WWN or serial, or looks at
`/dev/disk/by-id` — it has no raw device to inspect. It only asserts that the
mount is present, writable, root-owned, and not group- or world-writable, via
`/usr/local/sbin/kasa-appdata-guard`.

Docker's persistent state has two roots, not one:

```text
/etc/docker/daemon.json      "data-root": "/mnt/appdata/docker"
/etc/containerd/config.toml  root = "/mnt/appdata/containerd"
```

> **Setting `data-root` alone is not enough on current Docker.** Since Docker
> Engine 29 the containerd image store is the default on a fresh install, and
> image content and container snapshots live under containerd's own `root`, not
> under `data-root`. A container configured with only `data-root` would still
> fill its root filesystem with every image it pulled.

The bootstrap masks `docker.service`, `docker.socket` and `containerd.service`
across installation so neither daemon ever starts against its default paths,
generates containerd's config from `containerd config default`, and then
verifies the paths Docker and containerd *resolved* — `docker info` and
`containerd config dump` — rather than trusting the files it wrote. It also
asserts that `/var/lib/docker` and `/var/lib/containerd` are empty.

Both daemons carry an `ExecStartPre` guard, so if `/mnt/appdata` is missing
Docker **refuses to start** instead of silently falling back to the container's
root filesystem.

Docker logs to `journald` with the same container-name tag and Compose labels as
the VM profiles, so on a remote-syslog container the application logs travel the
same path as everything else:

```text
container stdout/stderr -> journald -> rsyslog/imjournal -> collector
```

Because the journal is volatile on those profiles, `journalctl` history does not
survive a reboot; the collector is the durable copy.

### First-boot upgrade

Like the VM profiles, the bootstrap runs a full upgrade before configuring
anything, because the container template is pinned by hand and can be months
behind. `ca-certificates` is installed first, ahead of any third-party HTTPS
repository.

### Logging, SSH, and fail2ban

These match the VM policy. The `-syslog` containers run `journald` with
`Storage=volatile` and `RuntimeMaxUse=64M`, forward through `imjournal` with a
memory-only queue that ends in `stop`, and keep fail2ban's database in `/run`.
The other two keep Debian's normal durable local logging. `/var/log` is a
persistent directory on all four.

One difference is deliberate: a container is bootstrapped live, not built as a
template, so an **unreachable collector aborts the bootstrap** before the journal
is made volatile. A VM template build only warns, because the template has to be
buildable without a collector.

Proxmox seeds the SSH key you supply into **root's** `authorized_keys`. The
bootstrap then migrates access to `admin`, in this order:

1. Confirm root (or a previous run's `admin`) holds a key that `ssh-keygen`
   accepts. Nothing changes if not.
2. Create `admin`: locked password, `/bin/bash`, `adm` and `sudo`,
   `/home/admin` `0700`, `.ssh` `0700`, `authorized_keys` `0600`, and
   `/home/admin/apps`.
3. Merge root's keys with any `admin` already had, without duplicates, and
   validate the result.
4. Write passwordless sudo and check it with `visudo -cf`.
5. Write the sshd hardening drop-in and test it with `sshd -t`.
6. Only then reload sshd, and read the policy back with `sshd -T`.

Any failure before step 6 leaves root access exactly as it was, so there is no
path to locking yourself out. Afterwards, log in as `admin`.

fail2ban bans through nftables in the container's own network namespace. Rather
than assume that works, the bootstrap installs a real ban, confirms it appears in
`nft list ruleset`, and withdraws it — failing loudly if it could not. A
detect-only configuration is not shipped as if it were enforcement.

### Creating, bootstrapping, and verifying a container

First check the storage names. A container rootfs and mount point need storage
that accepts `rootdir` content, and on a standard install `local` does **not** —
it carries only `iso`, `vztmpl` and `backup`. Run `pvesm status --content
rootdir` on the node and set `LXC_ROOTFS_STORAGE` and `LXC_APPDATA_STORAGE` in
`tools/.env` accordingly; the defaults are `local-lvm`. `LXC_TEMPLATE_STORAGE`
does want `local`, which carries `vztmpl`. The create script verifies all three
before it touches anything, and names the storages that would work if one is
wrong.

Then copy a create script and its matching bootstrap to the node, keeping the
pair in the same directory:

```bash
bash create-kasa-deb13-lxc-docker-syslog.sh
```

`--ctid` and `--hostname` override the built-in values, so one profile can
provision more than one container without editing `tools/.env` and rebuilding:

```bash
bash create-kasa-deb13-lxc-docker-syslog.sh --ctid 9210 --hostname buzz-worker
```

It downloads the pinned Debian 13 container template if needed, creates the
container, checks the resulting `pct config`, starts it, verifies the bootstrap's
checksum, uploads it, and prints the one command that completes the container:

```bash
pct exec 9101 -- /root/kasa-deb13-lxc-docker-syslog-bootstrap.sh
```

There is **no `--replace`**. If the container ID already exists the script stops
and says so; removing a container stays something you do yourself.

The bootstrap is idempotent and can be re-run, and a re-run converges rather
than just completing: every service whose configuration it rewrites is
restarted, so changes actually take effect. On a Docker profile that means a
re-run bounces the daemon and any running application containers. It is also
independently usable against any already-created container that matches the
profile's assumptions
(unprivileged Debian 13, `/mnt/appdata` mounted, an SSH key on root, and
`keyctl=1,nesting=1` for a Docker profile).

It verifies its own work before exiting non-zero on any problem: services
enabled for reboot, `/var/log` not on tmpfs, admin's key and permissions, and on
Docker profiles the daemon state, Compose plugin, storage driver, resolved
storage paths (`docker info` and `containerd config dump`, not the files it
wrote), logging driver, and that `/var/lib/docker` and `/var/lib/containerd` are
empty.

None of that runs a container. `--docker-smoke-test` additionally starts a
throwaway container and checks runtime, DNS, the APPDATA bind mount, and that a
`--memory` limit is really enforced by reading `memory.max` from inside it,
removing the container and image afterwards. It is **off by default** on purpose:
it pulls and executes an image from a public registry and needs working DNS, and
neither belongs in the critical path of provisioning a container.
`--smoke-image REF` chooses the image, so it can be pinned by digest.
`docs/lxc-runtime-test.md` runs it deliberately as an acceptance gate.

Provenance lands in `/etc/kasa-lxc-release`:

```text
ID=docker
DESCRIPTION=Hardened Debian agent host with Docker
RELEASE=deb13
EXPECTED_LXC_TEMPLATE=debian-13-standard_13.1-2_amd64.tar.zst
DOCKER=yes
LOGGING=remote
SOURCE_COMMIT=<commit this was rendered from>
SOURCE_TREE_DIRTY=false
RENDERED_AT=<when the artifact was built>
BOOTSTRAPPED_AT=<when this container ran it>
```

It records two timestamps because there are two events, and it never claims an
image build: Proxmox created the container, and the bootstrap configured it.

The template field says `EXPECTED_` for the same reason. The bootstrap is usable
against any compatible container, so it cannot know which template the running
one was actually created from — only which one the artifact was built for.

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
