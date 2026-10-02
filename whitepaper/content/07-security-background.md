# Our Security Background

Attestium grew out of the operation of [Forward Email](https://forwardemail.net), an open-source email service whose production environment is managed entirely through [open-source Ansible playbooks](https://github.com/forwardemail/forwardemail.net/tree/master/ansible) that anyone can inspect. This section describes that hardening, and why it is paired with point-in-time audits and continuous automated verification.

## Ansible-Managed Infrastructure

Every server we operate is provisioned and hardened through Ansible. Security measures are codified, version-controlled, and reproducible rather than applied by hand. Here's what our playbooks enforce.

### Kernel and System Hardening

We disable core dumps entirely — hard and soft limits set to zero, `fs.suid_dumpable=0`, `ProcessSizeMax=0` in systemd, and `kernel.core_pattern` piped to `/bin/false`. Transparent Huge Pages are disabled via a systemd service. Swap is turned off on most servers; our MongoDB, Valkey and logs servers keep a small emergency swap with `vm.swappiness=1`. Every server gets more than 40 sysctl kernel parameters, and database servers get more, including ASLR (`kernel.randomize_va_space=2`), TCP SYN cookies for flood protection, RFC 1337 TIME-WAIT assassination protection, and TCP buffers scaled to available RAM.

`/dev/shm` is mounted as `tmpfs` with `noexec,nosuid,nodev`, so code cannot execute from shared memory. The root filesystem is mounted with `noatime`, `nodiratime` and `discard`. On database data drives we set the I/O scheduler by device type (`none` for multi-queue devices such as NVMe, `deadline` otherwise) and tune read-ahead. Web, API, CalDAV and CardDAV servers and database servers use TCP BBR congestion control; mail servers use CUBIC with `fq_codel`.

### USB Device Whitelisting

The `usb-storage` kernel module is disabled via `modprobe.d` and the initramfs is rebuilt to persist this across reboots. We maintain a whitelist of authorized USB devices by `vendor:product` ID in `/etc/security-monitor/authorized-usb-devices.conf`. Any unrecognized USB device triggers an immediate email alert to the team. Udev rules (`99-usb-monitor.rules`) provide real-time detection on top of the 5-minute polling cycle. A datacenter technician plugging in a USB drive gets flagged instantly.

### SSH and Access Control

Root login is disabled (`PermitRootLogin no`). Password authentication is disabled — only key-based auth is allowed. The root password is locked. We maintain two users: `devops` (with sudo, no password prompt) and `deploy` (with a 4096-bit SSH key, limited privileges). Fail2Ban is configured aggressively: 2 failed attempts trigger a permanent ban (`bantime=-1`) with a 365-day find window, and bans are shared across all of our servers. Alerts go out through a send-only Postfix configuration that listens on no TCP port, accepts mail only from root, and delivers straight to the recipient's mail server with no relay credentials.

### Nine Security Monitoring Systems

We run nine independent monitoring systems, all implemented as systemd timers with rate-limited email alerts:

1. **System Resource Monitor** — CPU, memory, and disk usage with five threshold levels (75%, 80%, 90%, 95%, 100%), checked every 5 minutes.
2. **SSH Security Monitor** — Failed logins, successful logins, root access, unknown IPs, and after-hours logins, checked every 10 minutes.
3. **USB Device Monitor** — Unknown device detection with vendor:product ID whitelisting, checked every 5 minutes plus real-time udev rules.
4. **Root Access Monitor** — Direct root login, sudo usage, `su` to root, and privilege escalation attempts, checked every 5 minutes.
5. **Lynis Audit Monitor** — Automated [Lynis](https://cisofy.com/lynis/) security audits, run daily.
6. **Package Monitor** — Tracks every package installation and removal, checked hourly.
7. **Open Ports Monitor** — Detects unexpected listening services, checked hourly.
8. **SSL Certificate Monitor** — Checks TLS certificate expiry dates daily.
9. **Outbound Traffic Monitor** — Alerts on sustained outbound traffic above a set limit, checked every minute.

Each monitor uses whitelist files in `/etc/security-monitor/` for authorized IPs, users, USB devices, root users, and sudo users. Rate limiting prevents alert flooding — resource alerts have a 1-hour cooldown per threshold, SSH root access alerts have no cooldown (always alert), and USB alerts have a 1-hour cooldown per device.

### Command Logging and Auditing

Every command executed on our servers is logged through multiple layers: `auditd` with custom audit rules, enhanced bash logging in both `/etc/profile.d/` (login shells) and `/etc/bash.bashrc`, zsh logging in `/etc/zsh/zshrc.d/`, and `rsyslog` capturing everything to `/var/log/bash-commands.log` with 30-day logrotate retention. If someone runs a command on our servers, we have a record of it.

### Automatic Security Updates

Unattended upgrades install security patches automatically. Servers reboot at 08:00 UTC when an update requires it, never while someone is logged in; our MongoDB, Valkey and logs servers do not reboot automatically. We deploy a custom port scan protection script (our own [maintained fork](https://github.com/forwardemail/portscan-protection)). DNS resolves through a local Unbound caching resolver that forwards to Cloudflare and Google over DNS-over-TLS. MongoDB is installed from the official repository and Valkey is compiled from source. Our only external Ansible code is three roles (DNS, fail2ban and sysctl) and three collections, each pinned to an exact version in `requirements.yml`.

## Audits and Continuous Verification

A one-time security audit from a reputable firm costs $5,000–$10,000 USD or more. That buys you a snapshot — a report that says "on this date, we checked these things and they looked fine." The moment the audit ends, the report starts going stale. New code gets deployed, packages get updated, configurations change. The audit doesn't tell you what happened last Tuesday at 3 AM.

But the cost isn't the real problem. The real problem is trust.

We manage email. Email is the most sensitive communication channel most people have — password resets, financial statements, legal correspondence, medical records. Giving a third-party auditor SSH access to our production servers means trusting them with access to all of that. Even with the best intentions, an audit can take weeks or months. During that entire window, we'd need to monitor their access, verify they aren't exfiltrating data, and hope that their own systems haven't been compromised. We'd essentially need to audit the auditor.

We have since completed a third-party security audit by [Cure53](https://cure53.de/) and [published the report](https://forwardemail.net/pentest-report_forward-email.pdf). Audits and continuous verification answer different questions. An audit is a deep, expert review of the code and systems at one point in time. Continuous verification checks the running state after every deploy and between deploys. It runs on a schedule and needs no interactive access to the servers: the verifier's SSH key can run only the attester, which accepts three operations (collect evidence for a nonce, and the two steps of TPM enrollment) and nothing else.

## From Hardening to Verification

The hardening described above (the sysctl parameters, USB whitelisting, the nine monitoring systems, command logging) consists of preventive controls. They make an attack harder, but they do not answer the question a user of the service cares about: is the code running on this server now the code in the public repository?

Attestium answers that question. The Ansible playbooks are designed to prevent unauthorized changes; Attestium and Audit Status are designed to detect them, on a schedule, with results that anyone can check against the public repository and the public releases the service depends on. Process memory integrity extends the question to the code executing in memory, and hardware-backed evidence extends it to an attacker who has root on the server. On a hardened server, the attacker to plan for is not only one who modifies files, but one who modifies memory or the tools that report on it.

\newpage
