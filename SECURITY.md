# Security policy and boundaries

This project manages privileged networking and private client credentials. A
source review or passing tests is not a certification or a guarantee of safety.
Only the latest reviewed release is supported; install OS security updates and
review upstream protocol deprecation notices.

## Reporting

Report reproducible security issues privately using GitHub's **Report a
vulnerability** feature for this repository when enabled. Include the affected
release, prerequisites, exact code locations and a minimal reproduction without
real keys/passwords. Do not publish live credentials, private profiles or server
backups in issues. If private reporting is unavailable, contact the maintainer
through their GitHub profile to arrange a private channel before disclosure.

## Intended protections

- HTTPS with verified public IP certificates and unattended renewal; no insecure
  TLS client flags. A separate private CA is used for IKEv2 and OpenVPN.
- Random installation-specific admin password, scrypt password hashing, hashed
  session tokens, 12-hour sessions, Secure/HttpOnly/SameSite=Strict cookies,
  login throttling, CSRF tokens and same-origin checks for mutations.
- Authenticated configuration downloads, strict ID/type allowlists, no-store
  responses, CSP/frame protection and local bundled fonts/assets.
- Unprivileged web process, dedicated VPN identities, root-owned executable code
  and export directories. The privileged worker exposes no HTTP or arbitrary
  shell-command interface. User fields and stored port settings are validated.
- OpenVPN accounting directory is root-owned/non-writable by the daemon. Hook
  and reader use `O_NOFOLLOW`, regular-file/owner/link-count checks and file locks.
- Fixed command argument arrays, parameterized SQL, serialized JSON/plist data
  and strict handling of generated paths/line-oriented credentials.
- VPN clients are blocked from host/private/cloud-metadata networks. Xray has
  both routing checks and process-owner egress rules; local DNS is explicitly
  permitted. IPv6 client egress is blocked until a proper IPv6 service is added.
- Shared quota/expiry enforcement, active-session removal, final OpenVPN
  disconnect counters and IKEv2 event observations. Meter failure disables finite
  quota accounts during healthy worker reconciliation.
- Root-only backups and CA keys; client exports are readable by the authenticated
  web service but not writable by it. Public code and runtime secrets are separate.

## Explicit limitations

- Private user-page/subscription URLs are bearer credentials. Tokens are randomly
  generated with 256 bits of entropy and stored alongside other private account
  data in the panel database so the administrator can retrieve/share them again.
  Do not publish URLs or QR codes. Rotation/revocation invalidates the old URL;
  it does not revoke profiles already downloaded. Disable the account to stop
  its VPN access. User endpoints enforce the account's current status and enabled
  protocols, use no-store/no-referrer/noindex, and the managed nginx/Uvicorn
  configuration disables access logs to avoid recording bearer paths. Third-party
  proxies and access log collectors must also avoid recording these URLs.

- The admin listener is public where your firewall permits. Restrict TCP 8443 to
  trusted source networks or an SSH tunnel when appropriate. There is no MFA or
  multi-admin/tenant isolation in this initial release.
- A compromised administrator/web process can read client exports and modify
  account data. That is an administration trust boundary, not a secret vault.
  A root compromise can control every service and credential on the server.
- The root worker and daemon counters are trusted. Polling is not byte-exact;
  crashes, abrupt restarts and sessions shorter than observation windows can lose
  unflushed counters. It is not suitable for adversarial financial billing.
- OpenVPN certificates allow one simultaneous session; they cannot be made
  uncopyable by a configuration file. Client files embed private keys by design.
- No protocol guarantees resistance to censorship, active probing or IP blocking.
  Fake TLS/DNS aliases do not hide the server IP. Telegram has a separate public
  shared credential and is not covered by VPN user quotas.
- The installer trusts Ubuntu/PyPI/npm and official upstream HTTPS distribution
  plus matching checksums. Checksums from the same source are not independent
  signatures or a complete supply-chain security guarantee.
- Preserve SSH and a separate secure backup. Upgrade failures are not universally
  transactional. Cloud firewall configuration and OS maintenance remain the
  operator's responsibility.
- One-server deployment only. Native-client interoperability, IPv6 leak behavior
  and reachability must be verified on the actual devices and networks in use.

## Repository security review guidance

Review unauthenticated HTTP → session/CSRF controls; authenticated account input →
root reconciliation; writable SQLite/settings → root configurator; daemon spool
→ privileged file access; configuration downloads → credential exposure; and
VPN traffic → host/private metadata access. Treat installer/upgrader interactions
with existing mutable state as security-sensitive, even when triggered by root.
Do not commit runtime state, CA/signing keys, admin credentials or client profiles.
