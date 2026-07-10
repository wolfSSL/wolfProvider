# wolfProvider CI

This directory holds the GitHub Actions configuration for wolfProvider —
55 workflows organized into three tiers: per-PR checks (fast feedback),
a nightly OSP suite (heavy integration), and reusable building blocks
that the other two compose.

There is no Jenkinsfile in this repo. GitHub Actions is the source of
truth for CI. The Jenkins jobs that build the `libwolfssl`,
`libwolfprov`, and `libssl3` `.deb`s are *upstream* of these workflows
— they publish the artifacts to `ghcr.io/wolfssl/wolfprovider/debs:{fips,nonfips}`,
which `_discover-versions.yml` then resolves on the fly.

## At a glance

| Tier | Trigger | Wall time | Purpose |
|------|---------|-----------|---------|
| **PR / push** | every push to master/release, every PR (non-draft) | ~5–30 min per job, parallel | smoke + style + unit / cmd tests against fresh source builds |
| **Nightly** | `cron: 0 6 * * *` UTC, or `workflow_dispatch` | ~60–90 min end-to-end | real-world integration against 40+ OSS projects, sanitizers, static analysis |
| **Reusable** | `workflow_call` only | varies | shared subroutines (build, version discovery, debian package) |

## PR / push workflows

These run on every pull request (synchronize, opened, reopened,
ready_for_review) and on every push to `master`, `main`, or
`release/**`. Drafts are skipped via `if: ... draft == false`.

| Workflow | What it does |
|----------|--------------|
| `simple.yml` | Builds wolfProvider against the matrix of supported wolfSSL + OpenSSL refs and runs `make check`. The baseline "did anything obvious break" check. |
| `smoke-test.yml` | Minimal end-to-end: build, load the provider into stock OpenSSL, run `openssl list -providers` and a handful of `openssl` subcommands. Catches link-time and provider-registration regressions. |
| `cmdline.yml` | Runs `scripts/cmd_test/do-cmd-tests.sh` — exercises every `openssl` CLI verb (genrsa, pkeyutl, enc, dgst, …) through wolfProvider. |
| `fips-ready.yml` | Same as `simple` but builds wolfSSL with `--enable-fips=ready`. Sanity check that FIPS-ready compiles and basic tests pass without the full FIPS bundle. |
| `seed-src.yml` | Builds with `--enable-seed-src` (entropy seed source variant) and `-DWP_TEST_SECCOMP_SANDBOX`, then runs the unit tests including the OpenSSH fork+seccomp-sandbox regression suite. |
| `multi-compiler.yml` | Cross-compiler sweep: gcc-9 through gcc-14 and clang-12 through latest. Catches toolchain-specific warnings / UB. |
| `codespell.yml` | Spell-check on tracked source. `*.patch` is excluded because OSP patches mirror upstream source whose original spelling we shouldn't silently rewrite. |
| `sanitizers.yml` | Builds wolfProvider with `-fsanitize=address,undefined` (one job) and `-fsanitize=thread` (separate job — TSan and ASan can't coexist in one binary), runs `make test` + `cmd_test/do-cmd-tests.sh` under each. Caches OpenSSL + wolfSSL source/install to avoid the ~15 min rebuild on every push. |
| `publish-test-deps-image.yml` | Builds and publishes `ghcr.io/wolfssl/wolfprovider-test-deps:bookworm` whenever `docker/wolfprovider-test-deps/**` changes on master. This image is what the nightly OSP jobs run inside. |

## Nightly OSP suite

`nightly-osp.yml` is the orchestrator. It fires daily at 06:00 UTC (or
on `workflow_dispatch`) and fans out to every OSP integration workflow
in parallel via `workflow_call`. A final `notify` job aggregates pass /
fail across all jobs and posts a single summary to Slack (or to the job
summary page if the `SLACK_WEBHOOK_URL` secret is unset).

**Why nightly and not per-PR?** Each OSP job:

1. Pulls a third-party project (krb5, hostap, stunnel, curl, openssh, …)
2. Applies the matching patch from `wolfssl/osp/wolfProvider/<app>/`
3. Builds it against the wolfProvider `.deb` stack (real `libssl3` replace-default install)
4. Runs the project's own test suite (often dozens of minutes)
5. Repeats across the FIPS + non-FIPS matrix, with and without
   `WOLFPROV_FORCE_FAIL=1` to confirm the negative case also fires.

Running the full set on every PR push would burn ~60–90 min of CI per
push and dominate the merge queue. Nightly is the right cadence for
catching regressions in third-party integration that wouldn't show up
in our unit tests.

### Running a nightly job on a PR (label toggles)

`pr-osp-select.yml` lets you pull any nightly job into a PR on demand —
to fix or validate it before it has to wait for the next nightly. You
toggle jobs with **labels**, not code edits; `nightly-osp.yml` and the
per-app workflows stay untouched.

| Label | Effect |
|-------|--------|
| `ci:<name>` | Run that one job (e.g. `ci:hostap`, `ci:curl`, `ci:static-analysis`). Add several to run several. |
| `ci:all` | Run the whole fan-out (all 43 jobs). |
| (no label) | Nothing runs — a normal PR is unaffected. |

`<name>` is the job key in the table below (the workflow base name, e.g.
`hostap`, `openssl-version`, `multi-compiler` → `nightly-multi-compiler.yml`).

The dispatcher fires **only on label change** (`labeled`/`unlabeled`),
not on push — so an unlabeled PR shows zero `PR OSP` rows. Add a label
and the selected job starts; the unselected jobs show as *skipped*
(neutral, non-blocking, collapsed under "skipped checks"). After
pushing a fix while a label is on, re-run by toggling the label off and
on again (or hit "Re-run" on the run). When you're done validating,
drop the labels — nothing to revert in the tree.

Off-PR equivalent (runs against a branch, no labels):

```bash
gh workflow run pr-osp-select.yml --ref <branch> -f jobs="hostap curl"
gh workflow run pr-osp-select.yml --ref <branch> -f jobs="all"
```

> Adding a brand-new OSP workflow? Append a matching label block to
> `pr-osp-select.yml` (same `needs: select` + `if:` pattern) so it's
> reachable via `ci:<name>`.

### What runs in the nightly fan-out

43 workflows total: 40 third-party OSS integrations, 2 internal
validations, and the static-analysis suite. Every one of these patches
the upstream project (where needed) via `osp/wolfProvider/<app>/*.patch`
from [wolfssl/osp](https://github.com/wolfssl/osp), builds it against
the replace-default wolfProvider `.deb` stack, and runs the project's
own test suite end-to-end. Both FIPS and non-FIPS matrices are
exercised, with and without `WOLFPROV_FORCE_FAIL=1`.

#### Networking, VPN, file transfer

| Workflow | Project | wolfProvider surface exercised |
|----------|---------|-------------------------------|
| `openssh.yml` | OpenSSH client + server | SSH2 KEX, host key sign/verify, hostbased auth, sftp |
| `openvpn.yml` | OpenVPN | control-channel TLS, tls-auth/tls-crypt HMAC, data-channel ciphers |
| `stunnel.yml` | stunnel TLS proxy | server + client TLS 1.2 termination (TLS 1.3 + X25519/X448 paths skipped in FIPS) |
| `nginx.yml` | nginx web server | server-side TLS, certificate selection, OCSP stapling |
| `nginx-pqc.yml` | oqs-demos nginx (PQC) | ML-DSA (FIPS 204) cert auth + ML-KEM/hybrid (FIPS 203) KEX over TLS 1.3 (master + latest -stable, v5.9.2 PQC floor) |
| `socat.yml` | socat (multipurpose relay) | OpenSSL bridge mode (TLS in/out) |
| `tcpdump.yml` | tcpdump packet capture | build + link against wolfprov-backed libssl (no live decrypt) |
| `tnftp.yml` | NetBSD FTP client | FTPS (TLS over FTP control + data) |
| `iperf.yml` | iperf3 throughput tester | --rsa-private-key authenticated mode |
| `rsync.yml` | rsync file sync | stunnel-wrapped rsync transport |
| `x11vnc.yml` | x11vnc VNC server | -ssl mode (server-side TLS) |
| `ppp.yml` | Point-to-Point Protocol | MS-CHAPv2 + EAP-TLS authentication |
| `python3-ntp.yml` | NTPsec Python bindings | NTPsec key digests + autokey crypto |
| `bind9.yml` | ISC BIND DNS | DNSSEC sign/verify, TLS for DoT/DoH |

#### Auth, identity, PKI, smart cards

| Workflow | Project | wolfProvider surface exercised |
|----------|---------|-------------------------------|
| `krb5.yml` | MIT Kerberos | KDC + kadmin DES/AES key derivation, GSSAPI |
| `openldap.yml` | OpenLDAP server + client | LDAPS, START TLS, SASL EXTERNAL |
| `sssd.yml` | SSSD identity daemon | LDAP + Kerberos backend through wolfprov |
| `pam-pkcs11.yml` | PAM PKCS#11 module | smartcard login via PKCS#11 token + wolfprov-backed verify |
| `opensc.yml` | OpenSC smartcard middleware | PKCS#15 / pkcs11-tool cert + key ops |
| `sscep.yml` | SCEP enrollment client | CSR signing + SCEP message envelope decrypt/encrypt |
| `git-ssh-dr.yml` | git over SSH (wolfSSL custom) | ed25519/RSA host key + signing path through OpenSSH stack |
| `libfido2.yml` | FIDO2 / WebAuthn | CTAP2 ECDSA signatures, HMAC-secret extension |

#### TPM, disk crypto, hashing

| Workflow | Project | wolfProvider surface exercised |
|----------|---------|-------------------------------|
| `libtss2.yml` | tpm2-tss (TPM 2.0 software stack) | session HMAC, parameter encryption (AES-CFB) |
| `tpm2-tools.yml` | tpm2-tools CLI | command-line TPM ops layered on libtss2 |
| `libcryptsetup.yml` | LUKS / cryptsetup | LUKS2 header HMAC, AES-XTS / Argon2 key derivation |
| `libhashkit2.yml` | libhashkit2 (libmemcached) | hash functions (MD5/SHA via wolfprov) |

#### Web, messaging, libraries

| Workflow | Project | wolfProvider surface exercised |
|----------|---------|-------------------------------|
| `curl.yml` | curl HTTP client | TLS client (HTTPS, FTPS, IMAPS, etc.), runs against `curl-8_4_0` + `curl-7_88_1` |
| `libssh2.yml` | libssh2 SSH client lib | SSH2 KEX + host key + cipher path |
| `libwebsockets.yml` | libwebsockets | WSS server + client (TLS 1.2/1.3) |
| `libnice.yml` | libnice (ICE for WebRTC) | DTLS-SRTP key exchange |
| `cjose.yml` | C JOSE | JWS/JWE/JWK (RSA-OAEP, A256GCM, ES256) |
| `liboauth2.yml` | OAuth 2.0 for Apache | JWT signing/verification, OIDC TLS |
| `grpc.yml` | gRPC C++ | TLS channel credentials, ALTS interop |
| `xmlsec.yml` | xmlsec | XML-DSig + XML-Enc (RSA-SHA256, AES-128/256-GCM) |
| `libeac3.yml` | OpenEAC (eID auth) | ePassport BAC/PACE + EAC3 chip auth |
| `librelp.yml` | rsyslog RELP transport | TLS session resumption (the recent FIPS 5.9.1 regression site) |
| `net-snmp.yml` | Net-SNMP | SNMPv3 USM (HMAC-SHA + AES priv) |
| `qt5network5.yml` | Qt5 Network (QSslSocket) | Qt's TLS path through the wolfprov-backed libssl |
| `systemd.yml` | systemd | journald-remote TLS, systemd-timesyncd NTS |

#### Wireless

| Workflow | Project | wolfProvider surface exercised |
|----------|---------|-------------------------------|
| `hostap.yml` | hostapd + wpa_supplicant | WPA2-PSK + EAP-TLS/TTLS/PEAP via UML kernel + hwsim VM. The heaviest job (~45 min). |

#### Internal validations + sweeps

| Workflow | Purpose |
|----------|---------|
| `debian-package.yml` | End-to-end check: builds the wolfprov `.deb`s and confirms they install cleanly on a fresh container and the provider loads. |
| `openssl-version.yml` | Sweeps every upstream `openssl-3.X.Y` release tag — catches breakage from OpenSSL point releases before they hit our matrix defaults. |
| `static-analysis.yml` | cppcheck, clang scan-build, Facebook Infer. Heavy enough that it lives in the nightly fan-out rather than per-PR. |

Sanitizers (ASan+UBSan, TSan) run on every PR/push — see the PR table
above. They're fast enough with caching to gate merges, so they don't
need to live in the nightly.

The `notify` job's `needs:` list must stay in sync with the fan-out
above. Adding a new OSP? Add the `<name>:` block to the `jobs:` map AND
to the `needs:` list in the `notify` job — otherwise the aggregate
status will be wrong.

### OSP workflow shape

Every OSP workflow follows the same template:

```yaml
on:
  workflow_call: {}
  workflow_dispatch: {}

jobs:
  discover_versions:
    uses: ./.github/workflows/_discover-versions.yml

  build_wolfprovider:
    uses: ./.github/workflows/build-wolfprovider.yml
    # matrix over wolfssl_ref x openssl_ref x [FIPS, non-FIPS] x replace_default

  test_<app>:
    container: ghcr.io/wolfssl/wolfprovider-test-deps:bookworm
    # 1. download debian-packages-* artifact from build job
    # 2. apt install + apt-mark hold the wolfprov-patched libssl3
    # 3. verify-install.sh --replace-default --fips
    # 4. checkout app + wolfssl/osp, apply osp/wolfProvider/<app>/*.patch
    # 5. build app, run its test suite, check exit code
```

The `osp/wolfProvider/<app>/` patches live in
[wolfssl/osp](https://github.com/wolfssl/osp) — a separate repo.
Updating an OSP integration usually means a PR to that repo first,
then bumping refs here.

### Force-fail sanity check (`WOLFPROV_FORCE_FAIL=1`)

Every OSP job runs the matrix twice — once normally, once with
`WOLFPROV_FORCE_FAIL=1` which forces wolfProvider's primitives to
return failure. The force-fail run is *expected to fail*; if it
unexpectedly passes, it means the test wasn't actually exercising
wolfProvider and the test is dead weight.
`.github/scripts/check-workflow-result.sh` encodes that XOR.

## Reusable / internal workflows

| Workflow | Triggered by | Purpose |
|----------|--------------|---------|
| `_discover-versions.yml` | `workflow_call` | Pulls the wolfprov `.deb` artifact descriptors from ghcr.io, parses the wolfSSL + OpenSSL version stamps out, exposes them as outputs + JSON arrays for downstream matrices. The underscore prefix is just a sorting convention. |
| `build-wolfprovider.yml` | `workflow_call` | Builds wolfProvider from source against a given (wolfssl_ref, openssl_ref, fips_ref, replace_default) tuple, packages it as `.deb`, uploads as `debian-packages-*` artifact for downstream jobs to install. |
| `debian-package.yml` | nightly | End-to-end check that the `.deb`s built by `build-wolfprovider` install cleanly on a fresh container and the provider loads. |

## Sanitizers + static analysis

`sanitizers.yml` runs on every PR/push. Two jobs:

| Job | Flags | What it catches |
|-----|-------|-----------------|
| `sanitizers` (ASan + UBSan) | `-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all` | use-after-free, double-free, out-of-bounds read/write, signed overflow, misaligned access, NULL deref, etc. |
| `tsan` (Thread Sanitizer) | `-fsanitize=thread` | data races + lock-ordering violations in the multi-threaded unit tests in `test/unit.c` (`pthread_create` fan-out). |

ASan and TSan can't coexist in one binary, so they're separate jobs
with separate caches. Both use `LD_PRELOAD=libasan.so` / `libtsan.so`
for the unit-test run because wolfProvider is loaded via `dlopen()`
from OpenSSL and the runtime needs the sanitizer interceptors live
before any provider code runs. `ASAN_OPTIONS=detect_odr_violation=0`
is set to suppress a known false positive from the provider's static
ASN.1 table being linked into both `libwolfprov.so` and the test
binary.

`static-analysis.yml` runs nightly too. Three jobs:

| Job | Tool | Notes |
|-----|------|-------|
| `cppcheck` | `cppcheck --enable=all` on `src/` | Fails on any `error:` line. Warnings are reported but don't fail. |
| `scan-build` | `clang --analyze` via `scan-build` | Currently fails only if bug count > 50 (rolling baseline). HTML report uploaded as artifact. |
| `infer` | Facebook Infer | Currently fails only if issue count > 100. CSV + text report uploaded. |

The scan-build and infer thresholds are baseline-based, not strict —
they let pre-existing issues slide but flag obvious regressions.
Bringing them to 0 is a future cleanup.

## Overhead regression testing

`perf-regression.yml` (workflow display name **Overhead Regression**) runs nightly at 07:00 UTC (and on
`workflow_dispatch`). Customers run scripts that fire many `openssl`
commands in a row, and each invocation is a fresh process paying a full
wolfProvider init (plus, in FIPS builds, the per-algorithm CAST on first
use). This job guards the per-invocation cost of that path so a repeat of
the DH-CAST init blow-up gets caught automatically.

**This is an overhead regression tripwire, not a crypto throughput
benchmark, and not a wolfProvider-vs-OpenSSL speed comparison.** It only
asks one question: did per-command load/init overhead grow versus the
committed baseline? A loadable provider inherently pays process-startup
cost the built-in default provider does not, so the measured `overhead`
is expected to sit above 1.0 — that is not a defect and not a crypto-speed
result.

`scripts/perf_test/do-perf-tests.sh` times a small set of representative
commands — a near-no-op init probe (`list -providers`, `version`) plus
real verbs (`dgst`, `enc`, `genpkey` RSA/EC, `pkeyutl` sign, DH derive) —
taking the **minimum** of N runs to cut runner noise. Each command is
timed under both the OpenSSL default provider and wolfProvider; the
default provider serves **only as a per-run baseline to cancel
runner-speed variance**, and the `overhead` factor (wolfProvider ÷
baseline) is checked against a committed budget
(`scripts/perf_test/perf-baseline.{nonfips,fips}.json`). The init probes
are gated on absolute ms. The job fails only when a command exceeds its
budget (× tolerance) — i.e. when overhead *regresses*, never for being
above 1.0.

Gating on the ratio (not absolute ms) is what makes machine/OS variance
between runs cancel out: a slow runner inflates both numerator and
denominator, so the ratio holds. That is also why the budget is a
committed ratio rather than a head-to-head against a freshly built
`master`: rebuilding master every run would roughly double build cost and
still drift silently as master itself changes, whereas a committed ratio
moves only when someone deliberately re-baselines (below). The absolute-ms
probes are the exception — they are near-no-ops with no meaningful
denominator, so their budget carries tolerance to absorb runner noise.

To keep the nightly from going red on a single noisy measurement, a
command that fails the gate is measured up to `PERF_CONFIRM` times total
(default 3) and only reported as a regression if it fails **every**
attempt — one passing round clears it as a fluke. A command that exits
non-zero is reported as an error (not a silent pass), so a broken or
removed capability fails the job instead of looking fast.

This is deliberately a second layer on top of the minimum-of-N inside one
measurement, not a substitute for raising N. The two cancel different
noise: min-of-N kills *jitter within one measurement window* (scheduler
hiccups between iterations), but a transient runner-level event — CPU
steal from a noisy neighbour, thermal throttling, a slow disk moment —
can inflate **every** iteration in that window at once, and no value of N
escapes a window that is uniformly slow. A fresh confirm round re-measures
later, after the event has likely passed. Raising N alone would make each
window longer and costlier without addressing whole-window contamination,
which is the failure mode that actually produced red nightlies in testing.

There are two job variants. **non-FIPS** tracks general init/load
overhead. **FIPS** is the one that actually guards the CAST class — the
FIPS CAST code is compiled out of non-FIPS builds, so only the FIPS row
exercises the DH-derive CAST that originally regressed.

It runs nightly on its own cron, and can be pulled into a PR on demand by
adding the `ci:perf` label (via `pr-osp-select.yml`, same as the OSP jobs).

Run it locally:

```sh
# non-FIPS
source scripts/env-setup
./scripts/perf_test/do-perf-tests.sh

# FIPS - export before sourcing so env-setup selects provider-fips.conf
export WOLFSSL_ISFIPS=1
source scripts/env-setup
./scripts/perf_test/do-perf-tests.sh
```

Timing uses GNU `date +%s.%N`, so local runs need GNU coreutils (the
script errors out early on BSD/macOS `date`). CI runs on Linux.

### Updating the baseline

The committed baselines are generous seeds. Regenerate on a stable runner
and commit the result:

```sh
./scripts/perf_test/do-perf-tests.sh --update-baseline
```

`--update-baseline` writes each command's budget as its just-measured
value plus `PERF_MARGIN` (default 30%) headroom, so re-baselining on a
faster result *tightens* the gate and re-baselining after a real
slowdown *loosens* it.

**Update when** the overhead change is understood and intended — e.g. a
deliberate init/load change you've reviewed, or a move to a different
runner class that shifts the ratio for everyone. **Do not** re-baseline to
silence an unexplained regression; that is the exact signal the job exists
to surface — investigate first, re-baseline only once you know why it
moved.

On **improvement**: the gate is one-sided on purpose — it never fails a
command for being *faster* than budget, because a green-but-better run is
never a problem to page on. But a sustained improvement is worth a
deliberate re-baseline *downward*: tightening the budget to the new, lower
overhead is what lets the job catch a later silent regression back to the
old level. So significant improvement is a prompt to re-baseline (manually,
after confirming it holds across runs), not an error and not automatic.

## Triggering manually

Every nightly-capable workflow also has `workflow_dispatch:` so you
can run it on demand:

```bash
gh workflow run nightly-osp.yml --ref <branch>
gh workflow run sanitizers.yml --ref <branch>
gh workflow run static-analysis.yml --ref <branch>
gh workflow run hostap.yml --ref <branch>   # single OSP
```

For PR-triggered workflows, push a commit (or mark a draft PR as ready
for review).

## Where to look when something fails

| Symptom | Look here |
|---------|-----------|
| PR check red on `Simple Tests` | `simple.yml` → typically a wolfSSL/OpenSSL build or unit test failure. Reproduce locally with `./scripts/build-wolfprovider.sh`. |
| Nightly Slack alert: `<app> FIPS` failed | The corresponding `<app>.yml` job log → "Test <app> with wolfProvider" step. The OSP patch in `wolfssl/osp` is the usual fix site. |
| Sanitizer report (ASan/UBSan/TSan) | `sanitizers.yml` → "Run wolfprov unit tests (make test) under sanitizers" step. The first stack frame inside wolfProvider source is the bug. |
| Static analysis report | Download the `scan-build-results` / `cppcheck-results` / `infer-results` artifact from the workflow run. |
| Container image change isn't picked up | `publish-test-deps-image.yml` only fires on push to master under `docker/wolfprovider-test-deps/**`. Manually dispatch it if you need to force a rebuild. |

## Layout reference

```
.github/
├── README.md                  this file
├── scripts/
│   ├── check-workflow-result.sh   XOR force-fail vs normal expected result
│   ├── install-packages.sh        common deb install + apt-mark hold pattern
│   ├── add-rsync-sha-test.sh      OSP-specific test injection
│   ├── pam-pkcs11-test.sh         OSP-specific runner
│   ├── test_sscep.sh              OSP-specific runner
│   ├── docker/                    Dockerfiles used by ad-hoc jobs
│   ├── qtbase/                    qt5network5 helpers
│   └── x11vnc/                    x11vnc helpers
└── workflows/                 55 workflow YAMLs (see tables above)
```
