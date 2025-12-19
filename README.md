### wolfProvider — `wics`

This branch is **dedicated exclusively to CI/CD and packaging automation**. It is **not part of the main source code** and is **not intended for development or code contributions**.

#### Purpose

The `wics` branch serves as a **storage and publishing branch** for generated `.wic.xz` Disk Images produced by the wolfProvider CI pipelines. These files get converted to `.xz` files so that we can successfully compress and export them to Github. These artifacts are then automatically uploaded here for decompression, testing, validation, and testing in workflows.

#### Usage

- **Do not submit pull requests** to this branch.
- **Do not modify files manually** — all updates are performed by automated CI jobs (e.g., Jenkins, GitHub Actions).
- **Do not consume these artifacts in production** — These are for testing purposes only and should not be used in real applications.

#### Notes

- This branch does **not contain any source code** or build logic.
- It is maintained automatically by the wolfSSL build infrastructure.

#### CI Usage

CI builds
```
.github/workflows/yocto-curl.yml
.github/workflows/yocto-librelp.yml
.github/workflows/yocto-test.yml
.github/workflows/yocto-verify.yml
.github/workflows/yocto-xmlsec1.yml
```

Nightly Builds - (2-3hrs)
```
.github/workflows/yocto-openssh.yml
.github/workflows/yocto-openssl.yml
.github/workflows/yocto-rsyslog.yml
```
