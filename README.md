### wolfProvider — `debs`

This branch is **dedicated exclusively to CI/CD and packaging automation**.
It is **not part of the main source code** and is **not intended for development or code contributions**.

#### Purpose

The `debs` branch serves as a **storage and publishing branch** for generated Debian (`.deb`) packages produced by the wolfProvider CI pipelines.
These artifacts are automatically uploaded here for testing, validation, and distribution workflows.

#### Usage

* **Do not submit pull requests** to this branch.
* **Do not modify files manually** — all updates are performed by automated CI jobs (e.g., Jenkins, GitHub Actions).
* **Do not consume these debs** - These are for testing purposes only and should not be used in real application.

#### Notes

* This branch does **not contain any source code** or build logic.
* It is maintained automatically by the wolfSSL build infrastructure.
