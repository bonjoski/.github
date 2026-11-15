# Security Policy

## Supported Versions

Only the latest release or active `main` branch of each repository receives security updates.

| Version / Branch | Supported          |
| ---------------- | ------------------ |
| `main` (Latest)  | :white_check_mark: |
| Older releases   | :x:                |

## Reporting a Vulnerability

Please do **NOT** report security vulnerabilities through public GitHub issues, pull requests, or discussions.

Instead, please use **GitHub Private Vulnerability Reporting**:
1. Navigate to the **Security** tab of the affected repository.
2. Click **Report a vulnerability** to create a private security advisory.
3. Provide details including:
   - Summary and potential impact of the vulnerability
   - Step-by-step instructions or proof-of-concept to reproduce
   - Suggested mitigation or fix (if available)

Alternatively, you may contact the maintainer directly using the contact information on the [@bonjoski GitHub Profile](https://github.com/bonjoski).

### Cryptographic Signing & Release Verification

All authoritative commits, release tags, and security advisories across the `@bonjoski` ecosystem are cryptographically signed:

- **Maintainer GPG Key ID:** `7BB5B44244E586B0`
- **Tag & Commit Verification:** `git tag -v <tag>` / `git log --show-signature`
- **Artifact Provenance:** Release binaries ship with SHA-256 checksums (`checksums.txt` + `.asc`/`.sig` detached signatures), CycloneDX/SPDX SBOMs (`bomhound`), and SLSA v1.0 / in-toto provenance attestations (`soulcaster` / GitHub Artifact Attestations).

### Expected Response Times
- **Initial Acknowledgment**: Within 48 hours
- **Triage & Status Updates**: Within 7 business days
- **Coordinated Disclosure**: Security advisories will be published alongside patched releases.
