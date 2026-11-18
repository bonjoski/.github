# `bonjoski` — Sovereign AI Agent Security Toolchain

> **Core Focus:** Local Workstation AI Agent Security, Kernel & MicroVM Sandboxing, Biometric Secrets Management, Supply Chain Provenance

---

## ⚖️ Safe Harbor & Compliance Scope

All projects in this portfolio operate strictly within personal developer tooling boundaries:
- **100% Local Execution:** Utilities run exclusively on individual developer workstations (`localhost`), with zero multi-tenant cloud control planes, zero centralized fleet telemetry, and zero enterprise SaaS tiers.
- **Thin Wrappers on Public OS Primitives:** Runtimes leverage documented, public OS facilities (Apple Seatbelt, Linux Landlock LSM, macOS Hypervisor, Local Touch ID / TPM2).
- **Non-Commercial Open Source:** Distributed under permissive open-source licenses (MIT / Apache-2.0) solely for developer productivity and local test ergonomics.

---

## 🛠️ Toolchain Overview

- **[Fabrial](https://github.com/bonjoski/fabrial):** Dynamic multi-tier security fabric coordinating local sandboxes and biometric credentials.
- **[Airlock](https://github.com/bonjoski/airlock):** Sub-15ms zero-trust workstation sandbox for package managers and agents (Seatbelt / Landlock).
- **[Aegisbox](https://github.com/bonjoski/aegisbox):** MicroVM hardware isolation sandbox for ephemeral test builds (libkrun / macOS Hypervisor).
- **[Argus](https://github.com/bonjoski/argus):** Zero-SaaS pre-flight dependency validator and package typosquatting scanner.
- **[Locksmith](https://github.com/bonjoski/locksmith):** Biometric secrets vault and MCP server backed by Touch ID / TPM2.
- **[Shield](https://github.com/bonjoski/shield):** Local client-side secret redactor and `127.0.0.1:8080` loopback proxy.
- **[Conjoiner](https://github.com/bonjoski/conjoiner):** Deterministic tool gateway and RFC 9449 DPoP reference library for local agent CLI tools.
- **[Stormcage](https://github.com/bonjoski/stormcage):** In-process prompt and context sanitization Go library for agent test harnesses.
- **[Bomhound](https://github.com/bonjoski/bomhound):** CycloneDX legal attribution and copyright notice generator (Apache 2.0 §4c).
- **[Soulcaster](https://github.com/bonjoski/soulcaster):** Runtime hermetic compiler attestation generating in-toto and SLSA v1.0 provenance.
- **[Coppermind](https://github.com/bonjoski/coppermind):** Portable cognitive agent brain & local SQLite memory runtime.
