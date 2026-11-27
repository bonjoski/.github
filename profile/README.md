# `@bonjoski` — Power Steering for Deterministic & AI-Assisted Dev

> **Make the secure path faster than the shortcut.**  
> 100% local, zero-SaaS developer tools that stop `.env` leaks, AI package hallucinations, and rogue shell commands—with calm ≤3-line Fix-Forward guidance and zero mandatory YAML.

---

## ⚡ 60-Second Quickstart (Zero YAML Required)

```bash
# 1. Install the full local workstation toolchain in one command
brew install bonjoski/tap/paved-road

# 2. Auto-detect your stack & wire IDE MCP servers (dry-run first, then --apply)
fabrial init --mcp
fabrial init --mcp --apply

# 3. Move plaintext .env keys into Touch ID / TPM memory & shred .env
locksmith migrate .env

# 4. Start an amortized local session (1 Touch ID prompt, 0ms runtime wrapper hop tax)
eval "$(fabrial session begin)"

# 5. Run the worktree-local PR dry-run & verify signed BLPR-v1 local receipts
fabrial check --diff --why && fabrial receipt verify
```

Every tool follows **UB-CLI-v2**, **UB-MCP-v1**, and **BLPR-v1**:
* **≤3 calm lines by default:** What paused, a validated copy-pasteable `Fix:` command, and a 1-line `Why:`.
* **Progressive disclosure (`--why`):** Unlock the threat model, CWE/OWASP mapping, and kernel/crypto details whenever you want them.
* **Agent-native (`--json` & `UB-MCP-v1`):** Structured `FixForwardError` `structuredContent` + deterministic exit codes (`10`/`20`/`30`/`40`/`82`) and **zero-raw-secret opaque leases** (`locksmith_checkout_lease` → `airlock_exec`/`aegisbox_exec`) so Claude Code, Cursor, and Antigravity self-heal in one turn without ever seeing raw credentials.
* **Local cryptographic handoffs (`BLPR-v1`):** Standard DSSE / in-toto Statement v1 receipts signed locally via `locksmith` (`fabrial receipt verify`)—zero cloud control plane.

---

## 🗺️ The 4-Stage Developer Lifecycle Map

| Stage | Pain Point Solved | Core Local Tools | Example Command |
| :--- | :--- | :--- | :--- |
| **1. 60-Second On-Ramp** | Eliminates config cliffs across Go, Node, Python, Rust, and AI SDK repos (`openai`, `@anthropic-ai/sdk`, `@google/genai`, `@modelcontextprotocol/sdk`). | [**Fabrial**](https://github.com/bonjoski/fabrial) · [**Locksmith**](https://github.com/bonjoski/locksmith) | `fabrial init`<br/>`locksmith migrate .env` |
| **2. Daily Power-Steering Guardrails** | Stops LLM package hallucinations & slopsquats with calm Levenshtein `Did you mean?` suggestions and audits lockfiles/diffs pre-flight. | [**Argus**](https://github.com/bonjoski/argus) | `argus explain reqeusts --ecosystem pypi`<br/>`argus vet --diff` |
| **3. Multi-Agent Sandboxing & Secrets** | Keeps AI coding agents out of `~/.ssh`, `~/.aws`, and `.env` across $N=8$ parallel worktrees with <15ms kernel sandboxes, microVMs, and local AI memory. | [**Airlock**](https://github.com/bonjoski/airlock) · [**Aegisbox**](https://github.com/bonjoski/aegisbox) · [**Conjoiner**](https://github.com/bonjoski/conjoiner) · [**Coppermind**](https://github.com/bonjoski/coppermind) | `fabrial run -- npm test`<br/>`fabrial session begin --ttl 30m` |
| **4. Portable Local Cryptographic Receipts** | Generates standard SLSA v1.0 / in-toto provenance, CycloneDX SBOMs, and signed commits locally—verified in CI via open-source GitHub Actions with zero SaaS backend. | [**Soulcaster**](https://github.com/bonjoski/soulcaster) · [**Bomhound**](https://github.com/bonjoski/bomhound) · [**Reusable Workflow**](https://github.com/bonjoski/.github/blob/main/.github/workflows/verify-local-receipts.yml) | `uses: bonjoski/.github/.github/workflows/verify-local-receipts.yml@main` |

---

## 🛠️ Full Local Toolchain Directory

* **[Fabrial](https://github.com/bonjoski/fabrial):** Zero-config stack/AI-SDK detector (`fabrial init`) and local two-tier execution router.
* **[Locksmith](https://github.com/bonjoski/locksmith):** Hardware-backed biometric vault (`locksmith migrate .env`, Touch ID / TPM2, memory slicing, local MCP).
* **[Argus](https://github.com/bonjoski/argus):** Pre-flight dependency spellchecker, slopsquatting detector, and lockfile/diff auditor.
* **[Airlock](https://github.com/bonjoski/airlock):** Sub-15ms Tier 1 kernel sandbox (Apple Seatbelt / Linux Landlock).
* **[Aegisbox](https://github.com/bonjoski/aegisbox):** Tier 2 local microVM isolation sandbox (Apple Virtualization / Linux KVM / libkrun).
* **[Conjoiner](https://github.com/bonjoski/conjoiner):** Deterministic RFC 9449 DPoP capability gateway library for local agent CLI tools.
* **[Bomhound](https://github.com/bonjoski/bomhound):** CycloneDX SBOM legal attribution and copyright notice generator (Apache 2.0 §4c).
* **[Soulcaster](https://github.com/bonjoski/soulcaster):** Local hermetic compiler attestation emitting open-standard in-toto and SLSA v1.0 receipts.
* **[Coppermind](https://github.com/bonjoski/coppermind):** Local-first AI memory system that gives coding agents persistent, searchable memory across sessions.

---

## ⚖️ Safe Harbor & Local DevEx Scope

All `@bonjoski` repositories are strictly **100% local, single-developer workstation open-source tools**:
* **Zero Cloud Control Plane:** Every binary runs locally on `localhost` using public OS primitives (Apple Seatbelt, Linux Landlock, macOS Hypervisor, Touch ID / TPM2).
* **Zero Enterprise SaaS / Fleet Telemetry:** Stage 4 CI verification uses standard open-source formats (SLSA v1.0, in-toto, CycloneDX) and open-source GitHub Actions—never a centralized compliance server or paid tier.
* **Permissive Open Source:** Distributed under MIT / Apache-2.0 licenses solely for developer productivity and local security ergonomics.
