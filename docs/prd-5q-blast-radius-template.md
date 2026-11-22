# PRD / User Story Addendum: 5-Question Plain-English Blast-Radius Trigger

> Copy and paste this lightweight section into any **Jira ticket, Linear issue, Notion PRD, or GitHub Issue** before sprint sizing.  
> **Scope:** Static open-source developer/PO template paired with 100% local single-workstation CLI verification (`coppermind`, `aegisbox`, `argus`, `locksmith`, `bomhound`, `soulcaster`). Zero cloud GRC SaaS dependencies.

---

## 1. 5-Question Plain-English Blast-Radius Trigger Card (30 Seconds)

Check any box that applies to this feature:

- [ ] **Q1 (`auth_data_money`):** Does this touch login, permissions, billing/money, or cross-customer data?
- [ ] **Q2 (`ai_rag_context`):** Does this send text to an AI model or retrieve documents via search/RAG?
- [ ] **Q3 (`ai_state_mutation`):** Can an AI call a tool or API that **changes state** (write, delete, refund, email, webhook)?
- [ ] **Q4 (`supply_chain_mcp`):** Does this add a new third-party library, external API, or MCP tool server?
- [ ] **Q5 (`secrets_pii`):** Does this store, log, or transmit API keys, passwords, or sensitive customer PII?

### Zero-Ceremony Fast-Track Rule
* **0 boxes checked:** **Fast-track!** Skip Section 2 and move straight to implementation — zero security ceremony.
* **1+ boxes checked:** Add **2–3 plain-English `Given / When / Then` Safety Acceptance Criteria** in Section 2 so engineering sizes the safety boundary upfront in the sprint.

---

## 2. Safety Acceptance Criteria (Auto-Suggest Locally in `< 5ms`)

Generate 2–3 crisp, jargon-free criteria locally on your workstation (ephemeral & read-only — pasted story text is never stored):

```bash
# Example: AI support assistant that searches tickets (Q2) and issues refunds (Q3)
coppermind requirements \
  --story "As a support agent, I want an AI assistant to summarize customer tickets and issue refunds up to $50" \
  --triggers ai_rag_context,ai_state_mutation

# Or read directly from a local PRD file (strict 256KB cap)
coppermind requirements --story-file ./prd.md

# Add --why for a 1-sentence business-impact explanation
coppermind requirements --story-file ./prd.md --why
```

Paste the generated criteria here:

```markdown
### Safety Acceptance Criteria
1. **<Plain-English Title>**
  - **Given** <realistic abuse or failure setup>,
  - **When** <triggering action>,
  - **Then** <observable deterministic pass condition enforced in code>.
  - *Verify:* `<local verification command>`
```

---

## 3. Local Verification Definition of Done (Traceability)

Every checked trigger maps directly to a local, repeatable pass/fail check developers run before opening a PR:

| Checked Trigger | Local Proof Command | Plain-English Outcome |
| :--- | :--- | :--- |
| **Q1 (`auth_data_money`)** | `aegisbox test --authz` / `aegisbox test --billing` | Cross-customer access blocked; prices/limits enforced server-side |
| **Q2 (`ai_rag_context`)** | `aegisbox test --ai-safety --rag` | Customer search isolated by tenant; external text fenced as data |
| **Q3 (`ai_state_mutation`)** | `aegisbox test --ai-safety --tools` | Action caps enforced in code; risky actions require human approval |
| **Q4 (`supply_chain_mcp`)** | `argus vet --diff` / `soulcaster verify-patch` | New libraries vetted for typosquats; external MCP servers pinned |
| **Q5 (`secrets_pii`)** | `locksmith run -- env` / `bomhound check` | Zero hardcoded API keys in git; customer PII scrubbed from logs |
