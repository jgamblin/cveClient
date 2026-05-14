# cveClient Security Audit & Compatibility Upgrade — Design Spec

**Date:** 2026-03-28
**Author:** Jerry Gamblin
**Target Repo:** CERTCC/cveClient (upstream)
**Working Fork:** jgamblin/cveClient

---

## Context

cveClient is a browser-based CVE management client and JavaScript library for CVE-Services 2.x, maintained by CERT/CC (Carnegie Mellon SEI). It handles sensitive API credentials in the browser and is used by CNAs to manage real CVE records.

An initial code review identified multiple potential security vulnerabilities and schema/ADP compatibility gaps. This spec defines the approach for verifying findings, responsibly disclosing them, and delivering fix PRs.

**Relationship to upstream:** Independent contributor. No prior coordination with maintainer (`sei-vsarvepalli`). Upstream has an open PR #35 (version 1.0.23). Our work must be self-contained to minimize merge conflicts.

---

## Phase 1: Verified Security Audit

### Methodology

Each potential finding is verified through data flow tracing:

1. **Source** — where does untrusted data originate? (user input, API response, URL parameter, localStorage)
2. **Transforms** — is it sanitized? (`safeHTML()`, `encodeURIComponent()`, `.text()`, etc.)
3. **Sink** — where does it land? (`.html()`, `innerHTML`, storage API, fetch URL)
4. **Proof** — can an attacker control the source and reach the sink without adequate sanitization?

### Classification

- **Verified finding:** Traceable data flow from attacker-controlled source to exploitable sink, with reproducible PoC or concrete exploit scenario. Gets a CVSS 4.0 vector string and score.
- **Observation:** Potential concern that cannot be proven exploitable. Documented but excluded from GHSA filings.

### Scoring

All findings scored using CVSS v4.0 specification:
- Attack Vector, Attack Complexity, Attack Requirements, Privileges Required, User Interaction
- Vulnerable System Impact (Confidentiality, Integrity, Availability)
- Conservative scoring — ambiguous exploitability scores lower

### Candidate Findings to Verify

| # | Category | Location | Claim | Verification Needed |
|---|----------|----------|-------|---------------------|
| 1 | XSS | cveInterface.js — `.html()` calls (lines ~829-842, 859, 387) | API response data inserted into DOM without sanitization | Trace CVE API response fields through to `.html()` sinks; confirm no safeHTML() in path |
| 2 | XSS | autoCompleter.js — `innerHTML` (line ~97) | Suggestion HTML from external source set via innerHTML | Trace suggestion data source; determine if attacker can control suggestions |
| 3 | XSS | schemaToForm.js — multiple `innerHTML` assignments | Schema-derived content set as innerHTML | Trace whether schema content is attacker-controllable (likely not — observation candidate) |
| 4 | Credential Exposure | cveInterface.js — localStorage (lines ~626-632, 711-739) | API keys stored in plaintext in localStorage | Confirm storage mechanism; verify encryption is optional not default |
| 5 | Credential Exposure | cveInterface.js — console.log (lines ~745-746, 749, 1276, 1346) | API keys and sensitive data logged to console | Read exact log statements; confirm key material is logged |
| 6 | Crypto Weakness | encrypt-storage.js — extractable keys (line ~118) | RSA private key generated with extractable:true, exported as JWK | Confirm extractable flag; trace key export and storage path |
| 7 | Hardcoded Credential | index.html (line ~98) | Default password visible in HTML source | Confirm the element exists and its purpose |
| 8 | Dynamic Code Exec | cveInterface.js (lines ~1814-1820) | window[] function lookup from data attributes | Trace whether data attributes can be attacker-controlled |
| 9 | Open Redirect / Credential Theft | cveInterface.js (lines ~395-417) | Custom API URL accepts any URL; API keys sent to it | Confirm URL validation is insufficient; API keys sent in headers to arbitrary URLs |
| 10 | Dependency Vulns | index.html — CDN references | jQuery 3.5.1, Bootstrap 4.3.1, Popper 1.14.7 outdated | Check actual CVEs against these versions; confirm applicability to this codebase's usage |

### Deliverable

Local-only security audit document with:
- Verified findings table (ID, title, severity, CVSS 4.0 vector/score, affected file:line, description, PoC, remediation)
- Observations table (items we investigated but could not prove exploitable)
- Dependency vulnerability assessment

---

## Phase 2: Responsible Disclosure

### Process

1. File GitHub Private Security Advisories on `CERTCC/cveClient` for each verified critical/high finding
2. Draft email to `cert@cert.org` referencing the advisories
3. Jerry handles all filing manually; we prepare the content

### GHSA Content (per finding)

- Title, description, severity, CVSS 4.0 vector
- Affected versions (all up to and including 1.0.22)
- Proof-of-concept or exploit scenario
- Recommended remediation
- CWE classification

### Timeline

- Allow 90 days for maintainer response before public disclosure (standard responsible disclosure)
- Coordinate with maintainer on patch timeline if they engage

---

## Phase 3: Security Fix PRs

All PRs opened from `jgamblin/cveClient` against `CERTCC/cveClient:main`. Developed on feature branches on the fork.

### PR 1: XSS Remediation
**Branch:** `security/xss-remediation`
- Extend `safeHTML()` usage to all verified unsafe `.html()` sinks
- Replace `innerHTML` with `textContent` where HTML rendering is not needed
- In autoCompleter.js and schemaToForm.js, use DOM APIs instead of HTML string concatenation
- Scope: Only touch verified XSS sinks, not speculative ones

### PR 2: Credential & Crypto Hardening
**Branch:** `security/credential-hardening`
- Make encrypted storage the default path (not optional)
- Set `extractable: false` on RSA key generation; restructure key workflow to avoid JWK export of private keys
- Remove all `console.log` calls that output keys/credentials
- Remove hardcoded password from index.html

### PR 3: Dependency Updates
**Branch:** `security/dependency-updates`
- Update jQuery, Bootstrap, Popper.js, Bootstrap-Table to latest secure versions
- Update SRI hashes to match
- Verify no breaking changes against actual usage patterns in the codebase

### PR 4: Input Validation & Hardening
**Branch:** `security/input-validation`
- Add URL allowlist for API endpoints or explicit risk acknowledgment for custom URLs
- Sanitize query parameter parsing in `queryParser()`
- Remove dynamic `window[]` function lookup pattern; use explicit function map

---

## Phase 4: Schema & ADP Compatibility PRs

Opened publicly (no security sensitivity).

### PR 5: Schema Compatibility
**Branch:** `feature/schema-compatibility`
- Update/parameterize schema URL for CVE JSON 5.1 support
- Add schema version detection so form generation adapts to schema changes
- Test against current bundled schema endpoint

### PR 6: ADP Enhancements
**Branch:** `feature/adp-enhancements`
- Add missing ADP endpoint wrappers in cveClientlib.js (read, delete, list)
- Improve ADP UI beyond JSON-editor-only mode
- Add ADP schema validation before publish

---

## Phase 5: Disclosure Follow-up

- After maintainer has had reasonable time to review/merge security PRs, coordinate public disclosure timeline
- Update GHSAs with resolution status
- Standard 90-day disclosure window

---

## Execution Order

1. Phase 1 first (audit) — must complete before any PRs or disclosures
2. Phase 2 after Phase 1 (disclosure filings)
3. Phase 3 can begin after Phase 2 filings are submitted (security PRs)
4. Phase 4 can run in parallel with Phase 3 (no security overlap)
5. Phase 5 follows maintainer engagement timeline

---

## Constraints

- No automated tests exist; manual verification of fixes required
- No CI/CD; PRs cannot be validated automatically
- Must not conflict with upstream PR #35 (version 1.0.23) where possible
- CVSS 4.0 scoring only (not 3.1)
- Every finding must be provably exploitable to be reported — no speculative filings to CERT/CC
