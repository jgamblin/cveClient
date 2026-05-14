# Security Audit Report: CERTCC/cveClient v1.0.22

**Date:** 2026-03-28
**Auditor:** Jerry Gamblin
**Target:** https://github.com/CERTCC/cveClient (commit 527a895)
**Scope:** Full client-side security review of cveClient v1.0.22

---

## Executive Summary

This audit identified **4 verified security vulnerabilities** and **1 dependency vulnerability requiring further verification** in the cveClient browser-based CVE management tool. All findings were verified through data flow tracing from attacker-controlled sources to exploitable sinks, with reproducible proof-of-concept scenarios.

The most significant findings relate to credential storage: API keys are stored in plaintext due to an async race condition, and the RSA encryption scheme stores the private key as extractable JWK in IndexedDB — rendering the encryption ineffective against same-origin attacks.

---

## Verified Findings

### Finding 1: Stored XSS via Unsanitized Username in DOM Insertion

**Severity:** HIGH
**CVSS 4.0 Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:A/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N`
**CVSS 4.0 Score:** 7.1
**CWE:** CWE-79 (Cross-site Scripting)

**Affected Code:**
- `cveInterface.js:387` — `top_alert()` uses `.html(msg)` without sanitization
- `cveInterface.js:965` — `user_update_modal()` uses `.html("Update User ("+mr.username+")")`
- `cveInterface.js:837` — `deepdive()` uses `.html("("+tinfo+")")` where tinfo can be a username
- `cveInterface.js:859` — `.html("("+row.cve_id+")")` (lower risk — CVE ID format constrained)
- `cveInterface.js:15-16` — `add_option()` uses `.html(f)` on option elements

**Data Flow:**
```
CVE-Services API response (user object)
  -> Bootstrap Table stores username
  -> user_update_modal() sets data-oldvalue from mr.username (line 966)
  -> update_user_status() reads username from data-oldvalue (line 1389)
  -> top_alert() receives username in msg parameter (line 1404)
  -> .html(msg) renders unsanitized HTML in #topalert (line 387)
```

**Proof of Concept:**
1. An attacker with ADMIN or SECRETARIAT role creates a user via the API with username: `<img src=x onerror=alert(document.cookie)>@test.com`
2. When any admin views the user list and toggles the user's active status, `top_alert()` renders the malicious username as HTML
3. The onerror handler executes arbitrary JavaScript in the victim admin's browser context

**Additional XSS Sinks:**
- `add_option()` line 16: `.html(f)` — exploitable via `add_new()` (line 1999, self-XSS with arbitrary user input) and `urlprompt()` (line 413, `URL.host` can contain HTML)
- These are self-XSS (attacker is the victim) and lower severity

**Remediation:**
- Replace `.html()` with `.text()` for all DOM insertions containing usernames, CVE IDs, or other API data
- Apply `safeHTML()` to the `msg` parameter in `top_alert()`
- Change `add_option()` from `.html(f)` to `.text(f)`

---

### Finding 2: Plaintext API Key Storage Due to Async Race Condition

**Severity:** HIGH
**CVSS 4.0 Vector:** `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
**CVSS 4.0 Score:** 6.1
**CWE:** CWE-312 (Cleartext Storage of Sensitive Information), CWE-362 (Race Condition)

**Affected Code:**
- `cveInterface.js:618-632` — Login handler stores credentials before encryption completes
- `cveInterface.js:1864-1889` — `enable_encryption()` uses async `$.getScript()`

**Data Flow:**
```
Login success (line 615)
  -> enable_encryption() called (line 619) — ASYNC, returns immediately
  -> store.setItem("cveClient/key", plaintext_key) (line 631) — SYNC, executes NOW
  -> ... 2-3 seconds later ...
  -> $.getScript callback fires, encrypts key, overwrites storage (line 1879)
```

**Proof of Concept:**
1. Open DevTools -> Application -> Local Storage
2. Login with "Keep me logged in" checked
3. IMMEDIATELY observe `cveClient/key` contains the plaintext API key
4. After ~2-3 seconds, it's overwritten with an encrypted data URI

**Encryption Failure Scenario:**
If `encrypt-storage.js` fails to load (network error, CSP blocking), there is no `.fail()` handler — the plaintext key persists in localStorage **permanently**. The auto-login flow at lines 711-754 will use it without complaint.

**Remediation:**
- Never store the API key before encryption completes
- Skip the key field in the general storage loop; let `enable_encryption()` handle key storage after encryption succeeds
- Add error handling: if encryption fails, do not persist the key and warn the user

---

### Finding 3: RSA Private Key Stored as Extractable JWK in IndexedDB

**Severity:** HIGH
**CVSS 4.0 Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`
**CVSS 4.0 Score:** 7.1
**CWE:** CWE-522 (Insufficiently Protected Credentials), CWE-320 (Key Management Errors)

**Affected Code:**
- `encrypt-storage.js:118-126` — `check_create_key()` generates RSA keys with `extractable: true`
- `encrypt-storage.js:98-104` — `save_key()` exports private key as JWK and stores in IndexedDB

**Data Flow:**
```
check_create_key() generates RSA-OAEP 4096-bit key (extractable: true)
  -> save_key() exports private key as JWK via crypto.subtle.exportKey("jwk", key.privateKey)
  -> dbManager() stores {epr: privateKeyJWK, epb: publicKeyJWK} in IndexedDB
  -> Any same-origin JavaScript can read IndexedDB and extract the private key
```

**Proof of Concept (browser console or XSS):**
```javascript
indexedDB.open("cve-services.apikeyStore",1).onsuccess = function(e) {
  var tx = e.target.result.transaction("keyStore");
  tx.objectStore("keyStore").getAll().onsuccess = function(r) {
    var privateKeyJWK = r.target.result[0].key.epr;
    // Import the private key
    crypto.subtle.importKey("jwk", privateKeyJWK,
      {name:"RSA-OAEP", hash:"SHA-256"}, true, ["decrypt"])
    .then(function(privKey) {
      // Decrypt the API key from localStorage
      var encKey = localStorage.getItem("cveClient/key");
      var buf = atob(encKey.split(",")[1]);
      var ab = new ArrayBuffer(buf.length);
      var ia = new Uint8Array(ab);
      for(var i=0; i<buf.length; i++) ia[i] = buf.charCodeAt(i);
      return crypto.subtle.decrypt({name:"RSA-OAEP"}, privKey, ab);
    }).then(function(dec) {
      console.log("API KEY:", new TextDecoder().decode(dec));
    });
  };
};
```

**Impact:** The encryption feature provides **zero security benefit** against same-origin attacks (XSS, malicious extensions) because both the encrypted data (localStorage) and the decryption key (IndexedDB) are accessible from the same trust boundary. The `import_key()` function re-imports with `extractable: false`, but the JWK is already persisted in IndexedDB.

**Remediation:**
- Generate keys with `extractable: false`
- Store CryptoKey objects directly in IndexedDB (structured-clonable) instead of exporting as JWK
- Add backward-compatible `import_key()` that handles both legacy JWK and new CryptoKey format

---

### Finding 4: API Key Logged to Browser Console

**Severity:** MEDIUM
**CVSS 4.0 Vector:** `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
**CVSS 4.0 Score:** 6.1
**CWE:** CWE-532 (Insertion of Sensitive Information into Log File)

**Affected Code:**
- `cveInterface.js:746` — `console.log(client.key)` during auto-login
- `cveInterface.js:749` — `console.log(client.key)` after encryption activation
- `cveInterface.js:1346` — `console.log(updates)` during user updates (PII/role data)
- `schemaToForm.js:523` — `console.log(x)` during form data conversion

**Proof of Concept:**
1. Login with "Keep me logged in" checked
2. Close and reopen the application
3. Open DevTools Console
4. The encrypted API key (data URI) is visible at lines 746 and 749

**Impact:** Requires local access (DevTools, malicious extension, screen sharing). The logged key is the encrypted form, but combined with Finding 3, an attacker can decrypt it.

**Remediation:** Remove all `console.log` calls that output `client.key` or user data objects.

---

## Dependency Vulnerability (Requires Further Verification)

### SweetAlert2 11.4.9 — CVE-2023-40042

**Severity:** Potentially HIGH
**Status:** Needs verification of applicability

**Details:** The local copy of SweetAlert2 is version 11.4.9 (released Feb 2022). CVE-2023-40042 affects versions < 11.7.27 and involves XSS via title/html parameters.

**Applicability Concern:** cveClient passes API response data to `Swal.fire()` in multiple places (e.g., line 639: `Swal.fire({ title: title, text: messages })`). If the `text` parameter is affected by the CVE, this could be exploitable via malicious API responses.

**Recommendation:** Update to SweetAlert2 11.10.x regardless — the version is 4+ years old.

**Additional Outdated Dependencies:**
- Ace Editor 1.2.4 (current: 1.32.x) — low risk, hardcoded modes
- Bootstrap 4.3.1 (CVE-2019-8331) — NOT applicable, tooltips/popovers unused
- jQuery 3.5.1 — no CVEs for 3.5.1+, usage is safe

---

## Observations (Not Reportable as Findings)

### Observation 1: autoCompleter innerHTML Pattern
`autoCompleter.js:97` uses `innerHTML` but `cleanHTML()` properly escapes all content. Not exploitable.

### Observation 2: Hardcoded Placeholder in HTML
`index.html:98` contains `SYHpbZuvOGS80P5oNX` in a hidden div. This is a UI placeholder replaced by `set_copy_pass()` — never used for authentication. Recommend removing the placeholder value.

### Observation 3: Dynamic Function Execution via data-update
`cveInterface.js:1814-1820` uses `window[$(w).attr("data-update")]` for function lookup. All 5 `data-update` values are hardcoded in static HTML. Not independently exploitable but amplifies XSS impact. Recommend replacing with explicit function map.

### Observation 4: Custom API URL Accepts Any Destination
`cveInterface.js:395-417` allows custom API URLs with minimal validation. Credentials are sent as headers to whatever URL is configured. Requires social engineering or localStorage poisoning (via XSS) to exploit. Recommend adding known-host validation.

### Observation 5: Incomplete Logout Across Storage Types
`cveInterface.js:655-664` only clears the current storage type on logout. If credentials exist in both localStorage and sessionStorage, some may persist.

---

## Risk Summary

| Finding | Severity | CVSS 4.0 | GHSA? |
|---------|----------|----------|-------|
| XSS via unsanitized username | HIGH | 7.1 | Yes |
| Plaintext API key storage | HIGH | 6.1 | Yes |
| Extractable RSA key in IndexedDB | HIGH | 7.1 | Yes |
| API key logged to console | MEDIUM | 6.1 | Consider |
| SweetAlert2 CVE-2023-40042 | TBD | TBD | If confirmed |

---

## Disclosure Timeline

- **2026-03-28:** Audit completed
- **Target:** File GHSAs on CERTCC/cveClient for Findings 1-3
- **Target:** Email cert@cert.org referencing advisories
- **Target:** 90-day disclosure window for maintainer response
