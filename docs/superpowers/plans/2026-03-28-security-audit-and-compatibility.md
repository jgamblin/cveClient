# cveClient Security Audit & Compatibility Upgrade — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Perform a verified security audit of CERTCC/cveClient, prepare responsible disclosure materials, deliver grouped fix PRs, and upgrade schema/ADP compatibility.

**Architecture:** Phase 1 produces a local-only audit document with CVSS 4.0 scores. Phase 2 drafts GHSA/email content for Jerry to file. Phases 3-4 create 6 PRs on feature branches against upstream. No build system or tests exist — verification is manual via browser DevTools.

**Tech Stack:** Vanilla JavaScript, jQuery 3.5.1, Bootstrap 4.3.1, Web Crypto API, IndexedDB, CVE-Services 2.x REST API

---

## Phase 1: Verified Security Audit

### Task 1: Verify XSS in top_alert() function

**Files:**
- Read: `cveInterface.js:385-393`

**Context:** `top_alert(lvl, msg, tmr)` at line 385-393 calls `.html(msg)` on `#topalert`. We need to trace all callers to determine if `msg` ever contains attacker-controlled data.

- [ ] **Step 1: Trace all callers of top_alert**

Search cveInterface.js for every call to `top_alert`. For each call, document:
- The `msg` argument value
- Whether it contains user input, API response data, or only hardcoded strings

Run: `grep -n "top_alert" cveInterface.js`

- [ ] **Step 2: Trace API response data into top_alert**

Check if any caller passes API response fields (like `d.error`, `d.message`, `y.message`) into `top_alert`. These fields are server-controlled and could contain malicious HTML if the API is compromised or a MITM attack occurs.

Specifically check:
- Line 1404: `top_alert("success", "User ("+username+") Active status has been updated to <b>[" + String(f.active)+"]</b>",4000)` — `username` comes from form data (line 1389), `f.active` comes from API response
- Line 1836: `top_alert("warning","Encryption is now disabled...")` — hardcoded string, safe
- Line 1862: `top_alert("success","Encryption is now enabled...")` — hardcoded string, safe
- Line 1886: `top_alert("warning","Encrypting API key failed...")` — hardcoded string, safe

- [ ] **Step 3: Document finding**

**Finding or Observation:** Document whether `top_alert` is exploitable. The key question is whether `username` at line 1404 can be attacker-controlled — it comes from `$('#addUserModal .username').attr('data-oldvalue')` which was set from API response data in `user_update_modal()` at line 966. If an attacker can set a username containing HTML via the API, this is XSS.

Write finding to `docs/security-audit-findings.md` (local only, do not commit).

Format:
```markdown
## Finding X: [Title]
- **Severity:** [Critical/High/Medium/Low]
- **CVSS 4.0 Vector:** CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N
- **CVSS 4.0 Score:** X.X
- **CWE:** CWE-79 (Cross-site Scripting)
- **File:** cveInterface.js:387
- **Data Flow:** API response -> user_update_modal() -> data-oldvalue attr -> update_user_status() -> top_alert() -> .html()
- **PoC:** If a user's username contains `<img src=x onerror=alert(1)>`, the top_alert renders it as HTML
- **Remediation:** Use safeHTML() on all dynamic content passed to top_alert, or switch to .text()
```

---

### Task 2: Verify XSS in deepdive() and display_object()

**Files:**
- Read: `cveInterface.js:833-930`

**Context:** `deepdive()` at line 837 sets `$('#detailtag').html("("+tinfo+")")` where `tinfo` comes from `el.closest('tr').attr('data-uniqueid')`. Line 859 sets `.html("("+row.cve_id+")")`. `display_object()` at line 908-925 builds HTML from API response objects via `objwalk()`.

- [ ] **Step 1: Trace data sources in deepdive()**

- Line 835: `tinfo = el.closest('tr').attr('data-uniqueid')` — this is set by bootstrap-table from the `uniqueId` config. For CVE table, uniqueId is `cve_id` (line 1192). For user table, uniqueId is `username` (line 1146).
- Line 837: `$('#detailtag').html("("+tinfo+")")` — if `tinfo` is a CVE ID, it's format-validated (`/^CVE-\d{4}-\d{4,7}$/`). But if it's a username, it's an email address from the API — potentially attacker-controllable.
- Line 859: `$('#cveUpdateModal .mtitle').html("("+row.cve_id+")")` — `row.cve_id` from API response, but CVE IDs are constrained format.

- [ ] **Step 2: Trace objwalk() and display_object()**

- Line 829-830: `objwalk` uses `safeHTML(dp)` and `safeHTML(r[d])` — these ARE sanitized via the `safeHTML()` helper.
- Line 916: `safeHTML(JSON.stringify(obj,null,3))` — also sanitized.
- Line 923: `$('#f'+String(i)).html(html+'</tbody></table>')` — `html` is built from `objwalk` which uses `safeHTML`. This appears safe.

- [ ] **Step 3: Document finding**

Key question: Is the username XSS in `deepdive()` line 837 exploitable? A username is an email validated by the server, but:
1. The CVE-Services API may accept non-email usernames
2. Even email format allows `"tag<script>"@domain.com` in quoted local parts

Document as finding if username can contain HTML, or observation if server strictly validates.

---

### Task 3: Verify XSS in autoCompleter.js innerHTML

**Files:**
- Read: `autoCompleter.js:37-41, 77-107`

**Context:** Line 97 sets `suggestionItem.innerHTML = suggestionHTML` where `suggestionHTML` is built from `cleanHTML(suggestion)` with bold tags inserted. Line 37-41 defines `cleanHTML()` which uses `textContent`/`innerHTML` escaping (same pattern as `safeHTML()`).

- [ ] **Step 1: Analyze the data flow**

1. `suggestionsArray` comes from either a constructor argument or `fetch_data()` (line 19-31)
2. `fetch_data()` fetches JSON from `suggestionUrl` and returns `data[selector]` or `data`
3. Each `suggestion` from the array goes through `cleanHTML()` (line 93)
4. `cleanHTML()` at line 37-41 properly escapes HTML via `textContent` then `innerHTML` pattern
5. BUT line 94-96 wraps regex matches in `<strong>` tags: `suggestionHTML.replaceAll(m,"<strong>" + m + "</strong>")`

- [ ] **Step 2: Analyze the bold-wrapping vulnerability**

The pattern at line 92-96:
```javascript
const r = new RegExp(cleanHTML(val),"dgi");
let suggestionHTML = cleanHTML(suggestion);
new Set(suggestionHTML.match(r)).forEach(function(m) {
    suggestionHTML = suggestionHTML.replaceAll(m,"<strong>" + m + "</strong>");
});
```

`val` is the user's typed input (already HTML-escaped via `cleanHTML`). `suggestion` is also escaped. The `<strong>` wrapping only inserts `<strong>` around already-escaped text. The match `m` is from the escaped string, so it cannot contain unescaped HTML.

However, `suggestionUrl` could point to an attacker-controlled endpoint if the autoCompleter is initialized with user-supplied URLs. Check where autoCompleter is instantiated.

- [ ] **Step 3: Check autoCompleter instantiation**

In cveInterface.js, search for `new autoCompleter` or `autoCompleter(`. The CWE autocompleter is initialized with a relative URL to `cwe-common.json` (line 57-58). Check if any autoCompleter instance uses user-controlled URLs.

- [ ] **Step 4: Document finding or observation**

If all autoCompleter URLs are hardcoded/relative, this is an **observation** (defense-in-depth concern but not exploitable). If any URL is user-controlled, it's a finding.

---

### Task 4: Verify plaintext API key storage

**Files:**
- Read: `cveInterface.js:615-632, 711-754, 1822-1889`
- Read: `encrypt-storage.js:1-131`

**Context:** After successful login (line 615), credentials are stored in localStorage/sessionStorage at line 630-632. Encryption is enabled at line 619 via `enable_encryption()`, but the initial store happens at line 631 BEFORE encryption takes effect.

- [ ] **Step 1: Trace the login credential storage flow**

1. Line 618-619: `enable_encryption()` is called
2. Line 625-632: Credentials stored via `store.setItem(store_tag+$(x).attr('id'),$(x).val())`
3. `enable_encryption()` (line 1864-1889) loads encrypt-storage.js via `$.getScript()` — this is ASYNCHRONOUS
4. The script load and key generation happen asynchronously, but `store.setItem` at line 631 executes synchronously BEFORE encryption completes

- [ ] **Step 2: Verify the race condition**

The flow is:
```
login success ->
  enable_encryption() starts async script load ->
  store.setItem() writes PLAINTEXT key immediately ->
  ... async encryption eventually overwrites the key at line 1879
```

This means the API key is stored in plaintext for a window of time. Additionally, if `enable_encryption()` fails (line 1884-1886), the plaintext key persists permanently.

- [ ] **Step 3: Check if encryption is mandatory or optional**

- Line 618: `enable_encryption()` is called by default on login success — good
- BUT: encryption depends on `$.getScript("encrypt-storage.js")` succeeding
- If the script fails to load (network error, CSP blocking), encryption silently fails and plaintext persists
- The "Keep me logged in" checkbox (localStorage) makes this persistent across sessions

- [ ] **Step 4: Document finding**

This is a **verified finding**: API keys are stored in plaintext in localStorage/sessionStorage. Even when encryption is attempted, there is a race condition where plaintext is written first. If encryption fails, plaintext persists permanently.

```markdown
## Finding: Plaintext API Key Storage in Browser Storage
- **Severity:** High
- **CVSS 4.0 Vector:** CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N
- **CWE:** CWE-312 (Cleartext Storage of Sensitive Information)
- **File:** cveInterface.js:625-632
- **Data Flow:** Login form -> store.setItem() -> localStorage/sessionStorage (plaintext)
- **PoC:** After login, open DevTools -> Application -> Local Storage -> look for "cveClient/key" — contains plaintext API key
- **Remediation:** Never store plaintext key. Encrypt before storing. Make encryption synchronous or defer storage until encryption completes.
```

---

### Task 5: Verify extractable RSA private key weakness

**Files:**
- Read: `encrypt-storage.js:98-131`

**Context:** `check_create_key()` at line 118 generates RSA keys with `extractable: true` (line 125). `save_key()` at line 98 exports the private key as JWK and stores it in IndexedDB.

- [ ] **Step 1: Confirm extractable flag**

Line 118-126:
```javascript
return window.crypto.subtle.generateKey(
    {
        name: "RSA-OAEP",
        modulusLength: 4096,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
    },
    true,  // extractable = true
    ["encrypt", "decrypt"]
)
```

The second parameter `true` makes both keys extractable. This means any JavaScript running on the same origin can call `crypto.subtle.exportKey("jwk", key.privateKey)` and extract the private key.

- [ ] **Step 2: Trace key export and storage**

Line 98-104 `save_key()`:
```javascript
let fpb = await window.crypto.subtle.exportKey("jwk", key.publicKey);
let fpr = await window.crypto.subtle.exportKey("jwk", key.privateKey);
let exportKey = {epr: fpr, epb: fpb};
```

The private key (`fpr`) is exported as a JWK object and stored in IndexedDB at line 103. This defeats the purpose of using WebCrypto — the private key should be non-extractable so that even if an attacker can run JS on the page, they cannot export the key material.

- [ ] **Step 3: Assess impact**

However, note the nuance: `import_key()` at line 106-110 re-imports keys with `extractable: false`. So after the initial generation and save, subsequent uses import non-extractable keys. The vulnerability window is:
1. During initial key generation (keys are extractable in memory)
2. The JWK is stored in IndexedDB permanently — any same-origin script can read IndexedDB and reconstruct the private key from the JWK

- [ ] **Step 4: Document finding**

```markdown
## Finding: RSA Private Key Stored as Extractable JWK in IndexedDB
- **Severity:** Medium
- **CVSS 4.0 Vector:** CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N
- **CWE:** CWE-321 / CWE-522 (Insufficiently Protected Credentials)
- **File:** encrypt-storage.js:98-104, 118-130
- **Data Flow:** generateKey(extractable:true) -> exportKey("jwk") -> IndexedDB
- **PoC:** In DevTools console run: indexedDB.open("cve-services.apikeyStore",1).onsuccess = function(e) { e.target.result.transaction("keyStore").objectStore("keyStore").getAll().onsuccess = function(r) { console.log(r.target.result) } } — this exposes the full RSA private key as JWK
- **Remediation:** Generate keys with extractable:false. Use crypto.subtle.wrapKey/unwrapKey for storage instead of exportKey.
```

---

### Task 6: Verify console.log credential leakage

**Files:**
- Read: `cveInterface.js:744-749, 1276, 1346, 1868`

- [ ] **Step 1: Check each console.log for sensitive data**

- Line 745: `console.log("Already encrypted key")` — informational, not sensitive
- Line 746: `console.log(client.key)` — **LEAKS THE API KEY** (encrypted form, but still the credential used in storage)
- Line 749: `console.log(client.key)` — same, logs key again after `do_login()`
- Line 1276: `console.log("Old key was encrypted, Encrypting this new key")` — informational
- Line 1346: `console.log(updates)` — logs user update object which may contain role changes, username changes — **sensitive organizational data**
- Line 1868: `console.log("Already Encrypted")` — informational
- Line 523 in `schemaToForm.js`: `console.log(x)` — logs form data object during `toData()`, could contain CVE content

- [ ] **Step 2: Document finding**

```markdown
## Finding: API Key Logged to Browser Console
- **Severity:** Low
- **CVSS 4.0 Vector:** CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N
- **CWE:** CWE-532 (Insertion of Sensitive Information into Log File)
- **File:** cveInterface.js:746,749
- **PoC:** Login with "Keep me logged in", open DevTools Console — API key (encrypted form) is visible
- **Remediation:** Remove all console.log calls that output client.key or user data objects
```

---

### Task 7: Verify hardcoded password in HTML

**Files:**
- Read: `index.html:98`

- [ ] **Step 1: Examine the element and its usage**

Line 98: `<div id="cpassword" class="d-none cpassword">SYHpbZuvOGS80P5oNX</div>`

Search for how `cpassword` is used in cveInterface.js.

Run: `grep -n "cpassword" cveInterface.js index.html`

- [ ] **Step 2: Trace usage in cveInterface.js**

Line 1418-1424 `set_copy_pass()`:
```javascript
function set_copy_pass(secret){
    $("#cpassword").remove();
    var ppass = $('<input>').val(secret).attr("id","cpassword").
        addClass("passform").on("click",selectpass).
        attr("readonly","readonly");
    $('#addUserModal').append(ppass);
    selectpass("cpassword");
}
```

This function REMOVES the original `#cpassword` div and replaces it with an input containing the new API secret. The hardcoded value `SYHpbZuvOGS80P5oNX` appears to be a placeholder that gets replaced when a user's key is reset.

- [ ] **Step 3: Assess exploitability**

The hardcoded string is:
1. Never used as an actual credential — it's a placeholder in a hidden div
2. Replaced by `set_copy_pass()` when an actual secret is generated
3. Visible in page source but doesn't authenticate to anything

- [ ] **Step 4: Document as observation**

This is likely an **observation**, not a finding — the value does not appear to be a real credential. However, it is poor practice and could confuse security scanners. Document it as an observation with a recommendation to remove it.

---

### Task 8: Verify dynamic function execution via data attributes

**Files:**
- Read: `cveInterface.js:1811-1820`

**Context:** `clearoff()` at line 1814 checks `$(w).attr("data-update") in window` and calls `window[$(w).attr("data-update")]`.

- [ ] **Step 1: Identify all elements with data-update attribute**

Search index.html and cveInterface.js for `data-update`.

Run: `grep -n "data-update" index.html cveInterface.js`

- [ ] **Step 2: Determine if data-update can be attacker-controlled**

Check if any `data-update` values come from:
- User input
- API responses
- URL parameters
- Dynamic generation from untrusted data

From index.html line 102: `data-update="new_username"` — hardcoded in HTML.
Check all other occurrences — if all are hardcoded in the HTML source, the attacker would need DOM manipulation (via XSS) to exploit this, making it a secondary vulnerability that requires XSS first.

- [ ] **Step 3: Document finding or observation**

If `data-update` values are only set in static HTML, this is an **observation** (defense-in-depth: replace `window[]` lookup with explicit function map). If any are set dynamically from untrusted data, it is a finding.

---

### Task 9: Verify custom API URL credential theft

**Files:**
- Read: `cveInterface.js:395-417`
- Read: `cveClientlib.js:125-168`

**Context:** The "Custom" API URL option lets users enter any URL. The `cveClient` sends `CVE-API-KEY`, `CVE-API-ORG`, `CVE-API-USER` headers (line 152-155) to whatever URL is configured.

- [ ] **Step 1: Trace the custom URL flow**

1. `urlprompt()` at line 395-417 accepts any valid URL via `Swal.fire` with `input: 'url'`
2. URL validation at line 408-411 only checks `new URL(value)` — any syntactically valid URL passes
3. `add_option()` adds it to the dropdown at line 413
4. On login, `cveClient` is constructed with this URL at line 740
5. ALL subsequent API calls send credentials to this URL via headers (line 152-155)

- [ ] **Step 2: Assess exploitability**

This is user-initiated — the user themselves chooses to enter a custom URL. Attack scenarios:
1. **Social engineering:** Attacker convinces user to enter a malicious URL ("use our test server")
2. **Bookmark/link manipulation:** A crafted link with URL parameters could pre-fill the custom URL (check if `queryParser` affects the URL field)

Check if queryParser at line 716 can set the URL:
- Line 726: `if("skip" in qparams)` — only checks for "skip" parameter
- The URL select field is not populated from query parameters

- [ ] **Step 3: Document finding or observation**

Since the user must actively choose "Custom" and type a URL, this is more of a design concern than a vulnerability. Document as **observation** — recommend adding a warning dialog when custom URLs are used, or restricting to known CVE-Services hosts.

---

### Task 10: Verify dependency vulnerabilities

**Files:**
- Read: `index.html:9-25`

- [ ] **Step 1: Check jQuery 3.5.1 CVEs**

Search for known CVEs against jQuery 3.5.1. jQuery 3.5.0+ fixed the major `.htmlPrefilter()` XSS (CVE-2020-11022, CVE-2020-11023). Version 3.5.1 is the patch release. Check if any CVEs exist for 3.5.1 specifically.

- [ ] **Step 2: Check Bootstrap 4.3.1 CVEs**

Bootstrap 4.3.1 has known XSS in tooltip/popover data attributes (CVE-2019-8331). However, this requires an attacker to inject `data-template` attributes into the DOM, which requires existing XSS.

Check if cveClient uses Bootstrap tooltips/popovers with dynamic data.

- [ ] **Step 3: Check other dependencies**

- Popper.js 1.14.7 — check for known issues
- Bootstrap-Table 1.19.1 — check for known issues
- SweetAlert2 (local copy) — check version and known issues
- Ace Editor (local copy) — check version and known issues

- [ ] **Step 4: Document findings**

For each dependency with a known CVE, assess whether the vulnerability is actually exploitable given how cveClient uses the library. Only report as findings those that are exploitable in context.

---

### Task 11: Compile final audit document

**Files:**
- Create: `docs/security-audit-findings.md` (LOCAL ONLY — do not commit)

- [ ] **Step 1: Compile all verified findings**

Gather findings from Tasks 1-10. For each verified finding, include:
- Finding ID and title
- Severity (Critical/High/Medium/Low)
- CVSS 4.0 vector string and score
- CWE classification
- Affected file and line numbers
- Data flow description
- Proof-of-concept
- Remediation recommendation

- [ ] **Step 2: Compile observations**

List items investigated but not proven exploitable, with explanation of why they are observations rather than findings.

- [ ] **Step 3: Create dependency assessment table**

| Dependency | Version | Latest | Known CVEs | Applicable | Recommendation |
|------------|---------|--------|------------|------------|----------------|

- [ ] **Step 4: Review and finalize**

Re-read the entire document. For each finding, ask: "Could I demonstrate this to a CERT/CC analyst and have them agree it is exploitable?" If not, downgrade to observation.

---

## Phase 2: Responsible Disclosure Materials

### Task 12: Draft GHSA content for each verified finding

**Files:**
- Create: `docs/ghsa-drafts/` directory (LOCAL ONLY)

- [ ] **Step 1: Create GHSA draft for each Critical/High finding**

For each finding rated High or above, create a file `docs/ghsa-drafts/GHSA-<short-name>.md`:

```markdown
# Title: [Vulnerability Title]

## Summary
[2-3 sentence summary]

## Severity
[CVSS 4.0 vector and score]

## Affected Versions
All versions up to and including 1.0.22

## Details
[Full description with code references]

## Proof of Concept
[Step-by-step reproduction]

## Remediation
[Recommended fix]

## CWE
[CWE-XXX]

## Credit
Jerry Gamblin (jerry.gamblin@gmail.com)
```

- [ ] **Step 2: Draft email to cert@cert.org**

Create `docs/ghsa-drafts/cert-email-draft.md`:

```markdown
Subject: Security Vulnerabilities in CERTCC/cveClient

Dear CERT/CC Vulnerability Coordination Team,

I am writing to report [N] security vulnerabilities identified in the
cveClient project (https://github.com/CERTCC/cveClient).

I have filed GitHub Private Security Advisories for each finding on the
repository. The advisories contain full details, CVSS 4.0 scores, and
proof-of-concept information.

Summary of findings:
[Numbered list of finding titles and severities]

Advisory links:
[Links to filed GHSAs — to be added after filing]

I am available to discuss these findings and assist with remediation.

Best regards,
Jerry Gamblin
jerry.gamblin@gmail.com
```

- [ ] **Step 3: Review all drafts for accuracy**

Re-read each GHSA draft against the audit document. Ensure CVSS vectors are correct, PoCs are reproducible, and remediation advice is actionable.

---

## Phase 3: Security Fix PRs

### Task 13: PR 1 — XSS Remediation

**Files:**
- Modify: `cveInterface.js:385-393, 833-842, 859, 903-906, 935, 965, 1404`
- Modify: `autoCompleter.js:97` (defense-in-depth)

- [ ] **Step 1: Create branch**

Run: `git checkout -b security/xss-remediation main`

- [ ] **Step 2: Fix top_alert() to sanitize msg parameter**

In `cveInterface.js`, change line 387 from:
```javascript
.addClass("alert alert-"+lvl).html(msg).fadeIn();
```
to:
```javascript
.addClass("alert alert-"+lvl).html(safeHTML(msg)).fadeIn();
```

Also update line 1404 to remove inline HTML:
```javascript
top_alert("success", "User ("+username+") Active status has been updated to [" + String(f.active)+"]",4000);
```

- [ ] **Step 3: Fix deepdive() to sanitize data-uniqueid**

Change line 837 from:
```javascript
$('#detailtag').html("("+tinfo+")");
```
to:
```javascript
$('#detailtag').text("("+tinfo+")");
```

Change line 839 and 842 similarly to use `.text('')`.

- [ ] **Step 4: Fix deepdive() line 859**

Change from:
```javascript
$('#cveUpdateModal .mtitle').html("("+row.cve_id+")");
```
to:
```javascript
$('#cveUpdateModal .mtitle').text("("+row.cve_id+")");
```

- [ ] **Step 5: Fix user_update_modal() line 965**

Change from:
```javascript
$('#addUserModal .mtitle').html("Update User ("+mr.username+")");
```
to:
```javascript
$('#addUserModal .mtitle').text("Update User ("+mr.username+")");
```

- [ ] **Step 6: Fix add_option() line 16**

Change `.html(f)` to `.text(f)`:
```javascript
$(w).append($('<option/>').attr({value:v,selected:s})
    .text(f));
```

- [ ] **Step 7: Defense-in-depth comment for autoCompleter.js**

Add security comment at line 37:
```javascript
function cleanHTML(content) {
    /* Security: escapes HTML entities to prevent XSS when used with innerHTML */
    const div = document.createElement("div");
    div.textContent = content;
    return div.innerHTML;
}
```

- [ ] **Step 8: Test manually in browser**

Open the application in a browser. Verify:
1. Login still works
2. CVE table displays correctly
3. User table displays correctly
4. Deep dive modal shows correct data
5. Top alerts display correctly (without HTML rendering)
6. Dropdowns populate correctly

- [ ] **Step 9: Commit**

```
git add cveInterface.js autoCompleter.js
git commit -m "fix: sanitize HTML output to prevent XSS

Replace .html() with .text() or safeHTML() for all DOM insertions
that include data from API responses or user input. This prevents
stored and reflected XSS via malicious usernames, CVE IDs, or
API response fields."
```

---

### Task 14: PR 2 — Credential and Crypto Hardening

**Files:**
- Modify: `cveInterface.js:618-632, 744-749, 1276, 1346, 1868`
- Modify: `encrypt-storage.js:98-130`
- Modify: `index.html:98`
- Modify: `schemaToForm.js:523`

- [ ] **Step 1: Create branch**

Run: `git checkout -b security/credential-hardening main`

- [ ] **Step 2: Fix credential storage race condition**

In `cveInterface.js`, the login success handler (around line 615-632) stores credentials before encryption completes. Restructure so the API key is only stored after encryption.

Change the storage loop (lines 630-632) to skip the key field:
```javascript
$('#loginModal .form-control').each(function(_,x) {
    var fid = $(x).attr('id');
    if(fid !== 'key') {
        store.setItem(store_tag+fid, $(x).val());
    }
});
```

The key will be stored by `enable_encryption()` at line 1879 after encryption completes. If encryption fails, the key should not be persisted in plaintext.

- [ ] **Step 3: Fix extractable key generation**

In `encrypt-storage.js`, change line 125 from `true` to `false`:
```javascript
false,
```

This makes the generated key non-extractable. Since `save_key()` calls `exportKey()`, it will break. Restructure `save_key` to store CryptoKey objects directly in IndexedDB (they are structured-clonable):

```javascript
async function save_key(user, key) {
    let fpb = await window.crypto.subtle.exportKey("jwk", key.publicKey);
    let sum = {sha256: await sha256sum(fpb.n)};
    dbManager(user, {privateKey: key.privateKey, publicKey: key.publicKey}, sum);
    return key;
}
```

Update `import_key` to handle both legacy JWK format and new CryptoKey format:

```javascript
async function import_key(keyData) {
    if(keyData.privateKey instanceof CryptoKey) {
        return keyData;
    }
    let prkey = await window.crypto.subtle.importKey("jwk",keyData.epr,
        {name:"RSA-OAEP", hash: {name: "SHA-256"}},false,['decrypt']);
    let pbkey = await window.crypto.subtle.importKey("jwk",keyData.epb,
        {name:"RSA-OAEP", hash: {name: "SHA-256"}},false,['encrypt']);
    return { privateKey: prkey, publicKey: pbkey };
}
```

**Important:** CryptoKey objects with `extractable: false` may not be structured-clonable in all browsers. Test this in Chrome, Firefox, and Safari. If it fails, keep `extractable: true` for generation but re-import with `extractable: false` immediately after saving. The `import_key()` function already does this at line 107-108.

- [ ] **Step 4: Remove console.log of sensitive data**

Delete these lines in `cveInterface.js`:
- Line 746: `console.log(client.key);`
- Line 749: `console.log(client.key);`
- Line 1346: `console.log(updates);`

In `schemaToForm.js`:
- Line 523: `console.log(x);` — delete

- [ ] **Step 5: Remove hardcoded placeholder password**

In `index.html`, change line 98 from:
```html
<div id="cpassword" class="d-none cpassword">SYHpbZuvOGS80P5oNX</div>
```
to:
```html
<div id="cpassword" class="d-none cpassword"></div>
```

- [ ] **Step 6: Test manually**

1. Fresh login — verify credentials are encrypted before storage
2. Check localStorage in DevTools — key should be a data URI, not plaintext
3. Check IndexedDB — verify key storage works
4. Check console — no API keys logged
5. Enable/disable encryption toggle — verify round-trip works
6. Reset user API key — verify new key is encrypted

- [ ] **Step 7: Commit**

```
git add cveInterface.js encrypt-storage.js index.html schemaToForm.js
git commit -m "fix: harden credential storage and cryptographic key handling

- Defer API key storage until encryption completes (fixes race condition)
- Set RSA key extractable:false to prevent JWK export of private keys
- Remove console.log calls that leak API keys and sensitive data
- Remove hardcoded placeholder from password element"
```

---

### Task 15: PR 3 — Dependency Updates

**Files:**
- Modify: `index.html:9-25`

- [ ] **Step 1: Create branch**

Run: `git checkout -b security/dependency-updates main`

- [ ] **Step 2: Identify latest secure versions**

Research current latest versions:
- jQuery: check latest 3.x release
- Bootstrap: check latest 4.x release (stay on 4.x to avoid breaking changes)
- Popper.js: check latest 1.x release (required by Bootstrap 4)
- Bootstrap-Table: check latest release compatible with Bootstrap 4

Run: `npm view jquery version && npm view bootstrap@4 version && npm view popper.js version && npm view bootstrap-table version`

- [ ] **Step 3: Update CDN references and SRI hashes**

For each dependency, update the `src`/`href` URL and `integrity` hash in `index.html`.

Generate new SRI hashes for each CDN URL:
```
curl -s <CDN_URL> | openssl dgst -sha384 -binary | openssl base64 -A
```

Update lines 10-11 (Bootstrap CSS), 13-14 (jQuery), 17-18 (Popper.js), 20-21 (Bootstrap JS), 24 (Bootstrap-Table CSS), 25 (Bootstrap-Table JS).

- [ ] **Step 4: Test for breaking changes**

Open the application and test:
1. Login modal renders correctly
2. Tables load and paginate
3. Modals open and close
4. Dropdowns work
5. Alerts display
6. Form validation works
7. SweetAlert dialogs appear

- [ ] **Step 5: Commit**

```
git add index.html
git commit -m "fix: update frontend dependencies to latest secure versions

Update jQuery, Bootstrap, Popper.js, and Bootstrap-Table to their
latest stable releases within the same major version to address
known CVEs while maintaining compatibility."
```

---

### Task 16: PR 4 — Input Validation and Hardening

**Files:**
- Modify: `cveInterface.js:395-417, 1811-1820, 1958-1971`

- [ ] **Step 1: Create branch**

Run: `git checkout -b security/input-validation main`

- [ ] **Step 2: Add warning for custom API URLs**

In `cveInterface.js`, modify `urlprompt()` (line 395-417). After URL validation, add a known-host check:

```javascript
function urlprompt(w) {
    if($(w).val() == "custom") {
        $('#loginModal').removeAttr("tabindex");
        Swal.fire({
            title: 'Enter API URL',
            input: 'url',
            inputLabel: 'API URL',
            inputPlaceholder: 'API URL',
            showCancelButton: true,
            inputValidator: function(value) {
                if (!value) {
                    return 'You need to write something!';
                }
                try {
                    var f = new URL(value);
                } catch(err) {
                    return 'URL is invalid';
                }
                var knownHosts = ['cveawg.mitre.org', 'cveawg-test.mitre.org',
                                  '127.0.0.1', 'localhost'];
                if(knownHosts.indexOf(f.hostname) === -1) {
                    return 'This URL is not a known CVE Services host. ' +
                        'Your API credentials will be sent to this server. ' +
                        'Only use URLs you trust.';
                }
                add_option(w, f.toString(), f.host, 1);
                $('#loginModal').attr("tabindex", "-1");
            }
        });
    }
}
```

- [ ] **Step 3: Replace dynamic window[] function lookup**

First, identify all `data-update` values used:

Run: `grep -n 'data-update' index.html cveInterface.js`

Then replace lines 1814-1820 with an explicit function map:

```javascript
var _update_handlers = {
    "cweUpdate": cweUpdate,
    "new_username": checkchange
};

// In clearoff(), replace the dynamic lookup block:
if($(w).attr("data-update")) {
    var fname = $(w).attr("data-update");
    if(fname in _update_handlers) {
        var f = _update_handlers[fname];
        setTimeout(function() {
            f(w);
        }, 500);
    }
}
```

**Important:** Verify the complete list of `data-update` handler names from the grep results and include ALL of them in the map.

- [ ] **Step 4: Harden queryParser**

In `cveInterface.js`, add prototype pollution protection to `queryParser()` at line 1958-1971:

```javascript
function queryParser(query) {
    const urlParams = {};
    let match;
    const pl = /\+/g;
    const search = /([^&=:]+)[=:]?([^&]*)/g;
    const decode = function (s) {
        return decodeURIComponent(s.replace(pl, " "));
    };
    var blocked = {"__proto__": 1, "constructor": 1, "prototype": 1};
    if(!query)
        query = window.location.search.substring(1);
    if((location.search == "") && (location.hash != ""))
        query = location.hash.substring(1);
    while (match = search.exec(query)) {
        var key = decode(match[1]);
        if(!(key in blocked))
            urlParams[key] = decode(match[2]);
    }
    return urlParams;
}
```

- [ ] **Step 5: Test manually**

1. Try "Custom" URL option — verify known hosts work and unknown hosts show warning
2. Test CWE autocomplete — verify `data-update="cweUpdate"` still triggers
3. Test URL with query parameters — verify app loads correctly
4. Test URL with `?__proto__=test` — verify it is blocked

- [ ] **Step 6: Commit**

```
git add cveInterface.js
git commit -m "fix: harden input validation and remove dynamic code execution

- Add known-host validation for custom API URLs with user warning
- Replace window[] dynamic function lookup with explicit handler map
- Add prototype pollution protection to URL query parameter parser"
```

---

## Phase 4: Schema and ADP Compatibility

### Task 17: PR 5 — Schema Compatibility

**Files:**
- Modify: `cveInterface.js:5, 22`
- Modify: `schemaToForm.js:495-503`

- [ ] **Step 1: Create branch**

Run: `git checkout -b feature/schema-compatibility main`

- [ ] **Step 2: Research current CVE schema URL**

Verify the current schema endpoint and whether CVE 5.1 is available:

Run: `curl -sI "https://cveproject.github.io/cve-schema/schema/docs/CVE_Record_Format_bundled.json" | head -5`

Check if the schema has a version field we can detect.

- [ ] **Step 3: Parameterize schema URL**

In `cveInterface.js`, change line 5 from a const to a configurable value:

```javascript
var schemaUrl = "https://cveproject.github.io/cve-schema/schema/docs/CVE_Record_Format_bundled.json";
```

- [ ] **Step 4: Add schema version detection**

In `schemaToForm.js`, update `initializeForm()` (line 495-503) to capture schema version info:

```javascript
async function initializeForm(schemaUrl, elementId) {
    const schema = await fetchObj(schemaUrl);
    const dElement = document.getElementById(elementId);
    if (schema && dElement) {
        main.dElement = dElement;
        main.schemaVersion = schema.$id || schema.title || "unknown";
        createFormFromSchema(schema, dElement);
    } else {
        document.getElementById(elementId).textContent = 'Failed to load schema.';
    }
}
```

- [ ] **Step 5: Update hardcoded schema reference in chat prompt**

In `cveInterface.js` line 22, update the `askchatGPT` function to remove hardcoded "5.0":

```javascript
const prompt = "I have this CVE record and want help improve it especially the \"affected\" block.\nPlease check it against the CVE JSON schema guidance (https://github.com/CVEProject/cve-schema/blob/main/schema/docs/versions.md).\nHere is the full CVE Record:\n\n " + CVE_JSON;
```

- [ ] **Step 6: Test**

1. Verify schema loads and form generates correctly
2. Verify "All Fields" tab still works
3. Verify CVE publish still works with the schema

- [ ] **Step 7: Commit**

```
git add cveInterface.js schemaToForm.js
git commit -m "feat: improve schema compatibility and version detection

- Make schema URL configurable for future schema version updates
- Add schema version detection to schemaToForm
- Update hardcoded schema version references"
```

---

### Task 18: PR 6 — ADP Enhancements

**Files:**
- Modify: `cveClientlib.js:10-13`
- Modify: `cveInterface.js` (ADP-related sections)

- [ ] **Step 1: Create branch**

Run: `git checkout -b feature/adp-enhancements main`

- [ ] **Step 2: Research CVE-Services ADP API endpoints**

Check the CVE-Services API documentation to identify supported ADP endpoints. Verify which ADP endpoints exist beyond the current PUT `/cve/{cve}/adp`.

Run: `curl -s "https://cveawg-test.mitre.org/api" | python3 -m json.tool | head -50`

- [ ] **Step 3: Add missing ADP endpoint wrappers**

In `cveClientlib.js`, after the existing `publishadp()` method (line 10-13), add any verified endpoints:

```javascript
getadp(cve) {
    let path = "/cve/" + cve + "/adp";
    return this.getjson(path);
}
```

Only add endpoints that actually exist in the CVE-Services API. Do not add speculative endpoints.

- [ ] **Step 4: Improve ADP display in UI**

If there are verified ADP API endpoints, add UI elements to better surface ADP data. Keep changes minimal and functional. The scope depends on what the API actually supports.

- [ ] **Step 5: Test with CVE-Services test environment**

If access to the test environment is available:
1. Verify ADP read works for a CVE with ADP data
2. Verify ADP publish still works
3. Verify ADP display in the UI

- [ ] **Step 6: Commit**

```
git add cveClientlib.js cveInterface.js
git commit -m "feat: enhance ADP support with additional API endpoints

- Add ADP read endpoint wrapper
- Improve ADP data display in CVE detail view"
```

---

## Phase 5: PR Creation and Disclosure

### Task 19: Push branches and create PRs

- [ ] **Step 1: Push all branches to fork**

```
git push -u origin security/xss-remediation
git push -u origin security/credential-hardening
git push -u origin security/dependency-updates
git push -u origin security/input-validation
git push -u origin feature/schema-compatibility
git push -u origin feature/adp-enhancements
```

- [ ] **Step 2: Create security PRs (after GHSAs are filed)**

For each security branch, create a PR against `CERTCC/cveClient:main` using `gh pr create`. Include:
- Clear title describing the fix
- Summary of what changed and why
- Test plan checklist
- Reference to the GHSA (after filing)

- [ ] **Step 3: Create non-security PRs**

Create PRs for `feature/schema-compatibility` and `feature/adp-enhancements` branches with standard PR descriptions.

- [ ] **Step 4: File GHSAs and send disclosure email**

Jerry files GHSAs using the drafted content from Task 12, then sends the email to cert@cert.org.
