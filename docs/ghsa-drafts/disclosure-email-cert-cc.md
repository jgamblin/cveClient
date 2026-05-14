# Disclosure Email to cert@cert.org

**To:** cert@cert.org
**From:** Jerry Gamblin
**Subject:** Security Vulnerabilities in CERTCC/cveClient v1.0.22

---

Dear CERT/CC Team,

I am writing to report four verified security vulnerabilities identified in the cveClient browser-based CVE management tool (https://github.com/CERTCC/cveClient), current version 1.0.22 at commit 527a895.

cveClient is used by CNAs to manage CVE records via the CVE-Services 2.x API, handling sensitive API credentials in the browser. All findings below were verified through complete data flow tracing from attacker-controlled sources to exploitable sinks.

I am prepared to submit fix PRs for all findings if the maintainer is interested.

---

## Finding 1: Stored XSS via Unsanitized Username in DOM Insertion

**Severity:** HIGH
**CVSS 4.0 Vector:** CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:A/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N
**CVSS 4.0 Score:** 7.1
**CWE:** CWE-79 (Cross-site Scripting)

**Description:**
Multiple locations in `cveInterface.js` use jQuery's `.html()` method to insert API response data (usernames, CVE IDs) into the DOM without sanitization. The application already has a `safeHTML()` function (line 1111-1112) but it is not consistently applied.

**Affected Code:**
- `cveInterface.js:387` — `top_alert()` uses `.html(msg)` without sanitization
- `cveInterface.js:965` — `user_update_modal()` uses `.html("Update User ("+mr.username+")")`
- `cveInterface.js:837` — `deepdive()` uses `.html("("+tinfo+")")` where tinfo can be a username
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

**Remediation:**
Replace `.html()` with `.text()` for all DOM insertions containing usernames, CVE IDs, or other API data. Apply `safeHTML()` to the `msg` parameter in `top_alert()`.

---

## Finding 2: Plaintext API Key Storage Due to Async Race Condition

**Severity:** HIGH
**CVSS 4.0 Vector:** CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N
**CVSS 4.0 Score:** 6.1
**CWE:** CWE-312 (Cleartext Storage of Sensitive Information), CWE-362 (Race Condition)

**Description:**
During login, the API key is stored in plaintext in localStorage/sessionStorage before the asynchronous encryption routine completes. The encryption library is loaded via `$.getScript()` which is asynchronous, but credential storage at line 631 executes synchronously and immediately.

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
3. Immediately observe `cveClient/key` contains the plaintext API key
4. After ~2-3 seconds, it's overwritten with an encrypted data URI

**Additional Concern:** If `encrypt-storage.js` fails to load (network error, CSP blocking), there is no `.fail()` handler — the plaintext key persists in localStorage permanently. The auto-login flow at lines 711-754 will use it without complaint.

**Remediation:**
Never store the API key before encryption completes. Add error handling for script load failure — if encryption fails, do not persist the key and warn the user.

---

## Finding 3: RSA Private Key Stored as Extractable JWK in IndexedDB

**Severity:** HIGH
**CVSS 4.0 Vector:** CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N
**CVSS 4.0 Score:** 7.1
**CWE:** CWE-522 (Insufficiently Protected Credentials), CWE-320 (Key Management Errors)

**Description:**
The RSA-OAEP 4096-bit keypair used to encrypt stored API keys is generated with `extractable: true`, and the private key is exported as a JWK object and stored in IndexedDB. Any JavaScript running in the same origin (including via XSS from Finding 1) can read the private key from IndexedDB and decrypt the API key from localStorage, rendering the entire encryption scheme ineffective.

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

**Proof of Concept (browser console or via XSS):**
```javascript
indexedDB.open("cve-services.apikeyStore",1).onsuccess = function(e) {
  var tx = e.target.result.transaction("keyStore");
  tx.objectStore("keyStore").getAll().onsuccess = function(r) {
    var privateKeyJWK = r.target.result[0].key.epr;
    crypto.subtle.importKey("jwk", privateKeyJWK,
      {name:"RSA-OAEP", hash:"SHA-256"}, true, ["decrypt"])
    .then(function(privKey) {
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

**Impact:** The encryption feature provides zero security benefit against same-origin attacks because both the encrypted data (localStorage) and the decryption key (IndexedDB) are accessible from the same trust boundary. Combined with Finding 1 (XSS), an attacker can extract any user's API key.

**Remediation:**
Generate keys with `extractable: false`. Store CryptoKey objects directly in IndexedDB (they are structured-clonable) instead of exporting as JWK.

---

## Finding 4: API Key Logged to Browser Console

**Severity:** MEDIUM
**CVSS 4.0 Vector:** CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N
**CVSS 4.0 Score:** 6.1
**CWE:** CWE-532 (Insertion of Sensitive Information into Log File)

**Affected Code:**
- `cveInterface.js:746` — `console.log(client.key)` during auto-login
- `cveInterface.js:749` — `console.log(client.key)` after encryption activation
- `cveInterface.js:1346` — `console.log(updates)` during user updates (PII/role data)
- `schemaToForm.js:523` — `console.log(x)` during form data conversion

**Description:**
The API key (in its encrypted data URI form) is logged to the browser console during auto-login. Combined with Finding 3 (extractable private key), an attacker with console access can decrypt it. Additionally, user update objects containing PII and role data are logged.

**Remediation:**
Remove all `console.log` calls that output `client.key` or user data objects.

---

## Additional Note: Outdated SweetAlert2 Dependency

The local copy of SweetAlert2 is version 11.4.9. CVE-2023-40042 affects versions < 11.7.27 and involves XSS via title/html parameters. cveClient passes API response data to `Swal.fire()` in multiple places. I recommend updating to SweetAlert2 11.10.x regardless of confirmed applicability.

---

## Disclosure Timeline

- **2026-03-28:** Findings reported to CERT/CC via this email
- **90-day disclosure window:** I will coordinate with you on patch timing before any public disclosure
- **Fix PRs:** I am prepared to submit pull requests for all findings against the CERTCC/cveClient repository

Please let me know if you need any additional information or would like to discuss these findings.

Best regards,
Jerry Gamblin
