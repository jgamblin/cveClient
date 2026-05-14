# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

cveClient is a browser-based CVE (Common Vulnerabilities and Exposures) management client and JavaScript library for CVE-Services 2.x API. It provides CVE JSON 5.x vulnerability management for CNAs (CVE Numbering Authorities) and Roots. Current version: 1.0.22.

Public demo: https://certcc.github.io/cveClient/

## Build & Development

**No build system.** This is a pure static web application — no package.json, no npm, no transpilation. Serve files directly from any web server (Apache, nginx, IIS). To develop locally, just open `index.html` via a local web server.

**No automated tests or linting.** Testing is manual/exploratory.

## Architecture

### Core Files

- **`cveClientlib.js`** — Reusable API client library. Class `cveClient` wraps CVE-Services REST API with `rfetch()` (Fetch API wrapper that injects API key auth). Methods: CVE CRUD (`publishcve`, `publishadp`, `getcvedetail`, `reservecve`), user management (`createuser`, `updateuser`, `listusers`), org info (`getorg`, `getquota`).

- **`cveInterface.js`** (~2000 lines) — Main UI logic. Handles login/logout, CVE operations (get, publish, reject, reserve), user management, chat integration, and form↔JSON conversion (`to_json`/`from_json`). Global `client` variable holds the active `cveClient` session.

- **`schemaToForm.js`** — Class `schemaToForm` dynamically generates HTML forms from the CVE JSON 5.0 schema. Bidirectional: `FormToObject()` extracts JSON from form fields, `ObjectToForm()` populates forms from JSON. Fields linked via `data-field` attributes.

- **`autoCompleter.js`** — Class `autoCompleter` providing autocomplete/suggestion UI for input fields with dynamic URL fetching.

- **`encrypt-storage.js`** — RSA-OAEP (4096-bit) encryption for API keys in browser storage using Web Crypto API + IndexedDB for key persistence.

- **`index.html`** — Single-page app with Bootstrap modals for login, CVE editing (tabs: Minimal, All Fields, JSON, ADP, Chatbot), user management, reservation, and rejection.

### Dependencies (CDN with SRI)

jQuery 3.5.1, Bootstrap 4.3.1, Bootstrap-Table 1.19.1, Popper 1.14.7. Local copies of Ace Editor (`ace-builds/`) and SweetAlert2 (`sweetalert2/`).

### Key Patterns

- Heavy jQuery DOM manipulation with Bootstrap modals
- `data-field` attributes map form elements to CVE JSON paths
- Promise-based async/await for all API calls
- State: global `client` object (session), localStorage/sessionStorage (credentials), IndexedDB (encryption keys)
- Dynamic HTML generation for array fields (versions, descriptions, references) using `duplicate()`/`unduplicate()`
- Version branches named `version-X.X.X`, PRs merged to `main`
