<!-- SPDX-License-Identifier: Apache-2.0 -->
# AGENTS.md

## Security

You are helping a security researcher find and report vulnerabilities in
Apache Santuario (XML Security for Java). Before drafting any report or reaching
any conclusion, complete these steps.

### Step 1 — Read the threat model

Read **[THREAT_MODEL.md](THREAT_MODEL.md)**: the trust boundary, the central
**secure validation** knob, the properties provided vs. left to the caller, and
the known non-findings.

### Step 2 — Read the security policy

Read **[SECURITY.md](SECURITY.md)** for how to report and the published
advisories.

### Key scoping facts (see THREAT_MODEL.md)

- The library verifies/decrypts **attacker-controlled XML**; the calling
  application and its key-trust configuration are trusted.
- **Secure validation** mode is load-bearing: a finding that only manifests
  with secure validation *off* is out of model (it is the trusted-input
  posture) — see section 5a.
- The library does **not** decide **key trust** or **what the signature
  covers**: certificate-path validation and **XML-Signature-Wrapping** coverage
  checks are the caller's responsibility (sections 9/10). Route such findings
  there.
- The retired C++ project and archived repos are out of scope.

### Then assess

Route the finding to exactly one disposition in **THREAT_MODEL.md section 13**,
citing the section. If it cannot be routed, it is a `MODEL-GAP` — surface it.
