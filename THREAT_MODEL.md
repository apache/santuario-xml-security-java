# Apache Santuario (XML Security for Java) — Threat Model

## §1 Header

- **Project:** Apache Santuario — XML Security for Java (`apache/santuario-xml-security-java`),
  artifact `org.apache.santuario:xmlsec`.
- **Written against:** `main` @ HEAD (2026-06), 4.0.x/3.0.x line.
- **Author:** ASF Security team, drafted via the threat-model-producer rubric
  (Michael Scovetta rubric) at the Apache Santuario PMC's request (path 3).
- **Status:** DRAFT — under maintainer review (2026-06-10). Not yet ratified.
- **Version binding:** versioned with the project; a report against version *N*
  is triaged against the model as it stood at *N*.
- **Reporting cross-reference:** §8-violating findings go to the disclosure
  channel in [`SECURITY.md`](SECURITY.md); §3/§9 findings are closed citing
  this document.
- **Provenance legend:** *(documented)* = project source / `SECURITY.md` /
  advisories (cited); *(maintainer)* = a Santuario maintainer in this review;
  *(inferred)* = reasoned from code/domain, not yet confirmed — each has a §14
  open question.
- **Draft confidence:** ~26 documented / 0 maintainer / 22 inferred.

**What it is.** A Java library implementing the W3C XML Signature and XML
Encryption standards (plus the JSR-105 javax.xml.crypto API). It is consumed
**in-process** by applications and frameworks (notably WS-Security stacks —
WSS4J, CXF, OpenSAML/Shibboleth, Apache Santuario users in SAML/SOAP) to
**sign, verify, encrypt, and decrypt XML**. It ships two implementations: a
mature **DOM**-based stack and a newer **StAX** (streaming) stack. The
security-critical operations are *verification* and *decryption* of
**attacker-controlled XML**.

## §2 Scope and intended use

Intended use: an application calls the library to verify a signature on, or
decrypt, an XML document that **originates outside the application's trust
boundary** (a SOAP message, a SAML assertion, a signed document). Equally, to
produce signatures/ciphertext over its own (trusted) data.

Caller trust level: the **calling application is trusted**; the **XML input to
verification/decryption is untrusted and adversary-controlled**. This is the
defining trust split of the library. *(inferred — Q1.)*

**Component families.**

| Family | Entry point | Processes untrusted XML? | In model? |
| --- | --- | --- | --- |
| DOM XML Signature (verify) | `XMLSignature.checkSignatureValue`, `SignedInfo` | **yes** | **Yes** |
| DOM XML Encryption (decrypt) | `XMLCipher.doFinal` / `decryptData` | **yes** | **Yes** |
| StAX (streaming) Sig/Enc | `InboundXMLSec`, `*InputProcessor` | **yes** | **Yes** |
| Transforms / canonicalization | `Transform`, `Transforms`, `Canonicalizer` | **yes** (transform chain runs on attacker XML) | **Yes** |
| Key resolution | `KeyResolver`, `*KeyResolverSpi` | **yes** (`KeyInfo` is attacker-supplied) | **Yes** |
| Signing / encryption (produce) | `XMLSignature.sign`, `XMLCipher.encryptData` | no — over trusted data | partial — see §3 |
| JSR-105 API surface | `javax.xml.crypto.dsig.*` | as above | **Yes** (delegates to DOM) |

## §3 Out of scope (explicit non-goals)

- **Establishing trust in the verifying key.** The library tells the caller
  *"this signature is cryptographically valid under key K"* and can resolve K
  from the message's `KeyInfo`. It does **not** decide whether K is *trusted*.
  Validating the certificate chain / matching K against an allow-list is the
  **caller's** responsibility (§10). A report that boils down to "I trusted a
  self-signed cert in `KeyInfo`" is `OUT-OF-MODEL: trusted-input` /
  `BY-DESIGN`. *(documented — KeyResolver returns keys; trust decisions are not
  in this layer.)*
- **What the signature covers.** The library verifies that *referenced*
  content has a valid digest; it does **not** decide whether the *right*
  content was signed. Checking that the signature covers the
  security-relevant elements (the XML-Signature-Wrapping defence) is the
  caller's job — see §9/§11. *(documented — this is the canonical XSW
  caveat.)*
- **Retired C++ project** (`santuario-xml-security-cpp`) and the two archived
  repos — out of scope. *(documented — SECURITY.md "retired".)*
- **The application's XML toolchain after extraction.** Once the caller pulls
  decrypted/verified content out and re-parses or deserializes it, that is the
  caller's pipeline.

## §4 Trust boundaries and data flow

The boundary is **the XML document submitted for verification/decryption**.
Everything in that document — elements, `Reference` URIs, `Transform` chains,
`KeyInfo`, `EncryptedKey`, algorithm identifiers, namespace prefixes — is
**attacker-controlled** and must be treated as hostile.

```
untrusted XML (SOAP/SAML/doc)
   │  attacker controls structure, transforms, KeyInfo, algorithms
   ▼
parse (DocumentBuilderFactory — DTD handling = §8/§5a)
   ▼
Signature verify: resolve References -> run Transform chain -> canonicalize -> digest -> verify sig
   │                         ▲ XSLT/XPath transforms run here (§9 false friend)
Decrypt: resolve EncryptedKey -> KeyResolver -> unwrap -> decrypt -> (optional) re-parse
   ▼
result handed to caller  ──►  caller must check WHO signed + WHAT was signed (§10)
```

**Reachability precondition (the triager's test):** a finding is in-model only
if reachable from the untrusted XML during verify/decrypt **with secure
validation enabled** (§5a). A finding that requires secure validation to be
*off*, or requires the caller to skip trust/coverage checks, is out of model
(§5a / §3).

## §5 Assumptions about the environment

- **Runtime:** a conformant JRE with a JAXP XML parser and a JCE provider for
  the crypto primitives. The library relies on the platform parser's DTD/entity
  controls (§5a). *(inferred — Q2.)*
- **JCE provider:** primitive correctness (RSA/AES/SHA, GCM nonce handling) is
  the provider's; the library composes them. *(inferred — Q3.)*
- **Concurrency:** `XMLSignature`/`XMLCipher` instances are not assumed
  thread-safe; per-operation instances are the expected usage. *(inferred —
  Q4.)*
- **No ambient side effects** beyond what a `Transform`/`KeyResolver` is
  configured to do — but note the default-resolver and transform behaviour can
  dereference URIs (§9). *(inferred — Q5, high priority.)*

## §5a Build-time and configuration variants — **the central knob**

**Secure validation mode is the load-bearing configuration.** Santuario
exposes a "secure validation" flag (e.g. `XMLSignature` /
`XMLCipher.setSecureValidation(true)`, the
`org.apache.xml.security.secureValidation` property, and on by default in some
JSR-105 paths). With secure validation **on**, the library:
- rejects DTDs / disables external entity and `RetrievalMethod`/`KeyInfo`
  remote dereferencing,
- forbids dangerous transforms (notably **XSLT**),
- enforces minimum key sizes and rejects known-weak digest/MAC/signature
  algorithms (e.g. MD5, SHA-1-in-signatures, RSA < 1024-ish, HMAC truncation),
- caps the number of `Reference`/`Transform` elements to bound expansion.
*(documented — these are the historical CVE mitigations folded into secure
validation; exact set is Q-confirmed in §14.)*

**The insecure-default problem (must be resolved by the maintainer).** Whether
secure validation is **on by default** depends on entry point and version
(the JSR-105 `javax.xml.crypto` path vs the native `org.apache.xml.security`
path have differed). This reshapes §8/§9/§11a/§13 simultaneously:
- If secure validation is the **supported posture for untrusted input** and a
  caller must opt in, then a report that only manifests with it **off** is
  `OUT-OF-MODEL: non-default-build` and §10 carries "enable secure
  validation."
- If it is **on by default** everywhere, the §8 properties hold out of the
  box. **This is wave-1 Q6 and the most important question in the model.**

## §6 Assumptions about inputs

Per-parameter trust for the security-critical entry points:

| Entry point | Parameter | Attacker-controllable? | Caller must enforce |
| --- | --- | --- | --- |
| signature verify | the XML document / `SignedInfo` | **yes** | enable secure validation; check coverage (§10) |
| signature verify | `KeyInfo` (embedded key/cert) | **yes** | establish trust in the resolved key — do not trust `KeyInfo` blindly |
| signature verify | `Reference` URI / `Transform` chain | **yes** | rely on secure validation to bound transforms/derefs |
| decrypt | `EncryptedData` / `EncryptedKey` | **yes** | secure validation; treat decrypted bytes as untrusted |
| decrypt | algorithm identifiers | **yes** | secure validation enforces allow-list |
| sign / encrypt | content to protect, signing key | **no** — caller-supplied trusted | protect the private key (caller) |

Plus: the parser-level inputs (DOCTYPE, entities, external refs) are
attacker-controlled and governed by §5a/§8.

## §7 Adversary model

- **In scope:** the party that supplies the XML being verified or decrypted —
  a network peer in a WS-Security/SAML exchange, the sender of a signed
  document. Capabilities: full control of the XML structure, transforms,
  `KeyInfo`, algorithms; ability to craft signature-wrapping, transform, key-
  confusion, decryption-oracle, and resource-exhaustion payloads. *(inferred —
  Q1.)*
- **Out of scope:** an attacker who controls the calling process or the
  trust/keystore configuration (they have already won); side-channel/co-tenant
  adversaries against the JCE provider (§5); an attacker who can make the
  caller *disable* secure validation or skip trust checks.

## §8 Security properties the project provides (with secure validation on)

1. **DTD / XXE rejection.** Secure validation rejects DOCTYPE and external
   entity resolution during parse/verify. *Violation:* external entity
   resolved / SSRF / file read. *Severity:* critical. *(documented — secure
   validation; Q6 for default.)*
2. **Dangerous-transform rejection.** XSLT (and other code-executing/remote-
   deref transforms) are disallowed under secure validation. *Violation:*
   XSLT/script or remote fetch via a `Transform`. *Severity:* critical.
   *(documented.)*
3. **Weak-algorithm rejection.** Known-weak digest/MAC/signature algorithms and
   undersized keys are rejected under secure validation. *Violation:* a
   signature accepted under MD5/short-HMAC/short-RSA. *Severity:* critical.
   *(documented — folds prior CVEs.)*
4. **Expansion bounding.** The number of `Reference`/`Transform` elements is
   capped to bound CPU/memory under secure validation. *Violation:* super-
   linear blowup from many references/transforms. *Severity:* security
   (DoS). *(inferred — Q7: confirm the exact caps.)*
5. **Cryptographic correctness of the verify/decrypt operation** given a
   well-formed signature and a provided key — i.e. an invalid signature does
   not verify true. *Violation:* signature forgery / bypass. *Severity:*
   critical. *(documented — core function.)*

## §9 Security properties the project does *not* provide

- **It does not tell you the signature covers the right thing.** A valid
  signature over *some* element is not a signature over the element your
  application cares about. **XML Signature Wrapping (XSW)** lives entirely in
  this gap and is the #1 real-world Santuario-adjacent vulnerability class —
  it is the *caller's* responsibility to verify that the verified `Reference`
  resolves to the security-relevant content. *(documented — canonical caveat.)*
  - *False friend:* "the signature verified" is **not** "the document is
    authentic and unmodified where it matters."
- **It does not establish key trust.** Resolving a key from `KeyInfo` is a
  convenience, not a trust decision; certificate-path validation / key pinning
  is the caller's (§3/§10).
- **No protection if secure validation is disabled.** With it off, XXE, XSLT
  transforms, weak algorithms, and unbounded expansion are all reachable — by
  design, for backward-compatible processing of *trusted* XML. *(documented —
  §5a.)*
- **No decryption-oracle hardening at the protocol layer.** The library
  performs the cryptographic decrypt; padding-oracle / replay / "decrypt-then-
  verify ordering" defences are protocol-level (WS-Security/SAML) concerns the
  caller's stack must handle. *(inferred — Q8.)*
- **Well-known attack classes the integrator owns:** XSW (coverage checking),
  XXE/billion-laughs when secure validation is off, key-confusion via
  unvalidated `KeyInfo`, and decryption oracles at the protocol layer.

## §10 Downstream responsibilities

- **Enable secure validation** for any XML from outside your trust boundary.
- **Check what was signed** — verify the signature's `Reference`s resolve to
  the exact content you are about to trust (defeat XSW); prefer ID-based
  references you control and re-check post-verify.
- **Establish key trust independently** — validate the cert chain / match the
  key against an allow-list; never trust `KeyInfo`-embedded keys implicitly.
- **Treat decrypted/verified bytes as untrusted** until your own validation
  passes; apply resource limits at the boundary.
- Protect signing/decryption private keys (caller-side key management).

## §11 Known misuse patterns

- **Trusting a valid signature without checking coverage** → XSW.
- **Trusting `KeyInfo` keys/certs** without path validation → accept attacker's
  key.
- **Processing untrusted XML with secure validation off** → XXE / XSLT / weak-
  algo / expansion.
- **Using verification as authorization** without binding the signer identity
  to an authorization decision.

## §11a Known non-findings (recurring false positives)

- **`DocumentBuilderFactory` / transform / weak-algo reachable with secure
  validation OFF** — non-finding: off is the trusted-input posture (§5a);
  reachability precondition (secure validation on) not met.
  `OUT-OF-MODEL: non-default-build` (pending Q6).
- **"KeyInfo lets an attacker supply a key"** — non-finding: key *trust* is the
  caller's (§3/§9). `BY-DESIGN`.
- **"A valid signature didn't protect element X"** where X wasn't referenced —
  non-finding: coverage checking is the caller's (§9). `BY-DESIGN` /
  `VALID-HARDENING` only if the API makes the safe check unreasonably hard.
- **Findings in the retired C++ project / archived repos** — `OUT-OF-MODEL:
  unsupported-component` (§3).
- **JCE-provider primitive issues** (RNG, GCM) — out of layer (§5).

## §12 Conditions that would change this model

- A change to secure-validation defaults or the set of checks it performs (§5a).
- A new transform/canonicalization algorithm, or a new key-resolver that
  dereferences remote material.
- The StAX stack diverging from the DOM stack on any §8 property.
- A report that cannot be routed to a §13 disposition → revise §8/§9.

## §13 Triage dispositions

| Disposition | Meaning | Licensed by |
| --- | --- | --- |
| `VALID` | A §8 property breaks with secure validation on, via untrusted XML. | §8, §6, §7 |
| `VALID-HARDENING` | No §8 break, but the API makes a §11 misuse (esp. XSW coverage) too easy. | §11 |
| `OUT-OF-MODEL: trusted-input` | Requires attacker control of key-trust / config the model trusts. | §6 |
| `OUT-OF-MODEL: adversary-not-in-scope` | Requires an excluded capability. | §7 |
| `OUT-OF-MODEL: non-default-build` | Only manifests with secure validation off. | §5a |
| `OUT-OF-MODEL: unsupported-component` | Retired C++ / archived repos. | §3 |
| `BY-DESIGN: property-disclaimed` | Key trust, coverage checking, protocol oracles. | §9 |
| `KNOWN-NON-FINDING` | Matches §11a. | §11a |
| `MODEL-GAP` | Unroutable. | triggers §12 |

## §14 Open questions for the maintainers

**Wave 1 — the load-bearing ones.**

- **Q1.** Confirm the trust split: calling application trusted; the XML
  submitted to verify/decrypt is fully attacker-controlled; the in-scope
  adversary is the XML supplier. (§2/§4/§7.)
- **Q6.** **Secure validation defaults** — for each entry point (native
  `org.apache.xml.security` vs JSR-105 `javax.xml.crypto`, DOM vs StAX, and by
  version), is secure validation **on by default**, or must the caller opt in?
  This decides whether secure-validation-off findings are `VALID` or
  `OUT-OF-MODEL: non-default-build`. (§5a/§8/§9/§11a/§13.)
- **Q-XSW.** Confirm the project's official position that **signature-coverage
  checking (XSW defence) is the caller's responsibility**, and point at the
  canonical guidance you want cited when closing XSW reports. (§9/§10.)

**Wave 2 — the secure-validation checklist (confirm/correct the §8 list).**

- **Q7.** Exact set enforced by secure validation: which algorithms/key sizes
  are rejected, which transforms are forbidden, and the caps on
  `Reference`/`Transform` counts? (§8.)
- **Q3/Q5.** Which transforms or key-resolvers can dereference remote/local
  URIs, and are any enabled even under secure validation? (§5/§8/§9.)
- **Q8.** Do you make any protocol-level guarantee (decryption-oracle, replay,
  decrypt/verify ordering), or is that explicitly the WS-Security/SAML caller's
  layer? (§9.)

**Wave 3 — surface & coexistence.**

- **Q2/Q4.** Parser/JCE assumptions and thread-safety expectations. (§5.)
- **Q9.** This adds `THREAT_MODEL.md` + `AGENTS.md` alongside your existing
  `SECURITY.md` (which we kept). Confirm the disclosure pointer and whether the
  model should become canonical with `SECURITY.md` linking to it. (§1/§15.)

## §15 Appendix — existing-policy back-map

The repo's `SECURITY.md` is a disclosure-process + supported-versions policy
(no embedded threat model); it points at the ASF security process and the
published advisories at `santuario.apache.org/secadv.html`. This
`THREAT_MODEL.md` is additive — `SECURITY.md` is preserved and gains a pointer
to the model. The published advisories are a high-value source for refining
§8/§11a in a later pass (each historical CVE maps to a secure-validation
mitigation).
