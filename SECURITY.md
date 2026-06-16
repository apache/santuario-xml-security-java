# Security Policy

## Supported Versions

### Apache XML Security for Java

| Version | Supported          |
| ------- | ------------------ |
| 4.0.x   | :white_check_mark: |
| 3.0.x   | :white_check_mark: |
| 2.3.x   | :white_check_mark: |
| 2.2.x   | :white_check_mark: |
| < 2.2.x | :x:                |

### Apache XML Security for C++

This project is retired.

## Reporting a Vulnerability

For information on how to report a new security problem please see [here](https://www.apache.org/security/).
Our existing security advisories are published [here](http://santuario.apache.org/secadv.html).

## Threat Model

A threat model for this library is maintained in
[THREAT_MODEL.md](THREAT_MODEL.md). It describes the trust boundary (the XML
submitted for verification/decryption is attacker-controlled), the central role
of **secure validation** mode, the properties the library provides and the ones
it leaves to the caller (notably **signature-coverage / XML-Signature-Wrapping**
checks and **key trust**), and the recurring non-findings. Triagers of scanner,
fuzzer, or AI-generated findings should route them through `THREAT_MODEL.md`
section 13 before reporting.
