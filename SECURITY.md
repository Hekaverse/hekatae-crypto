# Security Policy

## Supported Versions

We release security updates for the latest minor version of `hekatae-crypto`.

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in this package or in any HEKATAE
service that handles user cryptography, please report it privately.

**Do not open a public issue for security bugs.**

### How to report

1. Open a **private vulnerability report** via GitHub:
   [Report a vulnerability](https://github.com/hekatae/hekatae-crypto/security/advisories/new)
2. Or email us directly at:
   **security@hekaverse.com**

Please include:
- A clear description of the vulnerability
- Steps to reproduce (proof-of-concept code, test vectors, or configuration)
- Impact assessment (what data or cryptographic property is at risk)
- Affected versions
- Any suggested remediation

### Response process

- We aim to acknowledge reports within **48 hours**.
- We will triage and provide an initial assessment within **5 business days**.
- Once a fix is ready, we will coordinate disclosure with you and publish a
  security advisory before releasing the patched version.

## Security Design

- All user Master Keys (UMK), Password-Derived Keys (PDK), and Content Keys
  (CK) are generated client-side with `crypto.subtle` / `crypto.getRandomValues`.
- This package does not transmit keys to HEKATAE servers.
- The server sees only ciphertext, encrypted shares, and encrypted recording keys.

## Scope

This policy covers:

- The `hekatae-crypto` source code and published npm package
- Cryptographic design flaws in the key hierarchy, share schemes, or cipher usage

It does **not** cover:

- Social engineering or account takeover of individual users
- Vulnerabilities in third-party dependencies unless they directly affect our
  usage (please report those to the upstream maintainers)
- Physical access to an unlocked user device

## Acknowledgments

We credit researchers who responsibly disclose valid security issues in our
release notes and security advisories (unless they prefer to remain anonymous).

## License

This security policy is provided under the same license as the project:
[Apache-2.0](./LICENSE).
