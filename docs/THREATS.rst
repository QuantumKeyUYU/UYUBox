# docs/THREATS.rst
.. SPDX-License-Identifier: MIT
.. SPDX-FileCopyrightText: 2025 Zilant Prime Core Contributors

Threat Model
============

Adversaries
-----------

- **A1 – Insider developer**: contributor with repo access who may inject malicious code.
- **A2 – Compromised CI/CD**: attacker gains control over the automation pipeline.
- **A3 – Stolen credentials**: leaked Vault or cosign keys used outside org.
- **A4 – Malicious dependency**: third-party package shipping vulnerable code.
- **A5 – Tampering user**: modifies artifacts or logs post-build.

Security Objectives
-------------------

- **C1 – Code integrity**: no unauthorized source changes.
- **C2 – Confidentiality of secrets**: Vault tokens/keys encrypted.
- **C3 – Traceability**: audit-log every build step.
- **C4 – Reproducibility**: identical artifacts from same tag.
- **C5 – Vulnerability free**: pass SBOM scanning.

Asset / Threat / Control
------------------------

- **Source code**
   - *Threat:* A1, A2
   - *Control:* signed commits; CI lint & tests

- **Secrets**
   - *Threat:* A3
   - *Control:* Vault AppRole; encrypted logs

- **Dependencies**
   - *Threat:* A4
   - *Control:* SBOM + Grype scans

- **Artifacts**
   - *Threat:* A5
   - *Control:* reproducible build; cosign signatures

- **Logs**
   - *Threat:* A5
   - *Control:* AES-GCM secure logger

- **Temporary directories**
   - *Threat:* A3 (leftover key files)
   - *Control:* use ``with tempfile.TemporaryDirectory():`` for auto-cleanup

- **CI logs**
   - *Threat:* A2, A3 (secrets printed via ``echo ${{ secrets.* }}``)
   - *Control:* mask via ``::add-mask::${{ secrets.NAME }}``

Mermaid Diagram
---------------

.. mermaid::

   graph LR
     A[Акторы] -->|атакуют| B[CLI]
     B -->|шифрует| C[AEAD Core]
     C --> D[Контейнер]
     C --> E[Watchdog]
     A -->|саботаж| E
     A -->|перехват| F[Журналы]
     F -->|шифруются| G[SecureLogger]

Static Diagram
---------------

.. image:: assets/threat_diagram.svg
   :alt: Threat Diagram

Threats for QAL
---------------

**Asset:** QAL key material
**Threat:** A3 – attacker forges quantum-authenticated link to inject bogus keys
**Vector:** MITM on QAL-packet; replay old messages
**Control:** HPKE integrity; verify timestamps/nonces; embed authenticity signature

Threats for PQRing
------------------

**Asset:** ring-signature keys
**Threat:** A1, A3 – replace ring public key
**Vector:** supply-chain compromise; config injection
**Control:** PKI trust-chain; cosign-sign keys; HSM-mode

Threats for QVPN
----------------

**Asset:** tunnel keys & metadata
**Threat:** A2, A4 – traffic analysis or VPN disable
**Vector:** DPI; DoS; DNS leaks
**Control:** kill-switch; multi-hop (Tor); HPKE metadata encryption

Attack Scenarios
----------------

1. **Подложный ring-ключ**

   - Replace public key in config → forged priv-key still verifies → attacker reads/modifies messages.
   - **Countermeasure:** store ring-keys in HSM; verify key signature at startup.

2. **Downgrade HPKE-канала**

   - MITM or compromised CI/CD intercepts key exchange; without context checks, inserts old key.
   - **Countermeasure:** use extended context in HPKE; enforce protocol version checks.
