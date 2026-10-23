# Security Policy: SentinelX

## Defensive Scope & Operational Philosophy

SentinelX is developed strictly as a defensive telemetry monitoring and analytical detection platform.

### Non-Interference Guarantee
SentinelX detection rules and engines operate in an observational capacity. The software:
- **Does not execute active network countermeasures**, IP bans, connection resets, or process terminations.
- **Does not conduct offensive probing**, network scanning, port enumeration, or remote exploits.
- **Does not require elevated administrative privileges** for Phase 1 execution.

Alerts emitted by SentinelX represent evidence-backed hypotheses for human security analyst review or automated security operations workflows.

---

## Supported Environments

| Phase | Platform | Status | Privileges Required |
| :--- | :--- | :--- | :--- |
| **Phase 1 (Current)** | Windows 11 (64-bit) / Cross-platform synthetic verification | Supported (Development / Demo) | None (Standard user) |
| **Phase 2 (Planned)** | Windows 11 (64-bit) | Planned (Live telemetry collector) | Standard user (TCP table) / Admin for ETW |

---

## Current Security Limitations

1. **No External Security Audit**: SentinelX is an educational systems engineering and defensive architecture portfolio project. It has not undergone an independent third-party cybersecurity audit or formal certification.
2. **Synthetic Data Focus (Phase 1)**: The current analytical engine does not interact with the host operating system kernel or live network interfaces.
3. **No Tamper-Resistant Logging**: Application logs emitted to the console via `tracing` are intended for development diagnostics and should not be treated as cryptographically signed or tamper-proof audit trails.
4. **Local Execution Context**: SentinelX does not expose unauthenticated network listening sockets in Phase 1.

---

## Vulnerability Reporting

If you identify a security vulnerability, memory safety defect, or invariant bypass in SentinelX:

1. **Responsible Disclosure**: Please submit a private issue or advisory report through the repository's hosting provider interface (e.g., GitHub Security Advisories).
2. **Details to Include**:
   - Detailed description of the vulnerability and affected crate/module.
   - Minimal proof-of-concept (PoC) code or synthetic event payload.
   - Potential impact on analytical integrity or denial-of-service conditions.
3. **Response Protocol**: Security issues will be triaged and addressed with priority fixes in a designated patch release.
