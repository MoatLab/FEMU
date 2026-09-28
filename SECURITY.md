# Security Policy

## Supported versions
Security fixes are made on `master` and in the latest release.

## Reporting a vulnerability
Please report vulnerabilities privately through GitHub:
**Security > Report a vulnerability** on
https://github.com/MoatLab/FEMU/security/advisories/new
Do not open a public issue for a suspected vulnerability.

Include the FEMU commit, the device options, the guest-visible trigger (for
example the NVMe command sequence), and the impact you observed.

## What to expect
- Acknowledgment within 3 business days.
- An initial assessment, including a CVSS v3.1 score, within 10 business days.
- A fix or mitigation for critical and high severity issues targeted within
  30 days, coordinated with the reporter before public disclosure.

## Scope
FEMU runs inside QEMU on the host. Issues where a guest can crash, hang or
corrupt the host process, read or write host memory outside the emulated
device, or exhaust host resources through the emulated device are in scope.
