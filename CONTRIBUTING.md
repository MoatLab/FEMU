# Contributing to FEMU

Thank you for helping. FEMU is a QEMU-based NVMe SSD emulator; almost all of
its code lives under `hw/femu/`.

## Before you start
- Search existing issues and pull requests.
- For a new feature, open an issue first so the design can be agreed on before
  the code is written.
- Features that change device behaviour should be opt-in (a device property,
  off by default) unless they fix a bug.

## Building
```sh
mkdir build && cd build
../configure --target-list=x86_64-softmmu --disable-docs --enable-debug --enable-slirp
ninja qemu-system-x86_64 tests/qtest/qos-test
```

## Testing
Every fix and feature needs a test that fails without the change and passes
with it.
- Device tests (qtest), in `hw/femu/tests/qtest/femu-test.c`:
  ```sh
  cd build
  QTEST_QEMU_BINARY=./qemu-system-x86_64 ./tests/qtest/qos-test -m quick \
      -p /x86_64/pc/i440FX-pcihost/pci-bus-pc/pci-bus/femu/femu-tests
  ```
- Unit tests: `make -C hw/femu/tests check`
- Configuration examples: `hw/femu/scripts/ssd-config-test.sh build/qemu-system-x86_64`
- Please also run the tests under a build configured with
  `--enable-asan --enable-ubsan`.

## Style
FEMU follows QEMU's coding style: `./scripts/checkpatch.pl` must report no
errors or warnings for your change (a note about MAINTAINERS for new files is
expected). Use `/* */` comments that explain why, not what.

## Commits and sign-off
- One logical change per commit, with a subject like `femu: <what changes>`
  (72 characters at most) and a short body saying why.
- Sign off each commit (`git commit -s`) to certify the
  [Developer Certificate of Origin](https://developercertificate.org/).

## AI tools
You may use AI coding tools; you are the author and are responsible for every
line. Make sure you can explain each change without the tool, run the qtests,
`make -C hw/femu/tests check` and `make -C hw/femu/tests check-docs`, and paste
real output. Add `Assisted-by: <tool and model>` above `Signed-off-by` in each
commit a tool helped write; only a person signs off. Open an issue first for a
change of more than about 300 lines or one a tool mostly wrote. Agents must not
open issues or pull requests on their own. Read the
[AI policy](hw/femu/docs/ai-policy.md) for the full rules.

## Pull requests
Complete the checklist in the pull request description, say which FEMU modes
you tested, and link the issue. A maintainer will respond within 72 hours.

## Conduct and security
By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md),
not in public issues.
