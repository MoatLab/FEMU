# Use of AI tools in FEMU contributions

FEMU accepts contributions made with AI coding tools. The person who submits
a change is its author and is responsible for every line, whether they typed
it or a tool did.

## 1. What every contribution needs, with or without AI

- You understand the change and can explain any line of it in review without
  asking a tool. "The model wrote it" is not an answer.
- You built it and ran the tests yourself: the FEMU qtests,
  `make -C hw/femu/tests check` and `make -C hw/femu/tests check-docs`. CI must
  pass. A fix or a feature comes with a test that fails without it.
- You sign off each commit (`git commit -s`). Only a person may add
  `Signed-off-by`; a tool must never add it for you.

## 2. Disclose AI use

If an AI tool wrote or rewrote part of a commit, add a line naming the tool
above `Signed-off-by`:

```text
Assisted-by: <tool and model>
```

You may add what it did in parentheses, for example
`Assisted-by: <tool> (tests)`. Short autocompletion, spelling fixes and an AI
review of your own patch need no line. If in doubt, add it, and tick the AI
assistance box in the pull request description.

## 3. Size

Small AI-assisted fixes and AI-written tests need only the disclosure. A change
in which a tool wrote most of the functional code, or any change over about
300 changed lines, needs an issue where a maintainer agrees to review it
before you open the pull request. Split it into commits a person can review one
at a time.

## 4. Licensing and upstream QEMU

FEMU is GPL-2.0-or-later and contains QEMU files that are GPL-2.0-only. Do not
use a tool to reproduce, or to "clean room" rewrite, code under an incompatible
licence. New files carry `SPDX-License-Identifier: GPL-2.0-or-later`.

FEMU is built on QEMU, and the copy of QEMU's `docs/devel/code-provenance.rst`
in this tree states QEMU's rule for changes submitted to upstream QEMU, which
currently declines AI-generated content. It does not govern contributions to
FEMU. Do not send a commit with an `Assisted-by` line to upstream QEMU unless
QEMU's policy at that time allows it. If a change should go upstream, say so in
the pull request; it will be written without generative tools.

## 5. Not allowed

- Pull requests, issues or comments posted by an agent without a person
  reading them first.
- Large mechanical or "cleanup" changes that nobody reviewed line by line.
- Test results, benchmark numbers, logs or citations that you did not produce
  or check yourself. Paste the real command and its output.
- Weakening or deleting a test to make CI pass.
- Security reports written by a tool without a reproducer you ran on current
  `master`.

## 6. Issues and reviews

Write issues, pull request descriptions and review replies yourself. A tool may
fix your grammar. Output from a fuzzer, sanitizer or AI bug finder may be pasted
verbatim if you label it and checked that it is real.

## 7. Maintainers

Much of the maintainers' own consolidation work is AI-assisted, as the
[README](../../../README.md) states. Maintainers may use AI to triage or
pre-review, but post only review comments they have checked, and a person
decides every merge.

## 8. Enforcement

Maintainers may close a pull request without detailed review if it breaks these
rules, if the author cannot explain it, or if it looks unreviewed. A first
missing disclosure is fixed with a note on the pull request. Fabricated results
and repeated violations are handled under the Code of Conduct and may lead to a
ban from the project.

This policy is reviewed when QEMU's policy changes, and at least once a year.
