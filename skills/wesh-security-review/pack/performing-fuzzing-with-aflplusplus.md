---
name: performing-fuzzing-with-aflplusplus
description: Performs coverage-guided fuzzing of compiled binaries with AFL++, instrumenting targets via afl-cc/afl-clang-fast, minimizing corpora with afl-cmin and afl-tmin, running parallel campaigns with afl-fuzz, and triaging crashes with CASR or GDB scripts.
subdomain: application-security
facing: config
mitre_attack:
- T1078
- T1190
- T1059
- T1005
nist_csf:
- PR.PS-01
- PR.PS-04
- ID.RA-01
- PR.DS-10
upstream: performing-fuzzing-with-aflplusplus@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- AFL++ installed (`apt install afl++` or build from source)
- Target binary source code (for compile-time instrumentation) or QEMU mode for binary-only
- Initial seed corpus of valid inputs for target format
- Linux system with /proc/sys/kernel/core_pattern configured

## Steps

1. Instrument target binary with `afl-cc` or `afl-clang-fast`
2. Prepare seed corpus directory with minimal valid inputs
3. Minimize corpus with `afl-cmin` to remove redundant seeds
4. Run `afl-fuzz` with appropriate flags (-i input -o output)
5. Monitor fuzzing progress via afl-whatsup and UI stats
6. Triage crashes with `afl-tmin` minimization and CASR/GDB analysis
7. Report unique crashes with reproduction steps

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-fuzzing-with-aflplusplus
