# Reporting Security Issues

libNeoAppleArchive is meant for public use of the `.aar`/`.yaa` (and soon, `.aea`) file formats, and is not meant to be an entrypoint for bad actors. I appreciate your efforts to responsibly disclose your findings, and will make every effort to acknowledge your contributions.

To report a security issue, please use the GitHub Security Advisory ["Report a Vulnerability"](https://github.com/0xilis/libNeoAppleArchive/security/advisories/new) tab.

I will send a response indicating the next steps in handling your report. After the initial reply to your report, I will keep you informed of the progress towards a fix and full announcement, and may ask for additional information or guidance.

While it is not a requirement, it would be greatly beneficial to supply a Proof of Concept with your report to test the issue, if applicable. 

### Previous Reports

- Thanks to [@octane0x](https://github.com/octane0x) for reporting OOB reads / Denial-of-Service due to missing bounds checks in AEA parsing. Advisory here: [https://github.com/0xilis/libNeoAppleArchive/security/advisories/GHSA-2h29-26hf-rhgw](https://github.com/0xilis/libNeoAppleArchive/security/advisories/GHSA-2h29-26hf-rhgw). (CVE/CVEs pending)
- Thanks to [@DB85656](https://github.com/DB85656) for reporting various memory issues found via fuzzing. Advisory here: [https://github.com/0xilis/libNeoAppleArchive/security/advisories/GHSA-chpv-g239-pp39](https://github.com/0xilis/libNeoAppleArchive/security/advisories/GHSA-chpv-g239-pp39). (CVE/CVEs pending)
