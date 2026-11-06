# Test Results

Python version used: 3.12.10 | Operating system: Windows 11 | Date: 2026-11-06

| # | Input | Expected result | Actual result | Pass/Fail |
|---|-------|-----------------|---------------|-----------|
| 1 | https://www.example.com/login | No listed warning signs | No listed warning signs found. This does NOT prove safety. | PASS |
| 2 | http://192.0.2.10/account | IP address + HTTP | Uses an IP address instead of a familiar domain. <br> Uses HTTP. HTTPS alone does not prove trust. | PASS |
| 3 | http://example.com@sample.invalid/login | @ symbol + HTTP | Contains an @ symbol; inspect carefully. <br> Uses HTTP. HTTPS alone does not prove trust. | PASS |
| 4 | https://a.b.c.d.e.example.invalid/path | Many hostname segments | Contains many hostname segments/subdomains. | PASS |
| 5 | https://xn--example.invalid/ | Punycode-style hostname | Contains a punycode-style hostname. | PASS |

## Notes
- The test suite verified that each URL structural component (scheme, credentials, hostname, subdomains, length) is isolated and inspected accurately.
- Even with valid HTTPS or zero flagged heuristics, a link cannot be deemed definitively safe, proving why multi-layered threat intelligence is vital in cybersecurity.
- Defensive parsing prevented malformed strings (e.g. malformed IPv6 brackets) from crashing the inspection pipeline.

