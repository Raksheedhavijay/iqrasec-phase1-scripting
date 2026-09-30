# IOC Extraction Report

- **Generated (UTC):** 2026-09-28 06:54:20
- **Tool:** IOCX v1.0.0
- **Unique indicators:** 32
- **Filtered out (private/allow-listed):** 3
- **Defanged output:** yes

## Sources

| Source | SHA-256 |
|---|---|
| samples/incident_report.txt | `ab9457e8a775b5975e57db42b535388a0778bf0b8254ad5a7c98d6b0dfc85046` |

## Summary

| Type | Unique |
|---|---|
| ipv4 | 2 |
| ipv6 | 1 |
| url | 3 |
| domain | 9 |
| email | 3 |
| md5 | 1 |
| sha1 | 1 |
| sha256 | 1 |
| cve | 2 |
| mitre | 4 |
| filename | 5 |

## High-attention indicators

| Type | Indicator | Why |
|---|---|---|
| url | `hxxp://91[.]215[.]85[.]17:8080/stage2/update[.]exe` | ip-in-url, non-standard-port, executable-download |
| url | `hxxp://bit[.]ly/3xYzAbC` | url-shortener |
| url | `hxxps://secure-invoice[.]xyz/login/verify[.]php` | suspicious-tld |
| domain | `secure-invoice[.]xyz` | suspicious-tld |
| domain | `a1[.]b2[.]c3[.]d4[.]evil-cdn[.]click` | suspicious-tld, deep-subdomain |
| domain | `bit[.]ly` | url-shortener |
| domain | `cdn-update[.]top` | suspicious-tld |
| domain | `paypa1-helpdesk[.]top` | suspicious-tld |
| domain | `xn--pypal-4ve[.]com` | punycode |
| filename | `invoice_september.docm` | macro/disk-image |
| filename | `invoice_viewer.dll` | executable |
| filename | `run.ps1` | executable |
| filename | `svchost_update.exe` | executable |
| filename | `update.exe` | executable |

## IPV4 (2)

| Indicator | Seen | Notes |
|---|---|---|
| `45[.]83[.]64[.]12` | 3 |  |
| `91[.]215[.]85[.]17` | 2 |  |

## IPV6 (1)

| Indicator | Seen | Notes |
|---|---|---|
| `2a01:4f8:c17:1234::2` | 1 |  |

## URL (3)

| Indicator | Seen | Notes |
|---|---|---|
| `hxxp://91[.]215[.]85[.]17:8080/stage2/update[.]exe` | 1 | ip-in-url, non-standard-port, executable-download |
| `hxxp://bit[.]ly/3xYzAbC` | 1 | url-shortener |
| `hxxps://secure-invoice[.]xyz/login/verify[.]php` | 1 | suspicious-tld |

## DOMAIN (9)

| Indicator | Seen | Notes |
|---|---|---|
| `secure-invoice[.]xyz` | 2 | suspicious-tld |
| `a1[.]b2[.]c3[.]d4[.]evil-cdn[.]click` | 1 | suspicious-tld, deep-subdomain |
| `bit[.]ly` | 1 | url-shortener |
| `cdn-update[.]top` | 1 | suspicious-tld |
| `iqrasec[.]example[.]org` | 1 |  |
| `microsoft[.]com` | 1 |  |
| `paypa1-helpdesk[.]top` | 1 | suspicious-tld |
| `update[.]microsoft[.]com` | 1 |  |
| `xn--pypal-4ve[.]com` | 1 | punycode |

## EMAIL (3)

| Indicator | Seen | Notes |
|---|---|---|
| `billing[@]secure-invoice[.]xyz` | 1 |  |
| `soc[@]iqrasec[.]example[.]org` | 1 |  |
| `support[@]paypa1-helpdesk[.]top` | 1 |  |

## MD5 (1)

| Indicator | Seen | Notes |
|---|---|---|
| `44d88612fea8a8f36de82e1278abb02f` | 1 |  |

## SHA1 (1)

| Indicator | Seen | Notes |
|---|---|---|
| `3395856ce81f2b7382dee72602f798b642f14140` | 1 |  |

## SHA256 (1)

| Indicator | Seen | Notes |
|---|---|---|
| `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f` | 2 |  |

## CVE (2)

| Indicator | Seen | Notes |
|---|---|---|
| `CVE-2021-4034` | 1 |  |
| `CVE-2023-23397` | 1 |  |

## MITRE (4)

| Indicator | Seen | Notes |
|---|---|---|
| `T1059.001` | 1 |  |
| `T1071.001` | 1 |  |
| `T1547.001` | 1 |  |
| `T1566.001` | 1 |  |

## FILENAME (5)

| Indicator | Seen | Notes |
|---|---|---|
| `invoice_september.docm` | 1 | macro/disk-image |
| `invoice_viewer.dll` | 1 | executable |
| `run.ps1` | 1 | executable |
| `svchost_update.exe` | 1 | executable |
| `update.exe` | 1 | executable |
