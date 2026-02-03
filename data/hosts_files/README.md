# Blocklist Data Sources

This directory contains snapshots and slightly modified versions of third-party threat intelligence feeds and blocklists. These files are included locally to ensure compatibility with the application's internal parsers (e.g., handling specific CSV comment formats or encoding issues) during testing and development.

## ⚖️ Licenses and Attribution

The datasets included in this repository are the intellectual property of their respective creators. They are used here in accordance with their licenses.

### 1. StevenBlack Hosts
**File:** `hosts` (and variants)  
**Source:** [https://github.com/StevenBlack/hosts](https://github.com/StevenBlack/hosts)  
**License:** MIT License

> **Copyright (c) 2012-2026 Steven Black**
>
> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

Full license text: [StevenBlack/hosts/license.txt](https://github.com/StevenBlack/hosts/blob/master/license.txt)

---

### 2. URLhaus (abuse.ch)
**File:** `urlhaus.csv` (and variants)  
**Source:** [https://urlhaus.abuse.ch/](https://urlhaus.abuse.ch/)  
**Provider:** abuse.ch / Institute for Cybersecurity and Engineering  
**License:** CC0 1.0 Universal (Public Domain Dedication)

This dataset is operated by **abuse.ch**. While the data is provided under CC0 (No Rights Reserved), we strictly adhere to their request for attribution and their Terms of Use regarding the principles of use.

> **Attribution:**  
> This project uses data from URLhaus. URLhaus is a project from abuse.ch with the goal of sharing malicious URLs that are being used for malware distribution.

Terms of Use: [abuse.ch Terms of Use](https://abuse.ch/terms-of-use/#principles)

---

## ⚠️ Modifications

Please note that the files in this directory may differ slightly from the upstream "live" versions. Modifications have been made solely for:
1.  **Sanitization:** Removing non-standard comments (e.g., `#` comments inside CSV lines) that break strict CSV parsers.
2.  **Formatting:** Standardizing delimiters or headers for the test suite.

For production use, the application is configured to fetch and parse the live data directly from the respective sources.