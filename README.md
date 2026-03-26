# Web Cache Deception Scanner

A fast, concurrent, and dependency-free Node.js scanner designed to identify **Web Cache Deception** vulnerabilities in web applications.

## Overview

Web Cache Deception occurs when a web cache is tricked into storing sensitive, user-specific content and serving it to unauthenticated users. This happens when an application relies on permissive URL parsing, allowing attackers to append cacheable file extensions (like `.css` or `.js`) to paths containing sensitive information (e.g., `/my-account/non-existent-file.css`).

This script automates the detection of this vulnerability by testing multiple path-appending techniques and static directory bypasses, and it actively validates the results by checking for cache-hit HTTP response headers.

## Features

- **Concurrent Execution:** Requests are executed in parallel (`Promise.all`) to significantly speed up the scanning process.
- **Multiple Attack Vectors:** 
  - *Path Appending:* Tests various delimiters and URL-encoded characters (`/`, `%2f`, `;`, `%3b`, `%00`, `%0a`, etc.) combined with common cacheable extensions.
  - *Static Directory Bypass:* Exploits potential normalization mismatches between the frontend cache and backend server (e.g., `/static/..%2fmy-account/file.css`).
- **Accurate Confirmation:** It doesn't just look for sensitive data; it verifies actual caching behavior by inspecting headers like `X-Cache`, `CF-Cache-Status`, `Age`, and others.
- **Zero Dependencies:** Built entirely with native Node.js modules (`http`, `https`, `url`).

## Prerequisites

- Node.js installed on your machine.

## Usage

Run the script from your terminal:

```bash
node webCacheDeceptionScanner.js <targetUrl> <sensitiveKeyword> [cookie]
```

### Arguments

- `<targetUrl>`: The full URL of the page containing sensitive, authenticated data (e.g., `https://example.com/my-profile`).
- `<sensitiveKeyword>`: A unique string of text that only appears on the page when the user is properly authenticated (e.g., `"Welcome back, John Doe"` or your account email). This acts as the proof-of-concept trigger.
- `[cookie]` *(Optional but highly recommended)*: The full session cookie string required to access the sensitive page.

### Example

```bash
node webCacheDeceptionScanner.js "https://vulnerable-app.com/dashboard" "Your secret API key is" "session_id=s3cr3tt0k3n12345; user_id=9876"
```

## How It Works

For every generated payload, the scanner performs a 3-step verification:
1. **Poisoning:** Sends an authenticated request to the crafted URL (e.g., `https://target.com/dashboard/payload.css`).
2. **Check:** Immediately sends a second, unauthenticated request to the exact same URL.
3. **Confirmation:** If the second request returns the `sensitiveKeyword` AND contains a cache-hit header, the vulnerability is confirmed and the exact exploitation path is outputted.
