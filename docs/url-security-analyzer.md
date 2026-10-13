# URL Security Analyzer — Usage Guide

The URL Security Analyzer performs local, rule-based analysis of HTTP and HTTPS URLs to identify potentially suspicious characteristics.

It does not visit the URL or perform network requests.

### 1. Interactive mode

```bash
docker compose run --rm -it security-toolkit url analyze
```

Enter the URL when prompted.

### 2. Analyze a URL directly

```bash
docker compose run --rm security-toolkit url analyze "https://example.com"
```

### 3. Test suspicious URLs

**Potential brand impersonation:**

```bash
docker compose run --rm security-toolkit url analyze "https://paypal.com.example.net/login"
```

**IP address and nonstandard port:**

```bash
docker compose run --rm security-toolkit url analyze "http://192.168.1.10:8080/admin"
```

**Redirect parameter:**

```bash
docker compose run --rm security-toolkit url analyze "https://example.com/?redirect=https://other.example"
```

**URL shortener:**

```bash
docker compose run --rm security-toolkit url analyze "https://bit.ly/abc123"
```

### 4. Analysis results

| Field | Description |
|---|---|
| Hostname | Normalized URL hostname |
| Registered domain | Actual registered domain |
| Risk score | Heuristic score from 0 to 100 |
| Risk level | LOW, MEDIUM, HIGH, or CRITICAL |
| Indicators | Suspicious characteristics detected |
| Recommendations | Suggested precautions |

### 5. Risk classification

| Score | Risk level |
|---|---|
| `0–14` | LOW |
| `15–29` | MEDIUM |
| `30–74` | HIGH |
| `75–100` | CRITICAL |

### 6. Detected indicators

The analyzer checks for:

- HTTP connections without HTTPS.
- IP addresses used as hostnames.
- Nonstandard ports and excessive subdomains.
- Potential brand impersonation.
- Punycode and mixed-script domain names.
- Suspicious URL encoding.
- Redirect parameters.
- Known URL shortening services.
- Unusually long URLs and authentication-related paths.

### Important notes

- Analysis is entirely local; no HTTP, DNS, WHOIS, or reputation lookups are performed.
- Risk scores are heuristic, not probabilities of malicious activity.
- A LOW risk score does not guarantee that a URL is safe.
- HTTPS alone does not guarantee that a website is legitimate.
- Some internal domains may not be recognized because they lack a public suffix.