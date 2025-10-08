
# 🕵️‍♂️ ReconAtlas

**ReconAtlas** is a Python tool that automates discovery and enrichment of public-facing assets using the [Shodan API](https://developer.shodan.io/).  
It allows you to provide one or more **keywords** (from a file or command-line) and automatically searches across a wide set of Shodan fields — including hostnames, domains, SSL certificates, HTTP metadata, and more.

This project is ideal for **security analysts**, **threat hunters**, and **vulnerability management teams** who want to quickly identify their organization’s exposed assets or related infrastructure.

---

## 🚀 Features

- 🔍 **Multi-keyword scanning** — provide one or many keywords (e.g., brand names, domains, internal projects).  
- 🌐 **Smart field coverage** — searches in hostnames, domains, organizations, HTTP headers, SSL CNs, alt names, CPEs, and more.  
- 🧠 **Enrichment mode** — fetches full host data (open ports, products, vulnerabilities, location, ASN, etc.).  
- 🧱 **Wide search mode (`--wide`)** — includes deeper fields such as `http.html`, `http.headers`, `http.server`, `http.component`, `ssl.ja3`, `tls.alpn`, and `http.favicon.hash`.  
- 🧩 **Web content inspection (`--include-web-snippets`)** — extracts where your keywords appear in HTML bodies, headers, or banners, with context snippets.  
- 🧾 **Structured outputs** — export to `.xlsx`, `.csv`, or `.json`, grouped per keyword with a combined summary sheet.  
- 📊 **Faceted summaries (`--facets`)** — get aggregated results by organization, country, or port.  
- 🖼️ **Favicon hash pivoting (`--favicon-url`)** — find visually identical sites based on favicon similarity.  
- 🧰 **Excel-safe sanitization** — avoids control character errors when exporting large or messy banners.  
- 🕒 **Backoff and retry** — handles Shodan rate limits gracefully.  

---

## 🧩 Installation

```bash
git clone https://github.com/XpecialOne/ReconAtlas.git
cd ReconAtlas
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.sample .env         # paste your SHODAN_API_KEY
```

---

## ⚙️ Usage

### Basic example
```bash
python ReconAtlas.py -k example.com -o results.xlsx
```

### Multiple keywords
```bash
python ReconAtlas.py --keywords-file keywords.txt -o results.xlsx
```

### Include wide templates and web snippets
```bash
python ReconAtlas.py --keywords-file keywords.txt --wide --include-web-snippets -o results.xlsx
```

### Limit results and disable enrichment
```bash
python ReconAtlas.py -k acme --no-enrich --limit-per-query 300 --max-hosts 1000 -o results.csv
```

### Add favicon hash pivot
```bash
python ReconAtlas.py -k acme --favicon-url https://acme.com/favicon.ico -o results.xlsx
```

### Get high-level asset distribution
```bash
python ReconAtlas.py --keywords-file keywords.txt --facets org:20,port:20,country:20 -o results.xlsx
```

### Estimate credit usage before running
```bash
python ReconAtlas.py --keywords-file keywords.txt --wide --estimate-only
```

---

## 📁 Output Overview

| Column | Description |
|--------|--------------|
| `ip_str` | Public IP address |
| `org`, `asn`, `isp` | Organization, ASN, and ISP |
| `ports`, `services_summary` | Open ports and summarized service data |
| `ssl_cn`, `ssl_alt_names`, `ssl_issuer` | Extracted SSL certificate details |
| `cpe_list` | List of known CPEs detected |
| `host_vulns` | Aggregated CVEs found for this host |
| `country_name`, `city`, `latitude`, `longitude` | Geolocation info |
| `web_matches` | JSON snippet of keyword hits in HTML, headers, or banners |
| `banner_snippet` | First 400 chars of service banner (optional) |

---

## ⚠️ API Credit Usage

- Each **search query** consumes **1 Shodan query credit**.  
- Each **enrichment (`api.host`)** call consumes **1 credit per IP**.  
- Use `--limit-per-query`, `--max-hosts`, and `--no-enrich` to manage usage.  
- The `--estimate-only` flag helps you plan before consuming credits.

---

## 💡 Recommended Workflows

1. **Asset discovery** — run wide scans for company names and domain roots to detect exposed infrastructure.  
2. **Brand monitoring** — include brand, product, and subsidiary names to detect look-alike domains.  
3. **Red teaming** — use favicon or JA3 pivots to find clone or staging servers.  
4. **Vulnerability triage** — combine results with CVE and CPE filters to identify exploitable systems.  

---

## 🧱 Example keyword file

`keywords.txt`
```
example.com
backup
nginx
```

---

## 🛠️ Dependencies

- [Python 3.9+](https://www.python.org/)  
- [Shodan API library](https://pypi.org/project/shodan/)  
- `pandas`, `requests`, `openpyxl`, `mmh3`, `tqdm`, `python-dotenv`

Install all with:
```bash
pip install -r requirements.txt
```

---

## 🧑‍💻 Author & License

Developed by **Soufiane Masaïf** – Cybersecurity consultant & OSINT Researcher  
Licensed under the **MIT License**.  
