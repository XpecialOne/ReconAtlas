
#!/usr/bin/env python3
"""
ReconAtlas v1.2
- Multi-keyword search (file or repeated -k)
- Wide templates (--wide)
- Excel-safe sanitizer + defensive retry
- Optional web snippet extraction (--include-web-snippets)
- Extra enrichment fields (isp, cpe_list, host_vulns, services_summary)
- Facets summaries (--facets) to Excel sheet
- Favicon hash pivot (--favicon-url ... adds http.favicon.hash:<hash>)
- Basic retry/backoff on Shodan 429
"""

import os, sys, argparse, json, concurrent.futures, re, time, base64
from time import sleep
from collections import defaultdict, Counter
from urllib.parse import urlparse
from dotenv import load_dotenv
import shodan, pandas as pd, requests, mmh3
from tqdm import tqdm
from openpyxl.utils.exceptions import IllegalCharacterError

load_dotenv()
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

# ---------------- Query templates ----------------
BASE_TEMPLATES = [
    'org:"{kw}"',
    'hostname:"{kw}"',
    'ssl.cert.subject.CN:"{kw}"',
    'ssl.cert.alt_names:"{kw}"',
    'ssl.cert.issuer.cn:"{kw}"',
    'ssl:"{kw}"',
    'http.title:"{kw}"',
    'product:"{kw}"',
    '"{kw}"',
    'port:80 "{kw}"',
    'port:443 "{kw}"',
    'org:{kw}',
    'domain:"{kw}"',
]

WIDE_TEMPLATES = [
    'http.html:"{kw}"',
    'http.headers:"{kw}"',
    'http.server:"{kw}"',
    'http.component:"{kw}"',
    'http.favicon.hash:{kw}',  # when kw is a hash
    'cpe:"{kw}"',
    'has_vuln:true "{kw}"',
    'vuln:{kw}',                 # use CVE as kw for this to hit
    'ssl.cert.serial:"{kw}"',
    'ssl.ja3:"{kw}"',
    'ssl.ja3s:"{kw}"',
    'ssl.cipher.name:"{kw}"',
    'ssl.version:"{kw}"',
    'tls.alpn:"{kw}"',
    'isp:"{kw}"',
    'asn:{kw}',
    'city:"{kw}"',
    'country:"{kw}"',
]

# --------------- Excel sanitizer -----------------
_ILLEGAL_XML_RE = re.compile(r'[\x00-\x08\x0B-\x0C\x0E-\x1F]')

def clean_value(val):
    if val is None: return val
    if isinstance(val, str): return _ILLEGAL_XML_RE.sub('', val)
    if isinstance(val, (bytes, bytearray)):
        try: s = val.decode('utf-8', errors='replace')
        except Exception: s = str(val)
        return _ILLEGAL_XML_RE.sub('', s)
    if isinstance(val, (list, dict, set, tuple)):
        try: s = json.dumps(val, default=str, ensure_ascii=False)
        except Exception: s = str(val)
        return _ILLEGAL_XML_RE.sub('', s)
    return val

def clean_df(df): return df.astype(object).applymap(clean_value)

# --------------- Utility -----------------
def build_queries(keyword, wide=False, extra_templates=None):
    templates = list(BASE_TEMPLATES)
    if wide: templates.extend(WIDE_TEMPLATES)
    if extra_templates: templates.extend(extra_templates)
    out, seen = [], set()
    for q in [t.format(kw=keyword) for t in templates]:
        if q not in seen: seen.add(q); out.append(q)
    return out

def load_keywords_from_file(path):
    kws = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"): continue
            kws.append(line)
    return kws

def backoff_sleep(attempt):
    t = min(60, 2 ** attempt)
    time.sleep(t)

def shodan_search_cursor(api, query, limit=None):
    attempt = 0
    while True:
        try:
            cursor = api.search_cursor(query)
            res = []
            for item in cursor:
                res.append(item)
                if limit and len(res) >= limit:
                    break
            return res
        except shodan.APIError as e:
            msg = str(e)
            if "429" in msg or "Too many requests" in msg:
                attempt += 1
                backoff_sleep(attempt)
                continue
            print(f"[!] Shodan API error for query `{query}`: {e}")
            return []

def shodan_host(api, ip):
    attempt = 0
    while True:
        try:
            return api.host(ip)
        except shodan.APIError as e:
            msg = str(e)
            if "429" in msg or "Too many requests" in msg:
                attempt += 1
                backoff_sleep(attempt)
                continue
            return {"ip_str": ip, "error": str(e)}

# --------------- Favicon hash pivot -----------------
def fetch_favicon_hash(url):
    u = urlparse(url)
    url_final = url
    if not u.scheme:
        url_final = "http://" + url
        u = urlparse(url_final)
    if not u.path or u.path == "/":
        url_final = url_final.rstrip("/") + "/favicon.ico"
    r = requests.get(url_final, timeout=15)
    r.raise_for_status()
    content = r.content
    b64 = base64.b64encode(content)
    return mmh3.hash(b64)

# --------------- Web snippet extraction ---------------
def extract_web_matches_for_keywords(item, keywords):
    out = {}
    http = item.get('http') or {}
    html = http.get('html')
    headers = http.get('headers') or {}
    header_blob = "\n".join(f"{k}: {v}" for k, v in headers.items()) if headers else ""
    banner = item.get('data')

    found = []
    for kw in keywords:
        if not isinstance(kw, str) or not kw:
            continue
        kw_re = re.compile(re.escape(kw), re.IGNORECASE)
        hit = {}
        if isinstance(html, str) and kw_re.search(html):
            i = kw_re.search(html).start()
            hit['match_in_html'] = True
            hit['html_snippet'] = html[max(0, i-150): i+150]
        if header_blob and kw_re.search(header_blob):
            hit['match_in_headers'] = True
        if isinstance(banner, str) and kw_re.search(banner):
            j = kw_re.search(banner).start()
            hit['match_in_banner'] = True
            hit['banner_snippet'] = banner[max(0, j-150): j+150]
        if hit:
            hit['keyword'] = kw
            found.append(hit)

    if found:
        out = {
            "port": item.get('port'),
            "title": http.get('title'),
            "matches": found
        }
        return out
    return None

# --------------- Flatten host ---------------
def flatten_host_for_row(host, include_banners=True, include_web_snippets=False, keywords=None):
    row = {}
    row['ip_str'] = host.get('ip_str') or host.get('ip')
    row['asn'] = host.get('asn')
    row['org'] = host.get('org')
    row['isp'] = host.get('isp')
    row['os'] = host.get('os')
    row['hostnames'] = ",".join(host.get('hostnames', [])) if host.get('hostnames') else None
    row['ports'] = ",".join(map(str, host.get('ports', []))) if host.get('ports') else None
    row['timestamp'] = host.get('timestamp') or host.get('last_update') or None
    row['tags'] = ",".join(host.get('tags', [])) if host.get('tags') else None
    loc = host.get('location', {}) or {}
    row['country_name'] = loc.get('country_name')
    row['city'] = loc.get('city')
    row['latitude'] = loc.get('latitude')
    row['longitude'] = loc.get('longitude')

    ssl = host.get('ssl')
    if isinstance(ssl, dict):
        cert = ssl.get('cert', {})
        if isinstance(cert, dict):
            subj = cert.get('subject', {}) or {}
            row['ssl_cn'] = subj.get('CN')
            alt = cert.get('alt_names')
            row['ssl_alt_names'] = ",".join(alt) if isinstance(alt, list) else (alt if isinstance(alt,str) else None)
            iss = cert.get('issuer', {}) or {}
            row['ssl_issuer'] = iss.get('CN') or cert.get('issuer')

    cpe_set, cve_set, services = set(), set(), []
    web_snippets = []

    for item in host.get('data', []) or []:
        for cpe in item.get('cpe', []) or []:
            cpe_set.add(cpe)
        vulns_obj = item.get('vulns') or {}
        if isinstance(vulns_obj, dict):
            cve_set.update(vulns_obj.keys())
        services.append({
            "port": item.get('port'),
            "transport": item.get('transport'),
            "product": item.get('product'),
            "version": item.get('version'),
            "module": (item.get('_shodan') or {}).get('module')
        })
        if include_web_snippets and (item.get('http') or item.get('port') in (80,443,8080,8443)):
            m = extract_web_matches_for_keywords(item, keywords or [])
            if m:
                web_snippets.append(m)

    host_vulns_top = host.get('vulns') or {}
    if isinstance(host_vulns_top, dict):
        cve_set.update(host_vulns_top.keys())

    row['cpe_list'] = ",".join(sorted(cpe_set)) if cpe_set else None
    row['host_vulns'] = ",".join(sorted(cve_set)) if cve_set else None
    row['services_summary'] = json.dumps(services, ensure_ascii=False)

    if include_web_snippets and web_snippets:
        s = json.dumps(web_snippets, ensure_ascii=False)
        row['web_matches'] = s[:60000]

    try:
        data = host.get('data')
        if data:
            first = data[0]
            http = first.get('http') or {}
            row['http_title'] = http.get('title')
            if include_banners:
                banner_raw = first.get('data') or first.get('banner') or None
                if banner_raw:
                    row['banner_snippet'] = (banner_raw[:400] + '...') if len(banner_raw) > 400 else banner_raw
            row['product'] = first.get('product')
            row['module'] = (first.get('_shodan') or {}).get('module')
    except Exception:
        pass

    if include_banners:
        row['raw_json'] = json.dumps(host, default=str)

    return row

# --------------- Facets aggregation ---------------
def aggregate_facets(api, queries, facets_spec):
    if not facets_spec: return None
    agg = defaultdict(Counter)
    for q in queries:
        try:
            r = api.count(q, facets=facets_spec)
        except shodan.APIError as e:
            print(f"[!] Facets error for `{q}`: {e}")
            continue
        for facet, arr in (r.get('facets') or {}).items():
            for ent in arr or []:
                agg[facet][ent.get('value')] += ent.get('count', 0)
    rows = []
    for facet, counter in agg.items():
        for value, cnt in counter.most_common():
            rows.append({"facet": facet, "value": value, "count": cnt})
    return rows

# --------------- Save outputs ---------------
def save_excel(per_keyword_rows, combined_rows, facets_per_kw, output_path, append=False):
    writer_mode = 'w'
    if append and os.path.exists(output_path): writer_mode = 'a'
    with pd.ExcelWriter(output_path, engine="openpyxl", mode=writer_mode) as writer:
        df_comb = pd.DataFrame(combined_rows)
        try:
            df_comb.to_excel(writer, sheet_name="combined", index=False)
        except IllegalCharacterError:
            df_comb = clean_df(df_comb)
            df_comb.to_excel(writer, sheet_name="combined", index=False)

        for kw, rows in per_keyword_rows.items():
            safe_name = kw[:28].replace("/", "_").replace("\\", "_").replace("*","_").replace("?","_").replace("[","(").replace("]",")")
            sheetname = safe_name or "sheet"
            i = 1
            df = pd.DataFrame(rows)
            while writer.sheets.get(sheetname):
                i += 1; sheetname = f"{safe_name}_{i}"
            try:
                df.to_excel(writer, sheet_name=sheetname, index=False)
            except IllegalCharacterError:
                df = clean_df(df)
                df.to_excel(writer, sheet_name=sheetname, index=False)

        if facets_per_kw:
            facets_rows = []
            for kw, rows in facets_per_kw.items():
                for r in rows or []:
                    facets_rows.append({"keyword": kw, **r})
            if facets_rows:
                dff = pd.DataFrame(facets_rows)
                try:
                    dff.to_excel(writer, sheet_name="facets", index=False)
                except IllegalCharacterError:
                    dff = clean_df(dff)
                    dff.to_excel(writer, sheet_name="facets", index=False)

def save_csv_json(combined_rows, output_path):
    ext = output_path.split(".")[-1].lower()
    if ext == "csv": pd.DataFrame(combined_rows).to_csv(output_path, index=False)
    elif ext == "json":
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(combined_rows, fh, default=str, indent=2)
    else: raise ValueError("Unsupported extension for CSV/JSON saver")

# --------------- Main ---------------
def main():
    p = argparse.ArgumentParser(description="ReconAtlas 1.2")
    p.add_argument("-k","--keyword", action="append", help="Keyword to search (repeatable)")
    p.add_argument("--keywords-file", help="Path to file with one keyword per line")
    p.add_argument("-o","--out", default=None, help="Output filename (csv/xlsx/json)")
    p.add_argument("--max-hosts", type=int, default=None, help="Max unique hosts overall")
    p.add_argument("--limit-per-query", type=int, default=500, help="Max results per query template")
    p.add_argument("--no-enrich", action="store_true", help="Skip enrichment via api.host")
    p.add_argument("--extra-query", action="append", help="Add an extra query template (use {kw})")
    p.add_argument("--wide", action="store_true", help="Include wide set of query templates")
    p.add_argument("--sleep", type=float, default=1.0, help="Sleep seconds between queries")
    p.add_argument("--concurrent", type=int, default=0, help="Worker threads for enrichment")
    p.add_argument("--append", action="store_true", help="Append sheets to existing XLSX if present")
    p.add_argument("--estimate-only", action="store_true", help="Print planned query count and potential enrichment, then exit")
    p.add_argument("--include-web-snippets", action="store_true", help="Extract HTML/header/banner snippets for provided keywords")
    p.add_argument("--drop-banners", action="store_true", help="Do not include banner_snippet/raw_json in output")
    p.add_argument("--facets", default=None, help='Facets spec, e.g. "org:20,port:20,country:20" (consumes credits)')
    p.add_argument("--favicon-url", action="append", help="URL to a favicon (or base site); adds http.favicon.hash:<hash> query (repeatable)")
    args = p.parse_args()

    kws = []
    if args.keyword: kws.extend(args.keyword)
    if args.keywords_file:
        if not os.path.exists(args.keywords_file):
            print(f"[!] keywords file not found: {args.keywords_file}"); sys.exit(1)
        kws.extend(load_keywords_from_file(args.keywords_file))
    seen, ordered_kws = set(), []
    for kw in kws:
        if kw not in seen: seen.add(kw); ordered_kws.append(kw)
    if not ordered_kws:
        print("[!] No keywords provided. Use -k or --keywords-file."); sys.exit(1)

    out = args.out or f"results_{'_'.join([k.replace(' ', '_') for k in ordered_kws[:3]])}.xlsx"

    # Build extra templates from favicon URLs
    extra_templates = list(args.extra_query or [])
    favicon_hashes = []
    if args.favicon_url:
        for u in args.favicon_url:
            try:
                h = fetch_favicon_hash(u)
                favicon_hashes.append(h)
                extra_templates.append(f"http.favicon.hash:{h}")
                print(f"[+] Favicon hash for {u}: {h}")
            except Exception as e:
                print(f"[!] Favicon fetch/hash failed for {u}: {e}")

    # Estimate
    n_templates = len(BASE_TEMPLATES) + (len(WIDE_TEMPLATES) if args.wide else 0) + len(extra_templates)
    planned_queries = n_templates * len(ordered_kws)
    if args.estimate_only:
        print("=== ESTIMATE ONLY (no API calls) ===")
        print(f"Keywords: {ordered_kws}")
        print(f"Query templates per keyword: {n_templates}")
        print(f"Planned Shodan search queries: {planned_queries}")
        print(f"limit-per-query: {args.limit_per_query}  |  max-hosts: {args.max_hosts or 'unbounded'}")
        print("Potential enrichment calls depend on unique IPs found and --max-hosts / --no-enrich.")
        sys.exit(0)

    if not SHODAN_API_KEY:
        print("ERROR: SHODAN_API_KEY not found. Add it to your .env or environment variables."); sys.exit(1)
    api = shodan.Shodan(SHODAN_API_KEY)

    max_hosts = args.max_hosts; limit_per_query = args.limit_per_query
    do_enrich = not args.no_enrich; sleep_between_queries = args.sleep
    concurrent_workers = args.concurrent

    print(f"[+] Keywords: {ordered_kws}")
    print(f"[+] Output: {out}")
    print(f"[+] Enrichment: {'ON' if do_enrich else 'OFF'}; concurrent workers: {concurrent_workers}")
    print(f"[+] Queries per keyword: {n_templates} (base + wide + extras)")

    found = {}  # ip -> meta
    per_keyword_rows = defaultdict(list)
    facets_per_kw = {}

    # Searching per keyword
    for kw in ordered_kws:
        print(f"\n=== Searching keyword: {kw!r} ===")
        queries = build_queries(kw, wide=args.wide, extra_templates=extra_templates)
        for q in queries[:6]: print("   ", q)
        hits_for_kw = 0

        # optional facets aggregation per keyword
        if args.facets:
            try:
                facets_rows = aggregate_facets(api, queries, args.facets)
                facets_per_kw[kw] = facets_rows
            except Exception as e:
                print(f"[!] Facets aggregation failed for {kw}: {e}")

        for q in queries:
            results = shodan_search_cursor(api, q, limit=limit_per_query)
            for r in results:
                ip = r.get('ip_str') or r.get('ip')
                if not ip: continue
                if ip not in found:
                    found[ip] = {'matched_keywords': set(), 'matched_queries': set(), 'sample_hits': []}
                found[ip]['matched_keywords'].add(kw)
                found[ip]['matched_queries'].add(q)
                if len(found[ip]['sample_hits']) < 3:
                    found[ip]['sample_hits'].append(r)
                hits_for_kw += 1
                if max_hosts and len(found) >= max_hosts:
                    print(f"[!] Reached global max_hosts limit: {max_hosts}")
                    break
            if max_hosts and len(found) >= max_hosts: break
            sleep(sleep_between_queries)
        print(f"[+] Keyword {kw!r} matched ~{hits_for_kw} hits (raw), unique IPs so far: {len(found)}")

    print(f"\n[+] Total unique IPs found across all keywords: {len(found)}")

    # Enrich & flatten
    combined_rows = []
    ips = list(found.keys())

    def process_ip(ip):
        meta = found[ip]
        host_info = shodan_host(api, ip) if do_enrich else (meta['sample_hits'][0] if meta['sample_hits'] else {'ip_str': ip})
        host_info['_matched_keywords'] = list(meta['matched_keywords'])
        host_info['_matched_queries'] = list(meta['matched_queries'])
        row = flatten_host_for_row(
            host_info,
            include_banners=(not args.drop_banners),
            include_web_snippets=args.include_web_snippets,
            keywords=ordered_kws
        )
        row['matched_keywords'] = ",".join(sorted(host_info.get('_matched_keywords', [])))
        row['matched_queries'] = ",".join(sorted(host_info.get('_matched_queries', [])))
        return ip, row

    if concurrent_workers and do_enrich:
        print(f"[+] Enriching with {concurrent_workers} threads...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrent_workers) as ex:
            futures = {ex.submit(process_ip, ip): ip for ip in ips}
            for fut in tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc="Enriching hosts"):
                try:
                    ip, row = fut.result()
                    combined_rows.append(row)
                    for kw in row['matched_keywords'].split(","):
                        if kw: per_keyword_rows[kw].append(row)
                except Exception as e:
                    print(f"[!] Error enriching: {e}")
    else:
        print("[+] Enriching sequentially...")
        for ip in tqdm(ips, desc="Enriching hosts"):
            try:
                _, row = process_ip(ip)
                combined_rows.append(row)
                for kw in row['matched_keywords'].split(","):
                    if kw: per_keyword_rows[kw].append(row)
            except Exception as e:
                print(f"[!] Error enriching {ip}: {e}")

    if not combined_rows:
        print("[!] No results to save. Exiting."); return

    ext = (out.split(".")[-1].lower() if "." in out else "xlsx")
    if ext == "xlsx":
        save_excel(per_keyword_rows, combined_rows, facets_per_kw, out, append=args.append)
        print(f"[+] Wrote Excel workbook: {out} (combined + {len(per_keyword_rows)} keyword sheets{' + facets' if args.facets else ''})")
    elif ext in ("csv", "json"):
        save_csv_json(combined_rows, out); print(f"[+] Wrote {ext.upper()} file: {out}")
    else:
        fallback = out + ".xlsx"; save_excel(per_keyword_rows, combined_rows, facets_per_kw, fallback, append=args.append)
        print(f"[+] Unknown extension; wrote to {fallback}")

    # Raw hit metadata (audit)
    raw_out = f"raw_results_multi_keywords.json"
    with open(raw_out, "w", encoding="utf-8") as fh:
        json.dump({ip: {'matched_keywords': list(found[ip]['matched_keywords']),
                        'matched_queries': list(found[ip]['matched_queries'])} for ip in found},
                  fh, default=str, indent=2)
    print(f"[+] Saved raw hits/metadata to {raw_out}")

if __name__ == "__main__":
    main()
