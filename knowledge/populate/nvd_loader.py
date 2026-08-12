import json
import gzip
import urllib.request
import os
from typing import List, Dict, Optional, Tuple
from knowledge.query import VulnKnowledgeBase

# ── target products ───────────────────────────────────────────────────────────
TARGET_PRODUCTS = {
    # Priority 1
    "apache":     {"vendors": ["apache"], "products": ["http_server", "httpd"]},
    "php":        {"vendors": ["php"],    "products": ["php"]},
    "wordpress":  {"vendors": ["wordpress", "automattic"], "products": ["wordpress"]},
    "mysql":      {"vendors": ["mysql", "oracle"], "products": ["mysql"]},
    "openssh":    {"vendors": ["openbsd"], "products": ["openssh"]},
    "samba":      {"vendors": ["samba"],  "products": ["samba"]},
    "vsftpd":     {"vendors": ["vsftpd_project", "beasts"], "products": ["vsftpd"]},
    "proftpd":    {"vendors": ["proftpd"], "products": ["proftpd"]},
    "iis":        {"vendors": ["microsoft"], "products": ["internet_information_services", "iis"]},
    "smb":        {"vendors": ["microsoft"], "products": ["windows_server_2008", "windows_server_2012", "windows_server_2016", "windows_10", "windows_7"]},

    # Priority 2
    "postgresql": {"vendors": ["postgresql"], "products": ["postgresql"]},
    "tomcat":     {"vendors": ["apache"],  "products": ["tomcat"]},
    "nginx":      {"vendors": ["nginx"],   "products": ["nginx"]},
    "openssl":    {"vendors": ["openssl"], "products": ["openssl"]},
    "vnc":        {"vendors": ["realvnc", "tightvnc", "libvncserver"], "products": ["vnc", "tightvnc", "libvncserver"]},
    "rdp":        {"vendors": ["microsoft"], "products": ["remote_desktop_protocol", "remote_desktop_services"]},
    "telnet":     {"vendors": ["gnu", "netkit"], "products": ["inetutils", "telnetd"]},
    "bind":       {"vendors": ["isc"], "products": ["bind"]},
    "unrealircd": {"vendors": ["unrealircd"], "products": ["unrealircd"]},
    "distcc":     {"vendors": ["distcc"], "products": ["distcc"]},
}

MSF_MODULE_MAP = {
    "CVE-2011-2523": "exploit/unix/ftp/vsftpd_234_backdoor",
    "CVE-2007-2447": "exploit/multi/samba/usermap_script",
    "CVE-2010-3333": "exploit/unix/irc/unreal_ircd_3281_backdoor",
    "CVE-2009-3843": "exploit/unix/ftp/proftpd_133c_backdoor",
    "CVE-2020-1938": "auxiliary/admin/http/tomcat_ghostcat",
    "CVE-2004-2687": "exploit/unix/misc/distcc_exec",
    "CVE-2008-4250": "exploit/windows/smb/ms08_067_netapi",
    "CVE-2017-0144": "exploit/windows/smb/ms17_010_eternalblue",
    "CVE-2012-1823": "exploit/multi/http/php_cgi_arg_injection",
    "CVE-2014-6271": "exploit/multi/http/apache_mod_cgi_bash_env_exec",
    "CVE-2021-41773": "exploit/multi/http/apache_normalize_path_rce",
    "CVE-2021-42013": "exploit/multi/http/apache_normalize_path_rce",
    "CVE-2019-0232":  "exploit/windows/http/tomcat_cgi_cmdlineargs",
}

PORT_MAP = {
    "apache":     ["port:80", "port:443", "port:8080"],
    "php":        ["port:80", "port:443"],
    "wordpress":  ["port:80", "port:443"],
    "mysql":      ["port:3306"],
    "openssh":    ["port:22"],
    "samba":      ["port:445", "port:139"],
    "vsftpd":     ["port:21"],
    "proftpd":    ["port:21", "port:2121"],
    "iis":        ["port:80", "port:443"],
    "smb":        ["port:445"],
    "postgresql": ["port:5432"],
    "tomcat":     ["port:8080", "port:8180", "port:8443"],
    "nginx":      ["port:80", "port:443"],
    "openssl":    ["service:ssl"],
    "vnc":        ["port:5900"],
    "rdp":        ["port:3389"],
    "telnet":     ["port:23"],
    "bind":       ["port:53"],
    "unrealircd": ["port:6667"],
    "distcc":     ["port:3632"],
}

VULN_TYPE_KEYWORDS = {
    "rce":                  ["remote code execution", "arbitrary code", "execute arbitrary"],
    "auth_bypass":          ["authentication bypass", "bypass authentication", "unauthorized access"],
    "command_injection":    ["command injection", "os command", "shell injection"],
    "sql_injection":        ["sql injection"],
    "path_traversal":       ["path traversal", "directory traversal", "../"],
    "privilege_escalation": ["privilege escalation", "local privilege", "gain privileges"],
    "file_read":            ["arbitrary file read", "file disclosure", "information disclosure"],
    "default_credentials":  ["default credential", "default password", "default login"],
    "backdoor":             ["backdoor", "back door", "trojan"],
    "buffer_overflow":      ["buffer overflow", "heap overflow", "stack overflow"],
    "dos":                  ["denial of service", "crash", "resource exhaustion"],
}

NVD_FEED_BASE = "https://nvd.nist.gov/feeds/json/cve/2.0"
YEARS = list(range(2010, 2026))


# ── CPE parser ────────────────────────────────────────────────────────────────
def parse_cpe(cpe_uri: str) -> Dict:
    """
    Properly parse CPE 2.3 string into structured fields.
    Format: cpe:2.3:part:vendor:product:version:update:edition:...
    """
    parts = cpe_uri.split(":")
    return {
        "part":    parts[2]  if len(parts) > 2  else "*",
        "vendor":  parts[3]  if len(parts) > 3  else "*",
        "product": parts[4]  if len(parts) > 4  else "*",
        "version": parts[5]  if len(parts) > 5  else "*",
        "update":  parts[6]  if len(parts) > 6  else "*",
    }


def match_cpe_to_service(cpe: Dict) -> Optional[str]:
    """
    Match a parsed CPE against our TARGET_PRODUCTS.
    Returns service name if matched, None otherwise.
    Compares vendor AND product fields — no substring guessing.
    """
    vendor  = cpe.get("vendor", "*").lower()
    product = cpe.get("product", "*").lower()

    for service_name, spec in TARGET_PRODUCTS.items():
        vendor_match  = any(v == vendor  for v in spec["vendors"])
        product_match = any(p == product for p in spec["products"])

        if vendor_match or product_match:
            return service_name

    return None


# ── NVD 2.0 download ──────────────────────────────────────────────────────────
def download_nvd_feed(year: int, cache_dir: str = "./knowledge/cache") -> Optional[str]:
    os.makedirs(cache_dir, exist_ok=True)
    gz_path   = os.path.join(cache_dir, f"nvdcve-2.0-{year}.json.gz")
    json_path = os.path.join(cache_dir, f"nvdcve-2.0-{year}.json")

    if os.path.exists(json_path):
        print(f"  [cache] {year} already downloaded")
        return json_path

    url = f"{NVD_FEED_BASE}/nvdcve-2.0-{year}.json.gz"
    print(f"  [download] {url}")

    try:
        urllib.request.urlretrieve(url, gz_path)
        with gzip.open(gz_path, "rb") as f_in:
            with open(json_path, "wb") as f_out:
                f_out.write(f_in.read())
        os.remove(gz_path)
        print(f"  [ok] {year} downloaded")
        return json_path
    except Exception as e:
        print(f"  [error] {year}: {e}")
        return None


# ── NVD 2.0 parsing ───────────────────────────────────────────────────────────
def extract_cvss(cve: Dict) -> Tuple[float, str, str, str]:
    """
    Extract CVSS score, severity, complexity, privileges_required
    from NVD 2.0 format.
    Returns: (score, severity, complexity, privileges_required)
    """
    metrics = cve.get("metrics", {})

    # prefer v3.1 → v3.0 → v2.0
    for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        metric_list = metrics.get(metric_key, [])
        if not metric_list:
            continue

        metric = metric_list[0]
        cvss_data = metric.get("cvssData", {})
        score = float(cvss_data.get("baseScore", 0))

        if metric_key in ["cvssMetricV31", "cvssMetricV30"]:
            severity   = cvss_data.get("baseSeverity", "MEDIUM").lower()
            complexity = cvss_data.get("attackComplexity", "HIGH").lower()
            privileges = cvss_data.get("privilegesRequired", "NONE")
        else:
            score_val  = score
            severity   = "critical" if score_val >= 9 else "high" if score_val >= 7 else "medium"
            complexity = cvss_data.get("accessComplexity", "HIGH").lower()
            privileges = "NONE" if cvss_data.get("authentication", "NONE") == "NONE" else "LOW"

        complexity = "low" if complexity in ["low", "none"] else "medium" if complexity == "medium" else "high"
        return score, severity, complexity, privileges

    return 0.0, "medium", "high", "NONE"


def extract_configurations_20(cve: Dict) -> List[Dict]:
    """
    Extract and parse all CPE matches from NVD 2.0 configurations.
    Returns list of parsed CPE dicts.
    """
    parsed_cpes = []
    configurations = cve.get("configurations", [])

    for config in configurations:
        nodes = config.get("nodes", [])
        for node in nodes:
            for cpe_match in node.get("cpeMatch", []):
                if not cpe_match.get("vulnerable", False):
                    continue
                uri = cpe_match.get("criteria", "")
                if uri:
                    parsed = parse_cpe(uri)
                    # preserve version range info
                    parsed["version_start_including"] = cpe_match.get("versionStartIncluding")
                    parsed["version_end_including"]   = cpe_match.get("versionEndIncluding")
                    parsed["version_start_excluding"] = cpe_match.get("versionStartExcluding")
                    parsed["version_end_excluding"]   = cpe_match.get("versionEndExcluding")
                    parsed_cpes.append(parsed)

    return parsed_cpes


def classify_vuln_type(description: str) -> List[str]:
    """Classify vulnerability type from description text."""
    desc_lower = description.lower()
    types = []
    for vuln_type, keywords in VULN_TYPE_KEYWORDS.items():
        if any(kw in desc_lower for kw in keywords):
            types.append(vuln_type)
    return types if types else ["other"]


def build_rich_document(
    cve_id: str,
    service: str,
    product: str,
    version: str,
    description: str,
    vuln_types: List[str],
    cvss_score: float,
    privileges: str,
) -> str:
    """
    Build a rich embedding document for semantic search.
    More context = better retrieval quality.
    """
    parts = [
        cve_id,
        service,
        product,
    ]

    if version and version not in ["*", "-"]:
        parts.append(f"version {version}")

    # vulnerability type context
    parts.extend(vuln_types)

    # severity context
    if cvss_score >= 9.0:
        parts.append("critical severity")
    elif cvss_score >= 7.0:
        parts.append("high severity")

    # auth context
    if privileges == "NONE":
        parts.append("unauthenticated")
        parts.append("no authentication required")
    else:
        parts.append("requires authentication")

    # description — use full text for better semantic matching
    parts.append(description[:300])

    return " ".join(filter(None, parts))


def compute_quality_score(
    service: str,
    version: str,
    cvss_score: float,
    vuln_types: List[str],
    msf_module: str,
    has_version_range: bool,
) -> float:
    """
    Quality score 0.0 - 1.0 for KB prioritization.
    Higher = more actionable for pentest.
    """
    score = 0.0

    # product match (always true if we got here)
    score += 0.20

    # version data available
    if version and version not in ["*", "-"]:
        score += 0.15
    if has_version_range:
        score += 0.10

    # CVSS score
    if cvss_score >= 9.0:
        score += 0.20
    elif cvss_score >= 7.0:
        score += 0.10

    # high value vuln types
    high_value = {"rce", "auth_bypass", "command_injection",
                  "backdoor", "default_credentials", "path_traversal"}
    if any(vt in high_value for vt in vuln_types):
        score += 0.20

    # known MSF module
    if msf_module:
        score += 0.15

    return min(score, 1.0)


# ── main extraction ───────────────────────────────────────────────────────────
def is_relevant_20(cve: Dict) -> bool:
    """
    Filter CVEs using NVD 2.0 format.
    Must have CVSS >= 7.0 AND match a target product.
    """
    score, _, _, _ = extract_cvss(cve)
    if score < 7.0:
        return False

    cpes = extract_configurations_20(cve)
    for cpe in cpes:
        if match_cpe_to_service(cpe):
            return True

    return False


def extract_vuln_data_20(cve: Dict) -> Optional[Dict]:
    """
    Extract structured vulnerability from NVD 2.0 CVE item.
    """
    cve_id = cve.get("id", "")
    if not cve_id:
        return None

    # description
    descriptions = cve.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        ""
    )

    # CVSS
    cvss_score, severity, complexity, privileges = extract_cvss(cve)

    # CPE matching
    cpes = extract_configurations_20(cve)
    service = ""
    product = ""
    version = ""
    version_range = {}

    for cpe in cpes:
        matched_service = match_cpe_to_service(cpe)
        if matched_service:
            service = matched_service
            product = cpe.get("product", "").replace("_", " ")
            ver = cpe.get("version", "*")
            if ver not in ["*", "-", ""]:
                version = ver

            # preserve version range
            for range_key in ["version_start_including", "version_end_including",
                               "version_start_excluding", "version_end_excluding"]:
                val = cpe.get(range_key)
                if val:
                    version_range[range_key] = val
            break

    if not service:
        return None

    # vuln type classification
    vuln_types = classify_vuln_type(description)

    # MSF module
    msf_module = MSF_MODULE_MAP.get(cve_id, "")

    # references
    refs = cve.get("references", [])
    reference_urls = [r.get("url", "") for r in refs[:5] if r.get("url")]

    # quality score
    has_version_range = bool(version_range)
    quality = compute_quality_score(
        service, version, cvss_score,
        vuln_types, msf_module, has_version_range
    )

    # build evidence_needed
    evidence_needed = []
    ports = PORT_MAP.get(service, [])
    if ports:
        evidence_needed.append(ports[0])
    if product:
        evidence_needed.append(f"product:{product.split()[0]}")
    if version and version not in ["*", "-"]:
        evidence_needed.append(f"version:{version}")

    # rich embedding document
    document = build_rich_document(
        cve_id, service, product, version,
        description, vuln_types, cvss_score, privileges
    )

    return {
        "cve_id": cve_id,
        "document": document,
        "metadata": {
            "cve_id": cve_id,
            "service": service,
            "product": product,
            "version_affected": version,
            "version_range": json.dumps(version_range),
            "cvss_score": cvss_score,
            "severity": severity,
            "exploitation_complexity": complexity,
            "privileges_required": privileges,
            "requires_auth": privileges != "NONE",
            "vuln_types": " ".join(vuln_types),
            "metasploit_module": msf_module,
            "known_msf_module": msf_module,
            "validation_method": "",
            "evidence_needed": evidence_needed,
            "tags": f"{service} {product} {' '.join(vuln_types)}",
            "quality_score": quality,
            "references": " ".join(reference_urls),
            "source": "nvd_2.0",
        }
    }


# ── main loader ───────────────────────────────────────────────────────────────
def load_nvd_years(
    kb: VulnKnowledgeBase,
    years: List[int] = None,
    cache_dir: str = "./knowledge/cache",
    min_quality: float = 0.3,
) -> int:
    if years is None:
        years = YEARS

    total_loaded = 0
    total_skipped = 0
    total_irrelevant = 0

    print(f"\n[NVD Loader] NVD 2.0 bulk loader")
    print(f"[NVD Loader] years: {years}")
    print(f"[NVD Loader] min quality score: {min_quality}")
    print(f"[NVD Loader] KB currently: {kb.count()} vulnerabilities\n")

    for year in years:
        print(f"\n[NVD Loader] year {year}...")
        json_path = download_nvd_feed(year, cache_dir)
        if not json_path:
            continue

        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # NVD 2.0 uses "vulnerabilities" not "CVE_Items"
        cve_items = data.get("vulnerabilities", [])
        print(f"  [info] {len(cve_items)} CVEs in {year}")

        year_loaded = 0
        year_skipped = 0

        for item in cve_items:
            cve = item.get("cve", {})

            if not is_relevant_20(cve):
                total_irrelevant += 1
                continue

            vuln = extract_vuln_data_20(cve)
            if not vuln:
                year_skipped += 1
                total_skipped += 1
                continue

            # quality gate
            if vuln["metadata"]["quality_score"] < min_quality:
                year_skipped += 1
                total_skipped += 1
                continue

            try:
                kb.add_vulnerability(vuln)
                year_loaded += 1
                total_loaded += 1
            except Exception as e:
                print(f"  [error] {vuln.get('cve_id', '?')}: {e}")
                year_skipped += 1

        print(f"  [done] {year}: loaded={year_loaded} skipped={year_skipped}")

    print(f"\n[NVD Loader] COMPLETE")
    print(f"  Loaded:     {total_loaded}")
    print(f"  Skipped:    {total_skipped}")
    print(f"  Irrelevant: {total_irrelevant}")
    print(f"  KB total:   {kb.count()}")

    return total_loaded