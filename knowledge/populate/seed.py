"""
Curated seed dataset — high value CVEs matching common pentest targets.
Start small, validate the pipeline works, then bulk load NVD later.
"""

SEED_VULNERABILITIES = [
    {
        "cve_id": "CVE-2011-2523",
        "document": "vsftpd 2.3.4 FTP server backdoor remote code execution unix linux",
        "metadata": {
            "cve_id": "CVE-2011-2523",
            "service": "ftp",
            "product": "vsftpd",
            "version_affected": "2.3.4",
            "cvss_score": 10.0,
            "severity": "critical",
            "exploitation_complexity": "low",
            "requires_auth": False,
            "metasploit_module": "exploit/unix/ftp/vsftpd_234_backdoor",
            "validation_method": "send USER with :) suffix, check port 6200",
            "evidence_needed": ["port:21", "product:vsftpd", "version:2.3.4"],
            "tags": "backdoor rce ftp",
            "source": "nvd",
        }
    },
    {
        "cve_id": "CVE-2010-3333",
        "document": "UnrealIRCd 3.2.8.1 IRC server backdoor remote code execution",
        "metadata": {
            "cve_id": "CVE-2010-3333",
            "service": "irc",
            "product": "unrealircd",
            "version_affected": "3.2.8.1",
            "cvss_score": 10.0,
            "severity": "critical",
            "exploitation_complexity": "low",
            "requires_auth": False,
            "metasploit_module": "exploit/unix/irc/unreal_ircd_3281_backdoor",
            "validation_method": "send AB; to port 6667, check for shell",
            "evidence_needed": ["port:6667", "product:unrealircd"],
            "tags": "backdoor rce irc",
            "source": "nvd",
        }
    },
    {
        "cve_id": "CVE-2007-2447",
        "document": "Samba 3.0.20 usermap script command injection remote code execution SMB",
        "metadata": {
            "cve_id": "CVE-2007-2447",
            "service": "netbios-ssn",
            "product": "samba",
            "version_affected": "3.0.20",
            "cvss_score": 10.0,
            "severity": "critical",
            "exploitation_complexity": "low",
            "requires_auth": False,
            "metasploit_module": "exploit/multi/samba/usermap_script",
            "validation_method": "send username with shell metacharacters",
            "evidence_needed": ["port:445", "product:samba", "version:3.0.20"],
            "tags": "rce smb samba command-injection",
            "source": "nvd",
        }
    },
    {
        "cve_id": "CVE-2009-3843",
        "document": "ProFTPD 1.3.3c backdoor remote code execution FTP unix",
        "metadata": {
            "cve_id": "CVE-2009-3843",
            "service": "ftp",
            "product": "proftpd",
            "version_affected": "1.3.1",
            "cvss_score": 10.0,
            "severity": "critical",
            "exploitation_complexity": "low",
            "requires_auth": False,
            "metasploit_module": "exploit/unix/ftp/proftpd_133c_backdoor",
            "validation_method": "connect to port 6200 after trigger",
            "evidence_needed": ["port:2121", "product:proftpd", "version:1.3.1"],
            "tags": "backdoor rce ftp",
            "source": "nvd",
        }
    },
    {
        "cve_id": "CVE-2020-1938",
        "document": "Apache Tomcat AJP Ghostcat file read remote code execution",
        "metadata": {
            "cve_id": "CVE-2020-1938",
            "service": "ajp13",
            "product": "tomcat",
            "version_affected": "9.0.0-9.0.30",
            "cvss_score": 9.8,
            "severity": "critical",
            "exploitation_complexity": "low",
            "requires_auth": False,
            "metasploit_module": "auxiliary/admin/http/tomcat_ghostcat",
            "validation_method": "send AJP request to port 8009",
            "evidence_needed": ["port:8009", "product:tomcat"],
            "tags": "ghostcat ajp rce tomcat file-read",
            "source": "nvd",
        }
    },
    {
        "cve_id": "CVE-2004-2687",
        "document": "distcc daemon arbitrary command execution remote code execution",
        "metadata": {
            "cve_id": "CVE-2004-2687",
            "service": "distccd",
            "product": "distcc",
            "version_affected": "all",
            "cvss_score": 9.3,
            "severity": "critical",
            "exploitation_complexity": "low",
            "requires_auth": False,
            "metasploit_module": "exploit/unix/misc/distcc_exec",
            "validation_method": "send compile request with command injection",
            "evidence_needed": ["port:3632"],
            "tags": "rce distcc command-execution",
            "source": "nvd",
        }
    },
    {
        "cve_id": "CVE-2008-4250",
        "document": "Microsoft Windows SMB MS08-067 NetAPI remote code execution EternalBlue Windows XP 2003",
        "metadata": {
            "cve_id": "CVE-2008-4250",
            "service": "netbios-ssn",
            "product": "windows",
            "version_affected": "XP SP2 SP3 2003",
            "cvss_score": 10.0,
            "severity": "critical",
            "exploitation_complexity": "low",
            "requires_auth": False,
            "metasploit_module": "exploit/windows/smb/ms08_067_netapi",
            "validation_method": "smb connection fingerprint OS version",
            "evidence_needed": ["port:445", "os:windows"],
            "tags": "rce smb windows ms08-067",
            "source": "nvd",
        }
    },
    {
        "cve_id": "CVE-2017-0144",
        "document": "Microsoft Windows SMB EternalBlue MS17-010 remote code execution WannaCry",
        "metadata": {
            "cve_id": "CVE-2017-0144",
            "service": "netbios-ssn",
            "product": "windows",
            "version_affected": "Windows 7 8 10 2008 2012 2016",
            "cvss_score": 9.3,
            "severity": "critical",
            "exploitation_complexity": "low",
            "requires_auth": False,
            "metasploit_module": "exploit/windows/smb/ms17_010_eternalblue",
            "validation_method": "smb ms17-010 check auxiliary scanner",
            "evidence_needed": ["port:445", "os:windows"],
            "tags": "rce smb windows eternalblue ms17-010 wannacry",
            "source": "nvd",
        }
    },
    {
        "cve_id": "CVE-2014-0224",
        "document": "OpenSSL CCS injection SSL TLS MITM man-in-the-middle vulnerability",
        "metadata": {
            "cve_id": "CVE-2014-0224",
            "service": "ssl",
            "product": "openssl",
            "version_affected": "before 0.9.8za 1.0.0m 1.0.1h",
            "cvss_score": 6.8,
            "severity": "medium",
            "exploitation_complexity": "medium",
            "requires_auth": False,
            "metasploit_module": "",
            "validation_method": "ssl-ccs-injection nmap script",
            "evidence_needed": ["service:ssl"],
            "tags": "ssl tls mitm openssl ccs-injection",
            "source": "nvd",
        }
    },
    {
        "cve_id": "CVE-2006-3392",
        "document": "Webmin file disclosure arbitrary file read unauthorized access",
        "metadata": {
            "cve_id": "CVE-2006-3392",
            "service": "http",
            "product": "webmin",
            "version_affected": "before 1.290",
            "cvss_score": 7.8,
            "severity": "high",
            "exploitation_complexity": "low",
            "requires_auth": False,
            "metasploit_module": "auxiliary/admin/webmin/file_disclosure",
            "validation_method": "request /unauthenticated path",
            "evidence_needed": ["port:10000", "product:webmin"],
            "tags": "file-read webmin disclosure",
            "source": "nvd",
        }
    },
]


def populate_knowledge_base(kb) -> None:
    """Populate ChromaDB with seed vulnerabilities."""
    print(f"[KB] populating with {len(SEED_VULNERABILITIES)} seed vulnerabilities...")
    
    for vuln in SEED_VULNERABILITIES:
        kb.add_vulnerability(vuln)
        print(f"[KB] added {vuln['cve_id']}")
    
    print(f"[KB] done — {kb.count()} vulnerabilities in database")