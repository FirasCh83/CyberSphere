import socket
import re
from typing import Dict

# service-specific probes — some services need a nudge to send their banner
SERVICE_PROBES = {
    21:   b"",                          # FTP sends banner immediately
    22:   b"",                          # SSH sends banner immediately
    25:   b"",                          # SMTP sends banner immediately
    80:   b"HEAD / HTTP/1.0\r\n\r\n",  # HTTP needs a request
    443:  b"HEAD / HTTP/1.0\r\n\r\n",
    3306: b"",                          # MySQL sends banner immediately
    5432: b"",                          # PostgreSQL sends immediately
    6667: b"",                          # IRC sends banner immediately
    8009: b"",                          # AJP — won't respond to raw
    8180: b"HEAD / HTTP/1.0\r\n\r\n",
}

def run_banner_grab(target: str, port: int, timeout: int = 5) -> Dict:
    """
    Grab service banner to confirm exact version.
    Cross-references against expected version from RAG candidate.
    """
    result = {
        "target": target,
        "port": port,
        "raw_banner": "",
        "version_detected": "",
        "error": "",
    }

    probe = SERVICE_PROBES.get(int(port), b"")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, int(port)))

        # send probe if needed
        if probe:
            sock.sendall(probe)

        # receive banner
        banner = b""
        sock.settimeout(2)
        try:
            while True:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                banner += chunk
                if len(banner) > 4096:  # don't read forever
                    break
        except socket.timeout:
            pass  # timeout is fine — we have what we got

        result["raw_banner"] = banner.decode("utf-8", errors="replace").strip()
        result["version_detected"] = _extract_version(result["raw_banner"], port)

    except socket.timeout:
        result["error"] = "connection timed out"
    except ConnectionRefusedError:
        result["error"] = "connection refused"
    except Exception as e:
        result["error"] = str(e)
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return result


def _extract_version(banner: str, port: int) -> str:
    """Extract version string from common banner formats."""
    if not banner:
        return ""

    patterns = [
        # FTP: 220 (vsFTPd 2.3.4)
        r"220[- ].*?(\d+\.\d+[\.\d]*)",
        # SSH: SSH-2.0-OpenSSH_4.7p1
        r"SSH-\d+\.\d+-(\S+)",
        # SMTP: 220 hostname ESMTP Postfix
        r"220.*?ESMTP\s+(\S+)",
        # HTTP Server header
        r"Server:\s*(.+?)[\r\n]",
        # MySQL: version in first 5 bytes after handshake
        r"(\d+\.\d+\.\d+[\w-]*)",
        # IRC: :server 004 version
        r"004\s+\S+\s+(\S+)",
        # Generic version pattern
        r"[Vv]ersion[:\s]+(\d+[\.\d]+)",
    ]

    for pattern in patterns:
        match = re.search(pattern, banner)
        if match:
            return match.group(1).strip()

    # return first line if no pattern matched
    return banner.splitlines()[0][:100] if banner else ""


def version_matches(detected: str, expected: str) -> bool:
    """
    Check if detected version matches expected from RAG.
    Handles partial matches e.g. '2.3.4' matches 'vsftpd 2.3.4'
    """
    if not detected or not expected:
        return False
    return expected.lower() in detected.lower() or detected.lower() in expected.lower()