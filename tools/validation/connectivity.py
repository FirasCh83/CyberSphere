import socket
from typing import Dict

def run_connectivity_check(target: str, port: int, timeout: int = 5) -> Dict:
    """
    Pure Python TCP connectivity check.
    Confirms port is reachable before sending Metasploit at it.
    """
    result = {
        "target": target,
        "port": port,
        "status": "unknown",
        "banner": "",
        "error": "",
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        conn = sock.connect_ex((target, int(port)))

        if conn == 0:
            result["status"] = "open"
            # try grabbing whatever the service sends immediately
            try:
                sock.settimeout(2)
                banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
                result["banner"] = banner
            except Exception:
                pass
        else:
            result["status"] = "closed"

    except socket.timeout:
        result["status"] = "filtered"
        result["error"] = "connection timed out"
    except socket.gaierror as e:
        result["status"] = "error"
        result["error"] = f"DNS resolution failed: {e}"
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return result