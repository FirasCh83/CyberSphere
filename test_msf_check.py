# test_msf_check.py
from tools.validation.msf_check import run_msf_check

# test vsftpd 2.3.4 backdoor — should return "vulnerable"
print("[TEST 1] vsftpd 2.3.4 backdoor check")
result = run_msf_check(
    target="192.168.56.107",
    port=21,
    msf_module="exploit/unix/ftp/vsftpd_234_backdoor",
)
print(f"  Status: {result['status']}")
print(f"  Output: {result['output'][:200]}")
print(f"  Error: {result['error']}")