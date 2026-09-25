"""
One-off migration: correct two mislabeled CVE ids in the already-populated
ChromaDB so the live KB matches the corrected seed.py without a full re-load.

  CVE-2010-3333 -> CVE-2010-2075   (UnrealIRCd 3.2.8.1 backdoor)
  CVE-2009-3843 -> CVE-2010-20103  (ProFTPD 1.3.3c backdoor)

Deletes the stale ids, then re-runs the (corrected) seed populate which
upserts the 10 curated CVEs — adding the correct ids. Safe to run repeatedly.
"""
import os
import sys

# make project root importable and cwd-independent so ./knowledge/db resolves
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

from knowledge.query import VulnKnowledgeBase
from knowledge.populate.seed import populate_knowledge_base

STALE_IDS = ["CVE-2010-3333", "CVE-2009-3843"]


def main():
    kb = VulnKnowledgeBase()
    before = kb.count()

    existing = kb.collection.get(ids=STALE_IDS)
    found = existing.get("ids", [])
    print(f"[migrate] stale ids present: {found or 'none'}")
    if found:
        kb.collection.delete(ids=found)
        print(f"[migrate] deleted {len(found)} stale record(s)")

    # re-run corrected seed (upsert — idempotent per cve_id)
    populate_knowledge_base(kb)

    after = kb.count()
    print(f"[migrate] count before={before} after={after}")
    # sanity: corrected ids should now exist, stale ids should not
    check = kb.collection.get(ids=["CVE-2010-2075", "CVE-2010-20103", *STALE_IDS])
    print(f"[migrate] present now: {check.get('ids', [])}")


if __name__ == "__main__":
    main()
