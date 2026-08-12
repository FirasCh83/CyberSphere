"""
Run this once to populate the ChromaDB knowledge base.
Seeds with curated CVEs then bulk loads from NVD.
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from knowledge.query import VulnKnowledgeBase
from knowledge.populate.seed import populate_knowledge_base, SEED_VULNERABILITIES
from knowledge.populate.nvd_loader import load_nvd_years

def run_full_population(
    years=None,
    skip_seed=False,
    cache_dir="./knowledge/cache"
):
    print("\n" + "="*60)
    print("[Cybersphere KB] starting knowledge base population")
    print("="*60)

    kb = VulnKnowledgeBase()
    print(f"\n[KB] current count: {kb.count()} vulnerabilities")

    # step 1 — seed data (always fast)
    if not skip_seed:
        print(f"\n[Step 1] loading {len(SEED_VULNERABILITIES)} seed CVEs...")
        populate_knowledge_base(kb)
        print(f"[Step 1] done — KB now has {kb.count()} vulnerabilities")
    else:
        print("[Step 1] skipping seed (already loaded)")

    # step 2 — NVD bulk load
    print(f"\n[Step 2] starting NVD bulk load...")
    print(f"[Step 2] this will take a while — downloading ~2GB of CVE data")
    print(f"[Step 2] feeds are cached locally so subsequent runs are instant\n")

    loaded = load_nvd_years(kb, years=years, cache_dir=cache_dir)

    print(f"\n[KB] POPULATION COMPLETE")
    print(f"  Total vulnerabilities: {kb.count()}")
    print(f"  NVD CVEs loaded:       {loaded}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--years", nargs="+", type=int,
        help="specific years to load e.g. --years 2020 2021 2022"
    )
    parser.add_argument(
        "--skip-seed", action="store_true",
        help="skip seed data (if already loaded)"
    )
    parser.add_argument(
        "--cache-dir", default="./knowledge/cache",
        help="directory to cache downloaded NVD feeds"
    )
    args = parser.parse_args()

    run_full_population(
        years=args.years,
        skip_seed=args.skip_seed,
        cache_dir=args.cache_dir,
    )