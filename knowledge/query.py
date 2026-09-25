import chromadb
import json
import re
from chromadb.utils import embedding_functions
from typing import List, Dict, Optional
from utilities.state import ReconState


def _port_of(entry) -> int:
    """Extract a numeric port from either the dict shape or a plain int/str."""
    if isinstance(entry, dict):
        return int(entry["port"])
    return int(entry)


def _parse_version(text: str) -> Optional[tuple]:
    """Pull the first dotted numeric version out of free text → tuple of ints.

    'Apache httpd 2.4.49 ((Unix))' -> (2, 4, 49). Returns None if none found,
    so callers can treat 'unknown version' as 'can't decide' rather than a
    false mismatch.
    """
    if not text:
        return None
    m = re.search(r"(\d+(?:\.\d+){1,3})", str(text))
    if not m:
        return None
    try:
        return tuple(int(x) for x in m.group(1).split("."))
    except ValueError:
        return None


def _version_in_range(detected: tuple, rng: dict) -> Optional[bool]:
    """Is `detected` inside the CPE version range from NVD metadata?

    Returns True/False, or None when the range carries no usable bounds (so the
    caller stays neutral instead of penalising). Bounds come straight from the
    NVD 2.0 cpeMatch fields the loader preserved.
    """
    lo_inc = _parse_version(rng.get("version_start_including", ""))
    lo_exc = _parse_version(rng.get("version_start_excluding", ""))
    hi_inc = _parse_version(rng.get("version_end_including", ""))
    hi_exc = _parse_version(rng.get("version_end_excluding", ""))
    if not any([lo_inc, lo_exc, hi_inc, hi_exc]):
        return None

    if lo_inc is not None and detected < lo_inc:
        return False
    if lo_exc is not None and detected <= lo_exc:
        return False
    if hi_inc is not None and detected > hi_inc:
        return False
    if hi_exc is not None and detected >= hi_exc:
        return False
    return True


class VulnKnowledgeBase:
    def __init__(self, persist_path: str = "./knowledge/db"):
        self.client = chromadb.PersistentClient(path=persist_path)
        
        # local embeddings — no API needed
        self.embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name="all-MiniLM-L6-v2"
        )
        
        # get or create collection
        self.collection = self.client.get_or_create_collection(
            name="vulnerabilities",
            embedding_function=self.embedding_fn,
            metadata={"hnsw:space": "cosine"}
        )
        
        print(f"[KB] loaded {self.collection.count()} vulnerabilities")

    def add_vulnerability(self, vuln: Dict) -> None:
        """Add a single vulnerability to the knowledge base."""
        self.collection.upsert(
            ids=[vuln["cve_id"]],
            documents=[vuln["document"]],
            metadatas=[vuln["metadata"]]
        )

    def query_by_service(
        self,
        service: str,
        version: str = "",
        port: int = None,
        n_results: int = 10
    ) -> List[Dict]:
        """
        Semantic search for vulnerabilities matching a service.
        Returns ranked candidates with metadata.
        """

        # Enrich query with known service aliases
        service_aliases = {
                    "netbios-ssn": "samba smb windows file sharing",
        "netbios-ns": "samba smb netbios",
        "ajp13": "tomcat apache jserv",
        "java-rmi": "java rmi registry",
        "bindshell": "backdoor shell root",
        "domain": "dns bind nameserver",
        }

        enriched_service = service_aliases.get(service.lower(), service)
        


        # build search query from service context
        query_text = f"{enriched_service} {version} vulnerability exploit".strip()

        total = self.collection.count()
        if total == 0:
            return []
        
        results = self.collection.query(
            query_texts=[query_text],
            n_results=total,
            include=["documents", "metadatas", "distances"]
        )

        candidates = []
        for i, metadata in enumerate(results["metadatas"][0]):
            candidates.append({
                "metadata": metadata,
                "document": results["documents"][0][i],
                "semantic_score": 1 - results["distances"][0][i],
            })

        return candidates

    def match_against_recon(self, recon_state: ReconState) -> List[Dict]:
        """
        Core method — match knowledge base against full recon state.
        Returns candidates scored by both semantic similarity + evidence match.
        """
        all_candidates = []
        # Key by cve and port combination instead of cve only to avoid duplicates when the same CVE is matched on multiple ports
        seen = set()

        for port_info in recon_state.open_ports:
            # tolerate plain int/str entries alongside the normal dict shape
            if isinstance(port_info, dict):
                port = port_info["port"]
                service = port_info.get("service", "")
                version = port_info.get("version", "")
            else:
                port = port_info
                service = ""
                version = ""

            if not service:
                continue

            # semantic search for this service
            candidates = self.query_by_service(service, version, port)
            candidates = candidates[:3]

            for candidate in candidates:
                cve_id = candidate["metadata"].get("cve_id", "")

                # Create a unique key for the combination of CVE and port
                key = f"{cve_id}:{port}"
                
                # skip duplicates
                if key in seen:
                    continue
                seen.add(key)

                # score evidence match deterministically
                evidence_score = self._score_evidence(
                    candidate["metadata"],
                    recon_state,
                    port_info
                )

                # combined score
                combined_score = (
                    candidate["semantic_score"] * 0.4 +
                    evidence_score * 0.6      # evidence match weighted higher
                )

                candidate["evidence_score"] = evidence_score
                candidate["combined_score"] = combined_score
                candidate["matched_port"] = port
                candidate["matched_service"] = service
                candidate["matched_version"] = version
                all_candidates.append(candidate)

        # sort by combined score
        all_candidates.sort(key=lambda x: x["combined_score"], reverse=True)
        return all_candidates

    def _score_evidence(
        self,
        metadata: Dict,
        recon_state: ReconState,
        port_info: Dict
    ) -> float:
        """
        Deterministic evidence matching.
        Returns 0.0 - 1.0 based on how much evidence aligns.
        """
        needed = metadata.get("evidence_needed", [])
        if not needed:
            return 0.5  # no evidence requirements — neutral score

        matched = 0
        for evidence in needed:
            try:
                key, value = evidence.split(":", 10)
            except ValueError:
                continue

            if key == "port":
                if any(int(_port_of(p)) == int(value)
                       for p in recon_state.open_ports):
                    matched += 1

            elif key == "service":
                if isinstance(port_info, dict) and value.lower() in port_info.get("service", "").lower():
                    matched += 1

            elif key == "product":
                if isinstance(port_info, dict) and value.lower() in port_info.get("version", "").lower():
                    matched += 1

            elif key == "version":
                if isinstance(port_info, dict) and value in port_info.get("version", ""):
                    matched += 1

            elif key == "os":
                os_guess = recon_state.os_guess or ""
                if value.lower() in os_guess.lower():
                    matched += 1

        score = matched / len(needed)
        product_meta = metadata.get("product", "").lower()
        port_version = (port_info.get("version", "") if isinstance(port_info, dict) else "").lower()

        if product_meta and port_version:
            meta_words = set(product_meta.split())
            version_words = set(port_version.replace("/", " ").split())
            if meta_words and version_words and not meta_words & version_words:
                score *= 0.8  # soft penalty if product/version mismatch

        # version-range gate — the strongest signal for bulk NVD entries. These
        # carry CPE version bounds (versionStart*/versionEnd*), so if we actually
        # detected a version on the port we can tell whether this CVE even applies
        # to that build. Out-of-range → hard penalty (kills modern CVEs matched to
        # ancient services on port/keyword alone); in-range → confidence boost.
        detected = _parse_version(port_version)
        raw_range = metadata.get("version_range", "")
        if detected is not None and raw_range and raw_range not in ("{}", "null"):
            try:
                rng = json.loads(raw_range)
            except (TypeError, ValueError):
                rng = {}
            verdict = _version_in_range(detected, rng) if rng else None
            if verdict is False:
                score *= 0.25          # affected range excludes this build
            elif verdict is True:
                score = min(1.0, score + 0.25)  # confirmed in affected range

        return score

    def get_high_confidence_candidates(
        self,
        recon_state: ReconState,
        min_score: float = 0.6
    ) -> List[Dict]:
        """
        Returns only candidates above confidence threshold.
        These go to active validation layer.
        """
        all_candidates = self.match_against_recon(recon_state)
        return [c for c in all_candidates if c["combined_score"] >= min_score]

    def count(self) -> int:
        return self.collection.count()