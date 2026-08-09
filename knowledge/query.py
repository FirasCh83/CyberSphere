import chromadb
from chromadb.utils import embedding_functions
from typing import List, Dict
from utilities.state import ReconState

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
            port = port_info["port"]
            service = port_info.get("service", "")
            version = port_info.get("version", "")

            if not service:
                continue

            # semantic search for this service
            candidates = self.query_by_service(service, version, port)

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
                if any(int(p["port"]) == int(value)
                       for p in recon_state.open_ports):
                    matched += 1

            elif key == "service":
                if value.lower() in port_info.get("service", "").lower():
                    matched += 1

            elif key == "product":
                if value.lower() in port_info.get("version", "").lower():
                    matched += 1

            elif key == "version":
                if value in port_info.get("version", ""):
                    matched += 1

            elif key == "os":
                os_guess = recon_state.os_guess or ""
                if value.lower() in os_guess.lower():
                    matched += 1

        return matched / len(needed)

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