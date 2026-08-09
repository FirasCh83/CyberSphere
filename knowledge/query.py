import chromadb
from chromadb.utils import embedding_functions
from typing import List, Dict
from utilities.state import ReconState

class VulnKnowledgeBase:
    def __init__(self, persist_path: str = "./knowledge/db"):
        self.client = chromadb.PersistentClient(path=persist_path)

        #Local embedding
        self.embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name="all-MiniLM-L6-v2"
        )

        #Get or Create the collection
        self.collection = self.client.get_or_create_collection(
            name = "vulnerabilities",
            embedding_function=self.embedding_fn,
            metadata = {"hnsw:space": "cosine"}
        )
        print(f"[KB] loaded {self.collection.count()} vulnerabilities")

    def add_vulnerability(self, vuln: Dict) -> None:
        """
        Add a single vulnrerability to the knowledge base."""

        self.collection.upsert(
            ids = [vuln["cve_id"]],
            documents= [vuln["document"]],
            metadatas = [vuln["metadata"]],
        )

    def query_by_service(
            self,
            service: str,
            version: str = "",
            port: int = None,
            n_results: int = 10
    ) -> List[Dict]:
        """
        Semantic search for vulnreabilities matching a service.
        Returns ranked candidates with metadata
        """

        #Build search query from service context
        query_text = f"{service} {version} vulnerability exploit".strip()

        results = self.collection.query(
            query_texts = [query_text],
            n_results = min(n_results, self.collection.count() or 1),
            include = ["metadatas", "documents", "distances"]
        )
        canditates = []
        for i, metadata in enumerate(results["metadatas"][0]):
            canditates.append({
                "metadata": metadata,
                "document": results["documents"][0][i],
                "semantic_score": 1 - results["distances"][0][i],
            })
        return canditates
    
