"""RAG retrieval interface and persistent Chroma-backed implementation."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from fastapi import Depends
from openai import AsyncOpenAI

from app.config import Settings, get_settings

COLLECTION_NAME = "sentinel_techniques"


@dataclass(frozen=True)
class TechniqueCandidate:
    """A retrieved MITRE ATT&CK or OWASP technique candidate."""

    technique_id: str
    name: str
    framework: str
    tactics: list[str] = field(default_factory=list)
    description: str = ""
    detection: str = ""

    def to_context_str(self) -> str:
        """Render a concise summary of the candidate for LLM prompt context."""
        parts = [f"[{self.technique_id}] {self.name} ({self.framework})"]
        if self.tactics:
            parts.append(f"Tactics: {', '.join(self.tactics)}")
        if self.description:
            clean_desc = " ".join(self.description.split())
            if len(clean_desc) > 250:
                clean_desc = clean_desc[:250] + "..."
            parts.append(f"Description: {clean_desc}")
        if self.detection:
            clean_det = " ".join(self.detection.split())
            if len(clean_det) > 150:
                clean_det = clean_det[:150] + "..."
            parts.append(f"Detection: {clean_det}")
        return "\n".join(parts)


class BaseRetriever(ABC):
    """Abstract retrieval interface so tests can inject fake retrievers."""

    @abstractmethod
    async def retrieve(
        self, query: str, top_k: int = 5
    ) -> list[TechniqueCandidate]:
        """Retrieve the top-k most relevant technique candidates for *query*."""


class ChromaRetriever(BaseRetriever):
    """Persistent Chroma store retriever using OpenAI embeddings."""

    def __init__(self, settings: Settings) -> None:
        import chromadb

        self._settings = settings
        self._openai = AsyncOpenAI(api_key=settings.openai_api_key)
        self._embedding_model = settings.embedding_model
        self._chroma = chromadb.PersistentClient(path=settings.chroma_persist_dir)

    async def retrieve(
        self, query: str, top_k: int = 5
    ) -> list[TechniqueCandidate]:
        """Embed query via OpenAI and search the Chroma collection."""
        if not query.strip():
            return []

        try:
            collection = self._chroma.get_collection(COLLECTION_NAME)
        except Exception:
            return []

        if collection.count() == 0:
            return []

        # Generate query embedding with OpenAI
        emb_res = await self._openai.embeddings.create(
            input=[query],
            model=self._embedding_model,
        )
        query_vector = emb_res.data[0].embedding

        actual_k = min(top_k, collection.count())
        results = collection.query(
            query_embeddings=[query_vector],
            n_results=actual_k,
        )

        candidates: list[TechniqueCandidate] = []
        metadatas = results.get("metadatas", [[]])[0]
        ids = results.get("ids", [[]])[0]

        for tech_id, meta in zip(ids, metadatas, strict=False):
            tactics_raw = meta.get("tactics", "")
            tactics = [t.strip() for t in tactics_raw.split(",") if t.strip()]
            candidates.append(
                TechniqueCandidate(
                    technique_id=tech_id,
                    name=meta.get("name", ""),
                    framework=meta.get("framework", "MITRE ATT&CK"),
                    tactics=tactics,
                    description=meta.get("description", ""),
                    detection=meta.get("detection", ""),
                )
            )

        return candidates


def get_retriever(settings: Settings = Depends(get_settings)) -> BaseRetriever:
    """FastAPI dependency for injecting the technique retriever."""
    return ChromaRetriever(settings)
