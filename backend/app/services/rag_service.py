from typing import Dict, Any, List, Optional

from app.models.schemas import ScanRequest, PromptTechnique, SecureCodePrompt, VulnerabilityInfo
from app.services.scanning.scanner_service import ScannerService
from app.services.llm_service import LLMService
from app.core.config import get_settings

# Qdrant + Embeddings for RAG
from qdrant_client import QdrantClient
from sentence_transformers import SentenceTransformer
from langchain_upstage.embeddings import UpstageEmbeddings


class RAGService:
    """
    Minimal orchestrator that:
    1) runs scan
    2) builds prompts from aggregated results
    3) asks LLM and returns the answer
    Note: No external retrieval is performed.
    """

    def __init__(self, scanner_service: ScannerService, llm_service: LLMService | None = None):
        self.scanner_service = scanner_service
        self.llm_service = llm_service or LLMService()
        # RAG components (lazy-initialized)
        self._settings = get_settings()
        self._qdrant: Optional[QdrantClient] = None
        self._code_embed: Optional[SentenceTransformer] = None
        self._text_embed: Optional[UpstageEmbeddings] = None

    # -------------------- RAG Setup --------------------
    def _ensure_rag_clients(self):
        if self._qdrant is None:
            self._qdrant = QdrantClient(
                url=self._settings.QDRANT_URL,
                api_key=getattr(self._settings, "QDRANT_API_KEY", None),
                prefer_grpc=False,
            )
        if self._code_embed is None:
            self._code_embed = SentenceTransformer(self._settings.CODE_EMBEDDING_MODEL)
        if self._text_embed is None:
            self._text_embed = UpstageEmbeddings(model=self._settings.TEXT_EMBEDDING_MODEL)

    def _embed_code(self, text: str) -> List[float]:
        return self._code_embed.encode(text, normalize_embeddings=True, convert_to_tensor=False).tolist()

    def _embed_text(self, text: str) -> List[float]:
        return self._text_embed.embed_query(text)

    # -------------------- Retrievers --------------------
    def _retrieve_code_examples(self, language: str, cwe_id: str, description: str, code_snippet: str, top_k: int = 2) -> List[Dict[str, Any]]:
        """Query Code DB collection for similar secure patterns."""
        self._ensure_rag_clients()
        collection = getattr(self._settings, "CODE_COLLECTION_NAME", "secure_coding_knowledge_qdrant")
        query = (
            f"Detected Vulnerability: {description} (CWE-{cwe_id})\n"
            f"Language: {language}\n"
            f"Vulnerable Code Snippet:\n{code_snippet}"
        )
        vector = self._embed_code(query)
        try:
            res = self._qdrant.query_points(
                collection_name=collection,
                query=vector,
                limit=top_k,
                with_payload=True,
            )
        except Exception:
            return []
        docs = []
        for p in res.points:
            payload = p.payload or {}
            docs.append({
                "score": p.score,
                "cwe_id": payload.get("cwe_id"),
                "description": payload.get("description"),
                "language": payload.get("language"),
                "vulnerable_code": payload.get("vulnerable_code"),
                "safe_code": payload.get("safe_code"),
                "source": payload.get("source"),
            })
        return docs

    def _retrieve_text_guidelines(self, query: str, db: str, top_k: int = 2) -> List[Dict[str, Any]]:
        """Query text guideline collections (KISA/OWASP)."""
        self._ensure_rag_clients()
        # Collection names from env or sensible defaults
        kisa_col = getattr(self._settings, "KISA_TEXT_COLLECTION", None) or "kisa_text_db"
        owasp_col = getattr(self._settings, "OWASP_TEXT_COLLECTION", None) or "owasp_text_db"
        collection = kisa_col if db == "kisa" else owasp_col
        vector = self._embed_text(query)
        # For KISA, fetch more and trim (poor-man rerank placeholder)
        fetch_k = top_k * 3 if db == "kisa" else top_k
        try:
            res = self._qdrant.query_points(
                collection_name=collection,
                query=vector,
                limit=fetch_k,
                with_payload=True,
            )
        except Exception:
            return []
        docs = []
        for p in res.points:
            payload = p.payload or {}
            docs.append({
                "score": p.score,
                "page_content": payload.get("page_content"),
                "source": payload.get("source"),
                "language": payload.get("language"),
            })
        # Simple trimming
        return docs[:top_k]

    # -------------------- Formatter --------------------
    @staticmethod
    def _format_rag_sections(code_docs: List[Dict[str, Any]], kisa_docs: List[Dict[str, Any]],
                             owasp_docs: List[Dict[str, Any]]) -> str:
        def fmt_code(docs: List[Dict[str, Any]]) -> str:
            if not docs:
                return "No code examples found."
            blocks = []
            for i, d in enumerate(docs, 1):
                blocks.append(
                    f"### 🔒 Secure Code Example {i} (Rel: {d.get('score', 0):.3f})\n"
                    f"**CWE**: {d.get('cwe_id', 'N/A')} | **Lang**: {d.get('language', 'N/A')}\n\n"
                    f"**❌ Vulnerable Pattern**:\n``````\n\n"
                    f"**✅ Secure Pattern**:\n``````\n"
                )
            return "\n".join(blocks)

        def fmt_text(docs: List[Dict[str, Any]], title: str) -> str:
            if not docs:
                return f"No {title} guidelines found."
            blocks = []
            for i, d in enumerate(docs, 1):
                content = d.get("page_content") or "N/A"
                if len(content) > 2500:
                    content = content[:2500] + "\n... [truncated]"
                blocks.append(
                    f"### 📖 {title} Guideline {i} (Rel: {d.get('score', 0):.3f})\n"
                    f"**Source**: {d.get('source', 'N/A')} | **Lang**: {d.get('language', 'N/A')}\n\n"
                    f"{content}\n"
                )
            return "\n".join(blocks)

        return (
            "\n".join([
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n",
                "### 1️⃣ Secure Code Examples (Proven Patterns)\n",
                fmt_code(code_docs),
                "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n",
                "### 2️⃣ KISA Secure Coding Guidelines\n",
                fmt_text(kisa_docs, "KISA"),
                "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n",
                "### 3️⃣ OWASP Security Best Practices\n",
                fmt_text(owasp_docs, "OWASP"),
            ])
        )

    async def run_secure_fix(
        self,
        request: ScanRequest,
        technique: PromptTechnique = PromptTechnique.COMBINED,
        use_rag: bool = False,
    ) -> Dict[str, Any]:
        # 1) Scan the code
        scan_response = await self.scanner_service.scan_code(request)

        # 2) Build the prompts
        prompt: SecureCodePrompt = self.scanner_service.generate_secure_code_prompt(
            aggregated_vulnerabilities=scan_response.aggregated_vulnerabilities,
            source_code=request.source_code,
            language=scan_response.language,
            technique=technique,
        )

        # 2.5) Optionally augment system prompt with RAG sections
        if use_rag:
            code_docs_all: List[Dict[str, Any]] = []
            kisa_docs_all: List[Dict[str, Any]] = []
            owasp_docs_all: List[Dict[str, Any]] = []

            for v in scan_response.aggregated_vulnerabilities:
                cwe_id = str(v.cwe)
                desc = v.description or ""
                code_snippet = v.code_snippet or ""

                code_docs_all += self._retrieve_code_examples(
                    language=scan_response.language.value,
                    cwe_id=cwe_id,
                    description=desc,
                    code_snippet=code_snippet,
                    top_k=1,
                )

                query = f"CWE-{cwe_id} {desc}" if desc else f"CWE-{cwe_id}"
                kisa_docs_all += self._retrieve_text_guidelines(query=query, db="kisa", top_k=1)
                owasp_docs_all += self._retrieve_text_guidelines(query=desc or f"CWE-{cwe_id}", db="owasp", top_k=1)

            rag_section = self._format_rag_sections(code_docs_all, kisa_docs_all, owasp_docs_all)
            prompt = SecureCodePrompt(
                system_prompt=f"{prompt.system_prompt}\n\n{rag_section}",
                user_prompt=prompt.user_prompt,
                vulnerabilities=prompt.vulnerabilities,
                metadata=prompt.metadata,
                technique=prompt.technique,
            )

        # 3) Ask the LLM
        llm_answer = self.llm_service.ask(
            system_prompt=prompt.system_prompt,
            user_prompt=prompt.user_prompt,
        )

        # 4) Aggregate response payload
        return {
            "job_id": scan_response.job_id,
            "language": scan_response.language.value,
            "total_vulnerabilities": scan_response.total_vulnerabilities,
            "severity_summary": scan_response.severity_summary,
            "scanners_used": scan_response.scanners_used,
            "scanner_errors": scan_response.scanner_errors,
            "system_prompt": prompt.system_prompt,
            "user_prompt": prompt.user_prompt,
            "llm_response": llm_answer,
            "technique": technique.value,
            "rag_used": use_rag,
        }

