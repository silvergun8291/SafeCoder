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
        docs: List[Dict[str, Any]] = []
        for p in res.points:
            payload = p.payload or {}
            item = {
                "score": p.score,
                "cwe_id": payload.get("cwe_id"),
                "description": payload.get("description"),
                "language": payload.get("language"),
                "vulnerable_code": payload.get("vulnerable_code"),
                "safe_code": payload.get("safe_code"),
                "source": payload.get("source"),
            }
            # Simple reranking: prefer matching language and presence of secure pattern
            bonus = 0.0
            if (item.get("language") or "").lower() == (language or "").lower():
                bonus += 0.05
            if item.get("safe_code"):
                bonus += 0.05
            if item.get("vulnerable_code") and not item.get("safe_code"):
                bonus -= 0.02
            item["score"] = float(item["score"] or 0) + bonus
            docs.append(item)
        # sort by adjusted score desc
        docs.sort(key=lambda d: d.get("score", 0), reverse=True)
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
        docs: List[Dict[str, Any]] = []
        for p in res.points:
            payload = p.payload or {}
            content = payload.get("page_content")
            item = {
                "score": p.score,
                "page_content": content,
                "source": payload.get("source"),
                "language": payload.get("language"),
            }
            # KISA usefulness filter
            if db == "kisa" and not self._is_useful_kisa_chunk(content or ""):
                continue
            # Keyword-based reranking for KISA (and lightly for OWASP)
            bonus = self._keyword_bonus(content or "", query)
            code_signal = self._code_signal_bonus(content or "")
            safe_signal = self._safe_pattern_bonus(content or "")
            item["score"] = float(item["score"] or 0) + bonus + code_signal + safe_signal
            docs.append(item)
        # sort and trim
        docs.sort(key=lambda d: d.get("score", 0), reverse=True)
        return docs[:top_k]

    @staticmethod
    def _is_useful_kisa_chunk(text: str) -> bool:
        t = (text or "").strip()
        if len(t) < 300:
            return False
        import re
        csharp_patterns = [
            r"SqlConnection", r"SqlCommand", r"EventArgs",
            r"string\s+usrinput", r"Request\[", r"Request\.Write",
            r"AntiXss", r"Sanitizer\.Get"
        ]
        if sum(1 for p in csharp_patterns if re.search(p, t)) >= 2:
            return False
        if len(re.findall(r"\n\d+\.\s+[^\n]{5,80}", t)) >= 5:
            return False
        return True

    @staticmethod
    def _keyword_bonus(content: str, query: str) -> float:
        c = (content or "").lower()
        q = (query or "").lower()
        score = 0.0
        keywords = {
            "sql": ["preparedstatement", "setstring", "parameter", "binding", "?", "sanitize", "escape"],
            "xss": ["encode", "escape", "sanitize", "html", "filter"],
            "file": ["file", "mime", "extension", "validate"],
        }
        if "sql" in q:
            for kw in keywords["sql"]:
                if kw in c:
                    score += 0.03
        elif "xss" in q:
            for kw in keywords["xss"]:
                if kw in c:
                    score += 0.03
        else:
            for group in keywords.values():
                for kw in group:
                    if kw in c:
                        score += 0.01
        return score

    @staticmethod
    def _code_signal_bonus(content: str) -> float:
        c = (content or "").lower()
        indicators = ["def ", "import ", "class ", "try:", "except:", "cursor", "preparedstatement"]
        cnt = sum(1 for token in indicators if token in c)
        if cnt >= 4:
            return 0.07
        if cnt >= 2:
            return 0.04
        return 0.0

    @staticmethod
    def _safe_pattern_bonus(content: str) -> float:
        c = (content or "").lower()
        patterns = ["parameterized", "prepared", "binding", "sanitize", "encode", "escape"]
        return 0.03 if any(p in c for p in patterns) else 0.0

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

            # Strengthened directive ensuring strict adherence (generic, non-specific)
            directive = (
                "IMPORTANT: Strictly follow the retrieved security guidelines and secure code examples. "
                "If any conflict arises, the priority order is: KISA > OWASP > Code Examples. "
                "Never introduce hard-coded secrets or unsafe dynamic execution. Validate and allowlist external inputs, "
                "apply secure defaults with robust error handling, and ensure full compliance with OWASP/CWE best practices."
            )
            rag_section = directive + "\n\n" + self._format_rag_sections(code_docs_all, kisa_docs_all, owasp_docs_all)
            prompt = SecureCodePrompt(
                system_prompt=f"{prompt.system_prompt}\n\n{rag_section}",
                user_prompt=prompt.user_prompt,
                vulnerabilities=prompt.vulnerabilities,
                metadata=prompt.metadata,
                technique=prompt.technique,
            )

        # 3) Ask the LLM (async)
        llm_answer = await self.llm_service.ask_async(
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

