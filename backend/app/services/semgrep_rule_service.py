from __future__ import annotations

import difflib
from typing import List, Dict, Any, Optional

from app.core.config import get_settings
from app.models.schemas import (
    SemgrepAutofixRuleRequest,
    SemgrepAutofixRuleResponse,
    Language,
)
from app.services.llm_service import LLMService

# RAG: Qdrant + Upstage embeddings
from qdrant_client import QdrantClient
from langchain_upstage.embeddings import UpstageEmbeddings


class SemgrepRuleService:
    """
    Generate Semgrep autofix rules by:
    1) computing diff between original and fixed code
    2) retrieving Semgrep autofix rule docs/examples from Qdrant (semgrep_rule_db)
    3) prompting LLM to synthesize a valid rule YAML (with autofix)
    """

    def __init__(self, llm: Optional[LLMService] = None):
        self.settings = get_settings()
        self.llm = llm or LLMService()

        # RAG clients
        self.qdrant = QdrantClient(
            url=self.settings.QDRANT_URL,
            api_key=getattr(self.settings, "QDRANT_API_KEY", None),
            prefer_grpc=False,
        )
        self.embedder = UpstageEmbeddings(model=self.settings.TEXT_EMBEDDING_MODEL)
        self.semgrep_collection = getattr(self.settings, "SEMGREP_RULE_COLLECTION", None) or "semgrep_rule_db"

    # ----------------- Utilities -----------------
    @staticmethod
    def _compute_unified_diff(original: str, fixed: str, filename: str | None = None) -> str:
        a = original.splitlines(keepends=False)
        b = fixed.splitlines(keepends=False)
        diff_lines = list(
            difflib.unified_diff(
                a, b,
                fromfile=f"a/{filename or 'original'}",
                tofile=f"b/{filename or 'fixed'}",
                lineterm=""
            )
        )
        return "\n".join(diff_lines)

    def _retrieve_semgrep_context(self, language: Language, diff_text: str, top_k: int = 3) -> List[Dict[str, Any]]:
        query = f"Language: {language.value}\nDiff:\n{diff_text[:2000]}"
        vec = self.embedder.embed_query(query)
        try:
            result = self.qdrant.query_points(
                collection_name=self.semgrep_collection,
                query=vec,
                limit=top_k,
                with_payload=True,
            )
        except Exception:
            return []

        docs: List[Dict[str, Any]] = []
        for p in result.points:
            payload = p.payload or {}
            docs.append({
                "score": p.score,
                "title": payload.get("title"),
                "page_content": payload.get("page_content"),
                "rule_yaml": payload.get("rule_yaml"),
                "source": payload.get("source"),
            })
        return docs

    @staticmethod
    def _format_rag_block(docs: List[Dict[str, Any]]) -> str:
        if not docs:
            return "No Semgrep autofix references found."
        blocks = []
        for i, d in enumerate(docs, 1):
            content = d.get("page_content") or d.get("rule_yaml") or ""
            if len(content) > 2500:
                content = content[:2500] + "\n... [truncated]"
            title = d.get("title") or "Semgrep Reference"
            blocks.append(
                f"""### 📚 Reference {i} (Rel: {d.get('score', 0):.3f})\n"""
                f"**Title**: {title}\n**Source**: {d.get('source','N/A')}\n\n"
                f"{content}\n"
            )
        return "\n".join(blocks)

    # ----------------- Public API -----------------
    def generate_autofix_rule(self, request: SemgrepAutofixRuleRequest) -> SemgrepAutofixRuleResponse:
        # 1) Diff
        unified = self._compute_unified_diff(request.original_code, request.fixed_code, request.filename)

        # 2) Retrieve Semgrep rule docs/examples
        refs = self._retrieve_semgrep_context(request.language, unified, top_k=3)
        rag_block = self._format_rag_block(refs)

        # 3) Build prompts
        system_prompt = (
            "You are a Semgrep rule authoring assistant. Generate a VALID Semgrep rule YAML with autofix for the given diff. "
            "Follow Semgrep official docs and best practices. The rule must be minimal, precise, and safe. "
            "Do NOT output anything except the YAML in a fenced code block labeled yaml."
        )
        user_prompt = f"""
# Context
Language: {request.language.value}
Filename: {request.filename or 'N/A'}

## Code Diff (unified)
{unified}

## Retrieved References
{rag_block}

## Requirements
- Produce a single Semgrep rule with:
  - id, message, severity, languages, metadata (include rationale), and patterns/regexes as needed
  - autofix that transforms the vulnerable pattern to the fixed form seen in the diff
- Ensure the rule matches the vulnerable form and not the fixed form (test mentally against the diff)
- Keep the rule specific to the shown change; avoid over-broad patterns

## Output Format
```yaml
# YAML only
```
"""

        # 4) Ask LLM
        yaml_text = self.llm.ask(system_prompt=system_prompt, user_prompt=user_prompt) or ""

        return SemgrepAutofixRuleResponse(
            rule_yaml=yaml_text.strip(),
            reasoning=None,
            retrieved_context={
                "top_k": len(refs),
                "items": refs,
            } if refs else None,
        )
