from __future__ import annotations

import difflib
from typing import List, Dict, Any, Optional, Tuple, Set
import re

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
try:
    import yaml  # optional for YAML sanitize
except Exception:
    yaml = None

# OS / subprocess utilities
import tempfile
import subprocess
import os


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

    # ---- Diff parsing helpers ----
    @staticmethod
    def _parse_changed_line_ranges(unified_diff: str) -> Tuple[List[Tuple[int, int]], List[Tuple[int, int]]]:
        """Parse unified diff and return list of (start,count) ranges for original and fixed.
        Returns: (orig_ranges, fixed_ranges), 1-based line numbers.
        """
        orig_ranges: List[Tuple[int, int]] = []
        fixed_ranges: List[Tuple[int, int]] = []
        for line in unified_diff.splitlines():
            if line.startswith('@@'):
                # @@ -l,s +l,s @@
                m = re.search(r"@@ -(?P<ol>\d+)(?:,(?P<oc>\d+))? \+(?P<nl>\d+)(?:,(?P<nc>\d+))? @@", line)
                if not m:
                    continue
                ol = int(m.group('ol'))
                oc = int(m.group('oc') or '1')
                nl = int(m.group('nl'))
                nc = int(m.group('nc') or '1')
                orig_ranges.append((ol, oc))
                fixed_ranges.append((nl, nc))
        return orig_ranges, fixed_ranges

    @staticmethod
    def _ranges_to_line_set(ranges: List[Tuple[int, int]]) -> Set[int]:
        s: Set[int] = set()
        for start, count in ranges:
            for i in range(start, start + max(count, 0)):
                s.add(i)
        return s

    # ---- Slicing helpers ----
    @staticmethod
    def _collect_imports_and_consts(language: Language, lines: List[str]) -> List[str]:
        res: List[str] = []
        if language == Language.JAVA:
            for ln in lines[:200]:
                if ln.strip().startswith('package ') or ln.strip().startswith('import '):
                    res.append(ln)
            # simple consts
            for ln in lines[:400]:
                if re.search(r"\bstatic\s+final\s+", ln):
                    res.append(ln)
        else:  # PYTHON
            for ln in lines[:200]:
                if ln.strip().startswith(('import ', 'from ')):
                    res.append(ln)
            for ln in lines[:400]:
                if re.match(r"^[A-Z_][A-Z0-9_]*\s*=", ln.strip()):
                    res.append(ln)
        return res

    @staticmethod
    def _find_block_bounds_java(lines: List[str], changed_line: int) -> Tuple[int, int]:
        """Return (start_idx, end_idx) 0-based inclusive indices for the method/class block containing changed_line.
        Heuristic: find nearest method signature above, then brace-balance to close.
        Fallback to window of +/- 30 lines.
        """
        idx = max(0, min(len(lines) - 1, changed_line - 1))
        sig_re = re.compile(r"\b(public|private|protected)?\s*(static\s+)?[\w<>\[\]]+\s+\w+\s*\([^)]*\)\s*\{")
        start = None
        for i in range(idx, -1, -1):
            if sig_re.search(lines[i]):
                start = i
                break
        if start is None:
            return max(0, idx - 30), min(len(lines) - 1, idx + 30)
        # brace balance from start
        bal = 0
        for j in range(start, len(lines)):
            bal += lines[j].count('{') - lines[j].count('}')
            if bal == 0 and j > start:
                return start, j
        return start, min(len(lines) - 1, start + 80)

    @staticmethod
    def _find_block_bounds_py(lines: List[str], changed_line: int) -> Tuple[int, int]:
        """Find def block spanning the changed line. Fallback to window +/- 30."""
        idx = max(0, min(len(lines) - 1, changed_line - 1))
        def_re = re.compile(r"^\s*def\s+\w+\s*\(.*\)\s*:\s*$")
        start = None
        for i in range(idx, -1, -1):
            if def_re.match(lines[i]):
                start = i
                break
        if start is None:
            return max(0, idx - 30), min(len(lines) - 1, idx + 30)
        base_indent = len(lines[start]) - len(lines[start].lstrip(' '))
        end = start + 1
        while end < len(lines):
            line = lines[end]
            if line.strip() == '':
                end += 1
                continue
            indent = len(line) - len(line.lstrip(' '))
            if indent <= base_indent:
                break
            end += 1
        return start, end - 1

    def _slice_code(self, language: Language, code: str, changed_lines: Set[int]) -> str:
        lines = code.splitlines()
        if not changed_lines:
            # fallback to whole with cap
            snippet = "\n".join(lines[:300])
        else:
            target_line = min(changed_lines)
            if language == Language.JAVA:
                s, e = self._find_block_bounds_java(lines, target_line)
            else:
                s, e = self._find_block_bounds_py(lines, target_line)
            block = lines[s:e+1]
            header = self._collect_imports_and_consts(language, lines)
            snippet = "\n".join(header + ["// ..." if language == Language.JAVA else "# ..."] + block)
        # hard cap to avoid token overflow
        if len(snippet) > 4000:
            snippet = snippet[:4000] + "\n... [truncated]"
        return snippet

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
    def generate_autofix_rule(self, request: SemgrepAutofixRuleRequest, prompt_strategy: str = "base") -> SemgrepAutofixRuleResponse:
        # 1) Prepare slices
        if request.original_slice and request.fixed_slice:
            original_slice = request.original_slice
            fixed_slice = request.fixed_slice
            sliced_unified = self._compute_unified_diff(original_slice, fixed_slice, request.filename)
        else:
            # Compute full diff first to estimate changed lines
            unified = self._compute_unified_diff(request.original_code, request.fixed_code, request.filename)
            orig_ranges, fixed_ranges = self._parse_changed_line_ranges(unified)
            orig_changed = self._ranges_to_line_set(orig_ranges)
            fixed_changed = self._ranges_to_line_set(fixed_ranges)

            # 1.1) Internal slicing (function/method + imports/constants)
            original_slice = self._slice_code(request.language, request.original_code, orig_changed)
            fixed_slice = self._slice_code(request.language, request.fixed_code, fixed_changed)
            sliced_unified = self._compute_unified_diff(original_slice, fixed_slice, request.filename)

        # 2) Retrieve Semgrep rule docs/examples (use sliced diff for better focus)
        #    If target_cwes provided, bias the retrieval by mentioning them in the query context.
        cwe_hint = getattr(request, "target_cwes", None)
        if cwe_hint:
            hint_text = f"\nTarget CWE Scope: {', '.join(f'CWE-{int(c)}' for c in cwe_hint if isinstance(c, (int, str)))}\n"
        else:
            hint_text = "\n"
        # Adjust retrieval size for RAG-enhanced strategies
        _ps = (prompt_strategy or "base").lower() if isinstance(prompt_strategy, str) else "base"
        _rag_enhanced = _ps in {"rag_boost", "combined_rag", "one_shot_rag", "cot_rag"}
        _top_k = 5 if _rag_enhanced else 3
        refs = self._retrieve_semgrep_context(request.language, (sliced_unified + hint_text), top_k=_top_k)
        rag_block = self._format_rag_block(refs)

        # 3) Build prompts
        base_system = (
            "You are a Semgrep rule authoring assistant. Generate a VALID Semgrep rule YAML with autofix for the given diff. "
            "Follow Semgrep official docs and best practices. The rule must be minimal, precise, and safe. "
            "Do NOT output anything except the YAML in a fenced code block labeled yaml."
        )
        scope_note = ""
        if cwe_hint:
            scope_note = "\n- Limit the rule scope to ONLY match vulnerabilities related to: " + \
                         ", ".join(f"CWE-{int(c)}" for c in cwe_hint if isinstance(c, (int, str))) + "\n"

        # Prompt variants
        ps = _ps
        checklist_block = (
            "\n[CHECKLIST]\n"
            "- Matches vulnerable pattern but NOT fixed form\n"
            "- Uses precise patterns with metavariables and minimal ellipses\n"
            "- Restricts scope via pattern-inside if necessary\n"
            "- Provides correct fix that transforms vulnerable into fixed\n"
            "- Validates with semgrep --validate (schema correctness)\n"
        ) if ps in {"checklist", "combined_rag", "combined"} else ""

        sample_block = (
            "\n[HINTS]\n"
            "- Prefer pattern with explicit method calls and arguments (e.g., PreparedStatement with bind)\n"
            "- Avoid generic wildcards; use metavariables like $X, $Y\n"
            "- Use pattern-inside to localize to method scope when needed\n"
        ) if ps in {"sample_injection", "combined_rag", "combined"} else ""

        cot_block = (
            "\n[METHOD]\n"
            "1) Identify vulnerable construct vs fixed construct from the diff.\n"
            "2) Design a precise Semgrep pattern capturing ONLY the vulnerable form (not the fixed one).\n"
            "3) Add pattern-inside if scope restriction is needed.\n"
            "4) Provide fix transforming it into the fixed construct.\n"
            "5) Self-check against the diff and ensure schema validity.\n"
        ) if ps in {"cot_rag", "combined_rag", "cot", "combined"} else ""

        system_prompt = base_system + checklist_block + sample_block + cot_block

        user_prompt = f"""
# Context
Language: {request.language.value}
Filename: {request.filename or 'N/A'}

## Sliced Source (original)
{original_slice}

## Sliced Source (fixed)
{fixed_slice}

## Sliced Code Diff (unified)
{sliced_unified}

## Retrieved References
{rag_block}

## Requirements
- Produce a single Semgrep rule with:
  - id, message, severity, languages, metadata (include rationale), and patterns/regexes as needed
  - autofix that transforms the vulnerable pattern to the fixed form seen in the diff
- Ensure the rule matches the vulnerable form and not the fixed form (test mentally against the diff)
- Keep the rule specific to the shown change; avoid over-broad patterns
{scope_note}

## Output Format
```yaml
# YAML only
```
"""

        # 4) Ask LLM (augment system prompt with strict rule requirements)
        system_prompt = (
            system_prompt
            + "\n\n[STRICT SEMGREP RULE REQUIREMENTS]\n"
              "- Output YAML only. No code fences. No tabs in YAML (use spaces).\n"
              "- Use keys: rules, id, message, severity, languages, metadata, patterns, pattern, pattern-inside, fix (or fix-regex).\n"
              "- Do NOT use 'autofix' key. Use 'fix'.\n"
              "- Do NOT use 'pattern-either'. Create ONE coherent 'pattern' using metavariables and ellipses '...'.\n"
              "- Restrict matches with 'pattern-inside' to the method scope if needed.\n"
              "- All Java statements inside patterns MUST be valid Java. Do not escape quotes like \"; use normal double quotes.\n"
              "- Never place ellipses as method-call arguments. Use metavariables instead, e.g., builder.parse($X) not builder.parse(...).\n"
              "- Do not insert '...' between statements if they are consecutive in the vulnerable example. Use contiguous statements.\n"
              "- Remove unsupported 'options' entries (e.g., java_version).\n"
              "- Ensure YAML validates with 'semgrep --validate'.\n"
        )

        yaml_text = self.llm.ask(system_prompt=system_prompt, user_prompt=user_prompt) or ""

        def _sanitize_yaml_schema(text: str, target_cwes: Optional[List[int]]) -> str:
            if yaml is None:
                return text
            # normalize tabs to spaces before parsing
            text = (text or "").replace("\t", "  ")
            try:
                data = yaml.safe_load(text) or {}
            except Exception:
                return text
            changed = False
            # helper: OWASP mapping by CWE
            def _map_owasp(cwe: Optional[int]) -> Optional[str]:
                if cwe is None:
                    return None
                mapping = {
                    89: "A03:2021 - Injection",
                    78: "A03:2021 - Injection",
                    611: "A05:2021 - Security Misconfiguration",
                }
                try:
                    return mapping.get(int(cwe))
                except Exception:
                    return None
            # If single rule dict, wrap into rules
            if isinstance(data, dict) and "rules" not in data:
                data = {"rules": [data]}
                changed = True
            if isinstance(data, dict) and isinstance(data.get("rules"), list):
                new_rules = []
                for r in data["rules"]:
                    if not isinstance(r, dict):
                        continue
                    # normalize id: replace invalid chars like '/' and spaces with '-'
                    rid = r.get("id")
                    if isinstance(rid, str):
                        new_id = re.sub(r"[^A-Za-z0-9_.\-]", "-", rid)
                        if new_id != rid:
                            r["id"] = new_id
                            changed = True
                    # ensure metadata exists and aligns to target CWE if provided
                    target_cwe = None
                    if target_cwes:
                        try:
                            target_cwe = int(list(target_cwes)[0])
                        except Exception:
                            target_cwe = None
                    meta = r.get("metadata")
                    if not isinstance(meta, dict):
                        meta = {}
                        r["metadata"] = meta
                        changed = True
                    if target_cwe is not None:
                        if meta.get("cwe") not in (target_cwe, f"CWE-{target_cwe}"):
                            meta["cwe"] = target_cwe
                            changed = True
                        owasp = _map_owasp(target_cwe)
                        if owasp and meta.get("owasp") != owasp:
                            meta["owasp"] = owasp
                            changed = True
                        # append cwe hint to id for clarity
                        if isinstance(r.get("id"), str) and f"cwe-{target_cwe}" not in r["id"].lower():
                            r["id"] = f"{r['id']}-cwe-{target_cwe}"
                            changed = True
                    # map autofix -> fix
                    if "autofix" in r and "fix" not in r:
                        r["fix"] = r.pop("autofix")
                        changed = True
                    # remove unknown options
                    opts = r.get("options")
                    if isinstance(opts, dict):
                        # Semgrep may not support custom options like java_version
                        if "java_version" in opts:
                            opts.pop("java_version", None)
                            if not opts:
                                r.pop("options", None)
                            changed = True
                    # collapse pattern-either entries inside patterns
                    pats = r.get("patterns")
                    if isinstance(pats, list):
                        collapsed: List[Dict[str, Any]] = []
                        for entry in pats:
                            if isinstance(entry, dict) and "pattern-either" in entry:
                                pe = entry.get("pattern-either")
                                # take first concrete pattern if available
                                rep = None
                                if isinstance(pe, list):
                                    rep = next((e for e in pe if isinstance(e, dict) and "pattern" in e), None)
                                if isinstance(rep, dict):
                                    collapsed.append({"pattern": rep.get("pattern")})
                                # else: drop and let other items handle match
                                changed = True
                                continue
                            collapsed.append(entry)
                        r["patterns"] = collapsed
                    # move top-level pattern/pattern-inside into patterns list if present
                    # and not already represented
                    tl_entries: List[Dict[str, Any]] = []
                    for k in ("pattern-inside", "pattern"):
                        if k in r and isinstance(r[k], str):
                            tl_entries.append({k: r.pop(k)})
                            changed = True
                    if tl_entries:
                        if not isinstance(r.get("patterns"), list):
                            r["patterns"] = []
                        r["patterns"] = tl_entries + r["patterns"]
                    # clean escaped quotes in pattern texts and ensure strings
                    def _clean_patterns(d: Dict[str, Any]):
                        for k in ("pattern", "pattern-inside"):
                            if k in d and isinstance(d[k], str):
                                s = d[k].replace('\"', '"')
                                # Replace illegal ellipsis as method-call argument: foo(...)->foo($X)
                                import re as _re
                                s = _re.sub(r"\(\s*\.\.\.\s*\)", "($X)", s)
                                # Remove standalone '...' lines between consecutive statements (both sides ending with ';')
                                lines = s.splitlines()
                                cleaned_lines: List[str] = []
                                for i, line in enumerate(lines):
                                    if line.strip() == "...":
                                        prev_ok = i > 0 and lines[i-1].strip().endswith(";")
                                        next_ok = i+1 < len(lines) and lines[i+1].strip().endswith(";")
                                        if prev_ok and next_ok:
                                            # skip this '...'
                                            continue
                                    cleaned_lines.append(line)
                                # Heuristic: ensure likely Java statements end with ';'
                                fixed_lines: List[str] = []
                                for ln in cleaned_lines:
                                    t = ln.rstrip()
                                    ts = t.strip()
                                    if ts and ts != "..." and not ts.endswith(";") and not ts.endswith("{") and not ts.endswith("}"):
                                        if ts.endswith(")") or ("=" in ts and not ts.startswith("//")):
                                            t = t + ";"
                                    fixed_lines.append(t)
                                s = "\n".join(fixed_lines)
                                # Close unmatched braces for pattern-inside
                                if k == "pattern-inside":
                                    opens = s.count("{")
                                    closes = s.count("}")
                                    if opens > closes:
                                        s = s + "\n" + ("}" * (opens - closes))
                                d[k] = s
                        return d
                    if isinstance(r.get("patterns"), list):
                        r["patterns"] = [_clean_patterns(x) if isinstance(x, dict) else x for x in r["patterns"]]
                    else:
                        for k in ("pattern", "pattern-inside"):
                            if k in r and isinstance(r[k], str):
                                import re as _re
                                s = r[k].replace('\"', '"')
                                s = _re.sub(r"\(\s*\.\.\.\s*\)", "($X)", s)
                                lines = s.splitlines()
                                cleaned_lines: List[str] = []
                                for i, line in enumerate(lines):
                                    if line.strip() == "...":
                                        prev_ok = i > 0 and lines[i-1].strip().endswith(";")
                                        next_ok = i+1 < len(lines) and lines[i+1].strip().endswith(";")
                                        if prev_ok and next_ok:
                                            continue
                                    cleaned_lines.append(line)
                                fixed_lines: List[str] = []
                                for ln in cleaned_lines:
                                    t = ln.rstrip()
                                    ts = t.strip()
                                    if ts and ts != "..." and not ts.endswith(";") and not ts.endswith("{") and not ts.endswith("}"):
                                        if ts.endswith(")") or ("=" in ts and not ts.startswith("//")):
                                            t = t + ";"
                                    fixed_lines.append(t)
                                s = "\n".join(fixed_lines)
                                if k == "pattern-inside":
                                    opens = s.count("{")
                                    closes = s.count("}")
                                    if opens > closes:
                                        s = s + "\n" + ("}" * (opens - closes))
                                r[k] = s
                    # prefer fix over fix-regex; if both present drop fix-regex
                    if "fix" in r and "fix-regex" in r:
                        r.pop("fix-regex", None)
                        changed = True
                    # normalize fix-regex: dict with regex + replacement
                    if "fix-regex" in r:
                        fr = r.get("fix-regex")
                        if isinstance(fr, list) and fr:
                            first = next((x for x in fr if isinstance(x, dict)), None)
                            if first:
                                val = {}
                                if "regex" in first:
                                    val["regex"] = first["regex"]
                                if "replacement" in first:
                                    val["replacement"] = first["replacement"]
                                elif "replace" in first:
                                    val["replacement"] = first["replace"]
                                r["fix-regex"] = val
                                changed = True
                        elif isinstance(fr, dict):
                            val = {}
                            if "regex" in fr:
                                val["regex"] = fr["regex"]
                            if "replacement" in fr:
                                val["replacement"] = fr["replacement"]
                            elif "replace" in fr:
                                val["replacement"] = fr["replace"]
                            r["fix-regex"] = val
                            changed = True
                    # unescape newlines in message/fix for block-friendly YAML
                    for _k in ("message", "fix"):
                        if isinstance(r.get(_k), str):
                            s = r.get(_k)
                            s2 = s.replace("\\n", "\n")
                            if s2 != s:
                                r[_k] = s2
                                changed = True
                    # filter by target_cwes if provided
                    if target_cwes:
                        meta = r.get("metadata")
                        ok = False
                        if isinstance(meta, dict):
                            c = meta.get("cwe")
                            try:
                                if isinstance(c, str) and c.upper().startswith("CWE-"):
                                    cnum = int(c.split("-", 1)[1])
                                elif isinstance(c, int):
                                    cnum = c
                                else:
                                    cnum = None
                                if cnum in set(target_cwes):
                                    ok = True
                            except Exception:
                                ok = False
                        if not ok:
                            # skip non-target rules
                            changed = True
                            continue
                    new_rules.append(r)
                data["rules"] = new_rules
            if changed:
                try:
                    return yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
                except Exception:
                    return text
            return text

        # ---- Feedback loop: validate rule with semgrep and retry on errors ----
        def _strip_yaml_fence(s: str) -> str:
            s = (s or "").strip()
            if s.startswith("```"):
                # remove fenced block
                import re as _re
                m = _re.search(r"```(?:yaml)?\s*\n(.*?)```", s, _re.DOTALL | _re.IGNORECASE)
                if m:
                    return m.group(1).strip()
            return s

        def _write_temp_rule(yaml_body: str) -> str:
            fd, path = tempfile.mkstemp(prefix="semgrep_rule_", suffix=".yaml")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(yaml_body)
            return path

        def _semgrep_validate(rule_path: str) -> Tuple[bool, str]:
            try:
                env = os.environ.copy()
                env["SEMGREP_SEND_METRICS"] = "off"
                env["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
                # Support binary override or Docker image
                semgrep_bin = env.get("SEMGREP_BIN")
                docker_image = env.get("SEMGREP_DOCKER_IMAGE") or getattr(self.settings, "SEMGREP_DOCKER_IMAGE", None)
                # Prefer validate first (faster, no code needed)
                if docker_image:
                    host_dir = os.path.dirname(rule_path)
                    base = os.path.basename(rule_path)
                    proc = subprocess.run([
                        "docker", "run", "--rm",
                        "-e", "SEMGREP_SEND_METRICS=off",
                        "-e", "SEMGREP_ENABLE_VERSION_CHECK=0",
                        "-v", f"{host_dir}:/rules",
                        docker_image,
                        "semgrep", "--validate", "--config", f"/rules/{base}"
                    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env, timeout=120)
                else:
                    bin_path = semgrep_bin or "semgrep"
                    proc = subprocess.run([
                        bin_path, "--validate", "--config", rule_path
                    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env, timeout=60)
                ok = proc.returncode == 0
                return ok, proc.stdout
            except FileNotFoundError:
                return False, "semgrep not installed or not in PATH"
            except Exception as e:
                return False, f"validation error: {e}"

        def _semgrep_scan(rule_path: str, code: str, filename: str | None) -> Tuple[bool, str]:
            try:
                # write code to a temp dir
                with tempfile.TemporaryDirectory(prefix="semgrep_scan_") as d:
                    fname = filename or "Main.java"
                    code_path = os.path.join(d, fname)
                    os.makedirs(os.path.dirname(code_path), exist_ok=True)
                    with open(code_path, "w", encoding="utf-8") as f:
                        f.write(code)
                    env = os.environ.copy()
                    env["SEMGREP_SEND_METRICS"] = "off"
                    env["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
                    semgrep_bin = env.get("SEMGREP_BIN")
                    docker_image = env.get("SEMGREP_DOCKER_IMAGE") or getattr(self.settings, "SEMGREP_DOCKER_IMAGE", None)
                    # run scan on the temp directory
                    if docker_image:
                        host_rule_dir = os.path.dirname(rule_path)
                        rule_base = os.path.basename(rule_path)
                        proc = subprocess.run([
                            "docker", "run", "--rm",
                            "-e", "SEMGREP_SEND_METRICS=off",
                            "-e", "SEMGREP_ENABLE_VERSION_CHECK=0",
                            "-v", f"{host_rule_dir}:/rules",
                            "-v", f"{d}:/code",
                            docker_image,
                            "semgrep", "scan", "--config", f"/rules/{rule_base}", "/code"
                        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env, timeout=240)
                    else:
                        bin_path = semgrep_bin or "semgrep"
                        proc = subprocess.run([
                            bin_path, "scan", "--config", rule_path, d
                        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env, timeout=180)
                    ok = proc.returncode == 0 or proc.returncode == 1  # 1 means findings
                    return ok, proc.stdout
            except FileNotFoundError:
                return False, "semgrep not installed or not in PATH"
            except Exception as e:
                return False, f"scan error: {e}"

        reasoning_logs: List[Dict[str, Any]] = []
        attempts = 0
        max_attempts = 3
        # sanitize once before loop
        initial = _strip_yaml_fence(yaml_text.strip())
        initial = _sanitize_yaml_schema(initial, getattr(request, "target_cwes", None))
        final_yaml = initial
        while attempts < max_attempts:
            attempts += 1
            body = _strip_yaml_fence(final_yaml)
            body = _sanitize_yaml_schema(body, getattr(request, "target_cwes", None))
            rule_path = _write_temp_rule(body)
            valid, out = _semgrep_validate(rule_path)
            reasoning_logs.append({"attempt": attempts, "phase": "validate", "ok": valid, "log": out})
            if not valid:
                # ask LLM to fix based on error log
                fix_prompt = (
                    "The following Semgrep rule YAML failed validation. "
                    "Fix the YAML strictly according to Semgrep's schema. Output YAML only.\n\n"
                    "Hard constraints:\n"
                    "- No code fences. No tabs; use spaces.\n"
                    "- Do NOT use 'pattern-either'. Use ONE 'pattern' with metavariables and ellipses '...'.\n"
                    "- If needed, add 'pattern-inside' to restrict method scope.\n"
                    "- Use 'fix' (not 'autofix'). Remove unsupported options.\n\n"
                    "- Never place ellipses as method-call arguments; use metavariables instead (e.g., parse($X)).\n"
                    "- Avoid '...' between consecutive statements; use contiguous statements when order is consecutive.\n\n"
                    f"Error Log:\n{out}\n\n"
                    f"Original YAML:\n```yaml\n{body}\n```"
                )
                fixed_yaml = self.llm.ask(system_prompt=system_prompt, user_prompt=fix_prompt) or final_yaml
                final_yaml = fixed_yaml.strip()
                continue

            # Optional: quick scan check on provided code (use original_code if available)
            scan_ok = True
            scan_log = ""
            if getattr(request, "original_code", None):
                scan_ok, scan_log = _semgrep_scan(rule_path, getattr(request, "original_code"), getattr(request, "filename", None))
                reasoning_logs.append({"attempt": attempts, "phase": "scan", "ok": scan_ok, "log": scan_log})
                # We don't strictly fail on scan non-zero, only if tool missing; the goal is smoke test

            # Self-Criticism refinement for selected strategies
            try:
                if ps in {"combined_rag", "cot_rag"}:
                    critique_prompt = (
                        "Critique and refine the following Semgrep rule YAML to reduce over-breadth and false positives, "
                        "without missing the vulnerable form shown in the diff. Keep output as YAML only (no fences).\n\n"
                        "Constraints:\n"
                        "- Ensure it does NOT match the fixed form in the diff.\n"
                        "- Prefer precise method/argument patterns with metavariables.\n"
                        "- Use pattern-inside to restrict scope when appropriate.\n"
                        "- Keep 'fix' accurate and minimal.\n"
                        "- Preserve Semgrep schema validity.\n\n"
                        f"Diff (sliced):\n{sliced_unified}\n\nCurrent YAML:\n```yaml\n{body}\n```"
                    )
                    refined = self.llm.ask(system_prompt=system_prompt, user_prompt=critique_prompt) or body
                    refined = _strip_yaml_fence(refined)
                    refined = _sanitize_yaml_schema(refined, getattr(request, "target_cwes", None))
                    # Validate refined
                    ref_path = _write_temp_rule(refined)
                    ref_ok, ref_log = _semgrep_validate(ref_path)
                    reasoning_logs.append({"attempt": attempts, "phase": "self_criticism_validate", "ok": ref_ok, "log": ref_log})
                    if ref_ok:
                        final_yaml = refined
                        rule_path = ref_path
                        # Optional re-scan
                        if getattr(request, "original_code", None):
                            r_ok, r_log = _semgrep_scan(ref_path, getattr(request, "original_code"), getattr(request, "filename", None))
                            reasoning_logs.append({"attempt": attempts, "phase": "self_criticism_scan", "ok": r_ok, "log": r_log})
            except Exception:
                # best-effort: ignore critique errors
                pass

            break

        return SemgrepAutofixRuleResponse(
            rule_yaml=_strip_yaml_fence(final_yaml),
            reasoning="\n\n".join(
                [f"[Attempt {r.get('attempt')}] {r.get('phase').upper()} ok={r.get('ok')}\n{r.get('log')}" for r in reasoning_logs]
            ) if reasoning_logs else None,
            retrieved_context={
                "top_k": len(refs),
                "items": refs,
            } if refs else None,
        )
