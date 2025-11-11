from __future__ import annotations

import re
from typing import List, Tuple, Set, Optional
from app.models.schemas import Language

# Optional parser imports
_HAS_JAVALANG = False
try:
    import javalang  # type: ignore
    _HAS_JAVALANG = True
except Exception:
    _HAS_JAVALANG = False

try:
    import ast
except Exception:
    ast = None  # type: ignore


def _collect_imports_and_consts(language: Language, lines: List[str]) -> List[str]:
    res: List[str] = []
    if language == Language.JAVA:
        for ln in lines[:200]:
            s = ln.strip()
            if s.startswith('package ') or s.startswith('import '):
                res.append(ln)
        for ln in lines[:400]:
            if re.search(r"\bstatic\s+final\s+", ln):
                res.append(ln)
    else:  # PYTHON
        for ln in lines[:200]:
            s = ln.strip()
            if s.startswith('import ') or s.startswith('from '):
                res.append(ln)
        for ln in lines[:400]:
            if re.match(r"^[A-Z_][A-Z0-9_]*\s*=", ln.strip()):
                res.append(ln)
    return res


def _find_block_bounds_java(lines: List[str], target_line_1based: int) -> Tuple[int, int]:
    idx = max(0, min(len(lines) - 1, target_line_1based - 1))
    sig_re = re.compile(r"\b(public|private|protected)?\s*(static\s+)?[\w<>\[\]]+\s+\w+\s*\([^)]*\)\s*\{")
    start = None
    for i in range(idx, -1, -1):
        if sig_re.search(lines[i]):
            start = i
            break
    # If not found above, search downward for the nearest method signature
    if start is None:
        for i in range(idx + 1, len(lines)):
            if sig_re.search(lines[i]):
                start = i
                break
    if start is None:
        return max(0, idx - 30), min(len(lines) - 1, idx + 30)
    bal = 0
    for j in range(start, len(lines)):
        bal += lines[j].count('{') - lines[j].count('}')
        if bal == 0 and j > start:
            return start, j
    return start, min(len(lines) - 1, start + 80)


def _find_block_bounds_py(lines: List[str], target_line_1based: int) -> Tuple[int, int]:
    idx = max(0, min(len(lines) - 1, target_line_1based - 1))
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


def _find_block_bounds_py_ast(code: str, target_line_1based: int) -> Optional[Tuple[int, int]]:
    if ast is None:
        return None
    try:
        tree = ast.parse(code)
    except Exception:
        return None
    target_fn = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, getattr(ast, 'AsyncFunctionDef', tuple()))):
            lineno = getattr(node, 'lineno', None)
            end_lineno = getattr(node, 'end_lineno', None)
            if lineno is None:
                continue
            # If end_lineno missing, skip (fallback later)
            if end_lineno is not None and lineno <= target_line_1based <= end_lineno:
                target_fn = (lineno, end_lineno)
                break
            # If no end lineno, approximate later
            if end_lineno is None and lineno <= target_line_1based:
                # tentatively pick; keep searching for a more precise one
                target_fn = (lineno, None)
    if not target_fn:
        return None
    lines = code.splitlines()
    s = max(1, target_fn[0])
    e = target_fn[1]
    if e is None:
        # Fallback to indent-based expansion from def line
        return _find_block_bounds_py(lines, s)
    return (s, e)


def _find_block_bounds_java_javalang(code: str, target_line_1based: int) -> Optional[Tuple[int, int]]:
    if not _HAS_JAVALANG:
        return None
    try:
        tree = javalang.parse.parse(code)
    except Exception:
        return None
    # Flatten methods with starting line
    methods: List[Tuple[int, str]] = []
    try:
        for t in getattr(tree, 'types', []) or []:
            for m in getattr(t, 'methods', []) or []:
                pos = getattr(m, 'position', None)
                if pos and getattr(pos, 'line', None):
                    methods.append((pos.line, m.name))
    except Exception:
        pass
    if not methods:
        return None
    # Pick nearest method with start line <= target, otherwise the next one after target
    start_line = None
    leq = [s for s, _ in methods if s <= target_line_1based]
    if leq:
        start_line = max(leq)
    else:
        geq = [s for s, _ in methods if s >= target_line_1based]
        if geq:
            start_line = min(geq)
    if start_line is None:
        return None
    # Use brace balancing from found start line
    lines = code.splitlines()
    s_idx = max(0, start_line - 1)
    bal = 0
    end_idx = None
    for j in range(s_idx, len(lines)):
        bal += lines[j].count('{') - lines[j].count('}')
        if bal == 0 and j > s_idx:
            end_idx = j
            break
    if end_idx is None:
        end_idx = min(len(lines) - 1, s_idx + 120)
    return (s_idx + 1, end_idx + 1)


def slice_function_with_header(language: Language, code: str, target_line_1based: int) -> str:
    lines = code.splitlines()
    # Enforce parser-based slicing; no regex fallback unless absolutely necessary
    s: Optional[int] = None
    e: Optional[int] = None
    if language == Language.JAVA:
        bounds = _find_block_bounds_java_javalang(code, target_line_1based)
        if not bounds:
            raise RuntimeError("Java slicing requires javalang parser. Please install 'javalang' or provide valid code.")
        s, e = bounds
    else:
        bounds = _find_block_bounds_py_ast(code, target_line_1based)
        if not bounds:
            raise RuntimeError("Python slicing requires AST parsing. Invalid code or 'ast' unavailable.")
        s, e = bounds

    s0, e0 = max(1, s), max(1, e)
    header = _collect_imports_and_consts(language, lines)
    block = lines[s0-1:e0]
    # Avoid duplicating header lines if block already starts with import/package (simple guard)
    if language == Language.JAVA and block and (block[0].lstrip().startswith(("package ", "import "))):
        snippet_lines = block  # header likely included in block context
    elif language != Language.JAVA and block and (block[0].lstrip().startswith(("import ", "from "))):
        snippet_lines = block
    else:
        snippet_lines = header + (["// ..."] if language == Language.JAVA else ["# ..."]) + block
    snippet = "\n".join(snippet_lines)
    if len(snippet) > 4000:
        snippet = snippet[:4000] + "\n... [truncated]"
    return snippet


def find_enclosing_symbol(language: Language, code: str, target_line_1based: int) -> Optional[Tuple[str, int, int]]:
    """Return (name, start_line, end_line) of the function/method enclosing target line.
    Lines are 1-based inclusive. Parser-based only; return None if unavailable.
    """
    if language == Language.JAVA:
        if not _HAS_JAVALANG:
            return None
        try:
            tree = javalang.parse.parse(code)
        except Exception:
            return None
        # collect methods with their start line and names
        methods: List[Tuple[int, str]] = []
        try:
            for t in getattr(tree, 'types', []) or []:
                for m in getattr(t, 'methods', []) or []:
                    pos = getattr(m, 'position', None)
                    if pos and getattr(pos, 'line', None):
                        methods.append((pos.line, m.name))
        except Exception:
            return None
        if not methods:
            return None
        # choose enclosing/nearest method
        start_line = None
        method_name = None
        leq = [(s, n) for s, n in methods if s <= target_line_1based]
        if leq:
            start_line, method_name = max(leq, key=lambda x: x[0])
        else:
            geq = [(s, n) for s, n in methods if s >= target_line_1based]
            if geq:
                start_line, method_name = min(geq, key=lambda x: x[0])
        if start_line is None or method_name is None:
            return None
        # compute end via brace balancing from start
        lines = code.splitlines()
        s_idx = max(0, start_line - 1)
        bal = 0
        end_idx = None
        for j in range(s_idx, len(lines)):
            bal += lines[j].count('{') - lines[j].count('}')
            if bal == 0 and j > s_idx:
                end_idx = j
                break
        if end_idx is None:
            end_idx = min(len(lines) - 1, s_idx + 120)
        return method_name, s_idx + 1, end_idx + 1
    else:
        if ast is None:
            return None
        try:
            tree = ast.parse(code)
        except Exception:
            return None
        best = None  # (lineno, end_lineno, name)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, getattr(ast, 'AsyncFunctionDef', tuple()))):
                lineno = getattr(node, 'lineno', None)
                end_lineno = getattr(node, 'end_lineno', None)
                name = getattr(node, 'name', None)
                if lineno is None or name is None:
                    continue
                if end_lineno is not None and lineno <= target_line_1based <= end_lineno:
                    best = (lineno, end_lineno, name)
                    break
                if end_lineno is None and lineno <= target_line_1based:
                    best = (lineno, None, name)
        if not best:
            return None
        s, e, nm = best
        if e is None:
            # approximate end using indent expansion
            lines = code.splitlines()
            s_idx, e_idx = _find_block_bounds_py(lines, s)
            return nm, s_idx + 1, e_idx + 1
        return nm, s, e
