import difflib
from typing import Tuple


class DiffAnalyzer:
    """Unified Diff 분석기"""

    @staticmethod
    def generate_unified_diff(before: str, after: str, filename: str = "code") -> str:
        """Unified diff 생성"""
        diff = difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
            lineterm=""
        )
        return "".join(diff)

    @staticmethod
    def count_changes(diff_text: str) -> Tuple[int, int, int]:
        """
        변경 라인 수 계산

        Returns:
            (added_lines, removed_lines, changed_lines)
        """
        lines = diff_text.split('\n')

        added = len([l for l in lines if l.startswith('+')])
        removed = len([l for l in lines if l.startswith('-')])

        # --- +++ 헤더 제외
        if added > 0:
            added -= 1
        if removed > 0:
            removed -= 1

        changed = added + removed

        return added, removed, changed

    @classmethod
    def analyze(cls, before: str, after: str) -> dict:
        """
        전체 Diff 분석

        Returns:
            {
                "diff_text": str,
                "added_lines": int,
                "removed_lines": int,
                "changed_lines": int
            }
        """
        diff_text = cls.generate_unified_diff(before, after)
        added, removed, changed = cls.count_changes(diff_text)

        return {
            "diff_text": diff_text,
            "added_lines": added,
            "removed_lines": removed,
            "changed_lines": changed
        }
