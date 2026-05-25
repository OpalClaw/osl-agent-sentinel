"""Guard checker AST coverage."""

from __future__ import annotations

import textwrap
from typing import TYPE_CHECKING

from sentinel.static_analysis.guard_checker import scan_paths

if TYPE_CHECKING:
    from pathlib import Path


def test_unguarded_subprocess_call_is_flagged(tmp_path: Path):
    src = textwrap.dedent("""
        import subprocess

        def run_thing():
            subprocess.run(["ls"])
        """).strip()
    (tmp_path / "bad.py").write_text(src)
    violations = scan_paths([tmp_path])
    assert any("subprocess.run" in v.callee for v in violations)


def test_guarded_subprocess_call_is_accepted(tmp_path: Path):
    src = textwrap.dedent("""
        import subprocess
        from some_interceptor import guard

        @guard
        def run_thing():
            subprocess.run(["ls"])
        """).strip()
    (tmp_path / "good.py").write_text(src)
    violations = scan_paths([tmp_path])
    assert violations == []
