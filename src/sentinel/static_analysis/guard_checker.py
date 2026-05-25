"""AST guard checker.

Scans a Python package for tool-invocation patterns that bypass sentinel.

A *guarded* tool call is any call site wrapped by the :func:`guard`
decorator (or any decorator whose dotted name ends in ``.guard``). An
*unguarded* tool call is a direct invocation of a function listed in a
deny pattern set without any guard on the enclosing scope.

The checker is deliberately conservative: it only flags patterns it can
prove statically, never guesses. CI integration is a one-liner:

    python -m sentinel.static_analysis.guard_checker src/
"""

from __future__ import annotations

import argparse
import ast
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

# Functions that must always be guarded.
_SENSITIVE_NAMES: frozenset[str] = frozenset(
    {
        "subprocess.Popen",
        "subprocess.run",
        "subprocess.call",
        "os.system",
        "os.exec",
        "os.execv",
        "os.execvp",
        "os.fork",
        "os.kill",
        "eval",
        "exec",
        "compile",
        "shutil.rmtree",
        "socket.socket",
        "open",
    }
)


@dataclass(slots=True)
class GuardViolation:
    path: Path
    line: int
    column: int
    callee: str
    message: str


class _GuardScanner(ast.NodeVisitor):
    def __init__(self, path: Path) -> None:
        self.path = path
        self.violations: list[GuardViolation] = []
        self._guarded_stack: list[bool] = [False]

    # -- helpers --------------------------------------------------------
    def _has_guard_decorator(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        for dec in node.decorator_list:
            name = _dotted(dec.func) if isinstance(dec, ast.Call) else _dotted(dec)
            if name and name.split(".")[-1] == "guard":
                return True
        return False

    # -- traversal ------------------------------------------------------
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._guarded_stack.append(self._has_guard_decorator(node))
        self.generic_visit(node)
        self._guarded_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._guarded_stack.append(self._has_guard_decorator(node))
        self.generic_visit(node)
        self._guarded_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        callee = _dotted(node.func)
        if callee and callee in _SENSITIVE_NAMES and not any(self._guarded_stack):
            self.violations.append(
                GuardViolation(
                    path=self.path,
                    line=node.lineno,
                    column=node.col_offset,
                    callee=callee,
                    message=f"unguarded sensitive call: {callee}",
                )
            )
        self.generic_visit(node)


def _dotted(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def scan_file(path: Path) -> list[GuardViolation]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except SyntaxError as exc:
        return [
            GuardViolation(
                path=path,
                line=exc.lineno or 0,
                column=exc.offset or 0,
                callee="<parse error>",
                message=f"syntax error: {exc.msg}",
            )
        ]
    scanner = _GuardScanner(path)
    scanner.visit(tree)
    return scanner.violations


def scan_paths(paths: Iterable[Path]) -> list[GuardViolation]:
    out: list[GuardViolation] = []
    for root in paths:
        if root.is_file() and root.suffix == ".py":
            out.extend(scan_file(root))
        elif root.is_dir():
            for p in root.rglob("*.py"):
                # Skip virtual envs, build outputs, tests by default.
                parts = set(p.parts)
                if any(s in parts for s in (".venv", "venv", "build", "dist", "tests")):
                    continue
                out.extend(scan_file(p))
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="sentinel-guard-check")
    p.add_argument("paths", nargs="+", type=Path)
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)

    violations = scan_paths(args.paths)
    if not args.quiet:
        for v in violations:
            print(f"{v.path}:{v.line}:{v.column}: {v.message}", file=sys.stderr)
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
