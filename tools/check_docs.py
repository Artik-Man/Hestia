"""Check named declarations in project sources, including tests and lab scripts."""

import ast
import json
import os
import subprocess
import sys
from pathlib import Path


def shell_functions(node: object):
    """Yield declaration line and name from the Bash AST emitted by shfmt."""
    if isinstance(node, list):
        for item in node:
            yield from shell_functions(item)
    elif isinstance(node, dict):
        if node.get("Type") == "FuncDecl":
            yield node["Pos"]["Line"], node["Name"]["Value"]
        for value in node.values():
            yield from shell_functions(value)


def main() -> int:
    """Report missing documentation with source locations and return a CI exit code."""
    names = subprocess.check_output(
        ["git", "ls-files", "-co", "--exclude-standard", "-z"]
    )
    paths = sorted({Path(os.fsdecode(name)) for name in names.split(b"\0") if name})
    go = [str(p.resolve()) for p in paths if p.suffix == ".go" and p.is_file()]
    failed = (
        subprocess.run(["go", "-C", "backend", "run", "./tools/doccheck", *go], check=False).returncode
        != 0
    )
    for path in paths:
        if not path.is_file() or path.suffix not in {".sh", ".py"}:
            continue
        source = path.read_text()
        if path.suffix == ".py":
            missing = [
                (n.lineno, n.name)
                for n in ast.walk(ast.parse(source, filename=str(path)))
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                and not ast.get_docstring(n)
            ]
        else:
            tree = subprocess.check_output(
                [os.environ.get("SHFMT", "shfmt"), "-ln", "bash", "--to-json"],
                input=source.encode(),
            )
            lines = source.splitlines()
            missing = []
            for line, name in shell_functions(json.loads(tree)):
                comment = lines[line - 2].strip() if line >= 2 else ""
                if not comment.startswith("# ") or comment.startswith("# shellcheck"):
                    missing.append((line, name))
        for line, name in missing:
            print(f"{path}:{line}: document {name}", file=sys.stderr)
            failed = True
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
