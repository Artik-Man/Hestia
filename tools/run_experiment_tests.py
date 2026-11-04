"""Run every experiment unit-test module in its own Python process."""

import subprocess
import sys
import unittest
from pathlib import Path


def run_module(module: Path) -> int:
    """Load one local test module and reject an empty suite on all supported Python versions."""
    sys.path.insert(0, str(module.parent))
    suite = unittest.TestLoader().loadTestsFromName(module.stem)
    if not suite.countTestCases():
        print(f"No test cases in {module}", file=sys.stderr)
        return 1
    return int(not unittest.TextTestRunner().run(suite).wasSuccessful())


def main() -> int:
    """Discover test files, run unittest from each file's directory and fail on missing tests or any failed module."""
    script = Path(__file__).resolve()
    if len(sys.argv) == 3 and sys.argv[1] == "--module":
        return run_module(Path(sys.argv[2]).resolve())
    if len(sys.argv) != 1:
        print("Usage: run_experiment_tests.py", file=sys.stderr)
        return 2
    root = script.parents[1]
    modules = sorted(
        path for path in (root / "experiments").rglob("test_*.py") if path.is_file()
    )
    if not modules:
        print("No experiment test modules found.", file=sys.stderr)
        return 1

    failed = []
    for module in modules:
        relative = module.relative_to(root)
        print(f"Running {relative}", flush=True)
        result = subprocess.run(
            [sys.executable, "-B", str(script), "--module", str(module)],
            cwd=module.parent,
            check=False,
        )
        if result.returncode != 0:
            failed.append(relative)
    if failed:
        print(
            "Failed experiment modules: " + ", ".join(map(str, failed)), file=sys.stderr
        )
        return 1
    print(f"Passed {len(modules)} experiment test modules.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
