"""Exercise diagnostic artifact provenance and fail-closed publication locally."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "diagnostic_build", Path(__file__).with_name("run.py")
)
BUILD = importlib.util.module_from_spec(SPEC)
if SPEC.loader is not None:
    SPEC.loader.exec_module(BUILD)


class BuildTests(unittest.TestCase):
    """Verify failures cannot publish misleading diagnostic artifacts."""

    def setUp(self):
        """Create isolated source files, including files outside Git's tracked set."""
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name in (
            "backend/go.mod",
            "backend/go.sum",
            "backend/cmd/hestia-keenetic-diagnostics/main.go",
            "backend/internal/keeneticdiagnostics/inventory.go",
            "scripts/build-keenetic-diagnostics/run.py",
            "scripts/build-keenetic-diagnostics/readme.md",
            "docs/features/keenetic-diagnostics.md",
        ):
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("fixture " + name)
        self.root_patch = patch.object(BUILD, "ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    @staticmethod
    def compile_fixture(source, binary, version):
        """Supply deterministic bytes instead of invoking a compiler in packaging tests."""
        binary.write_bytes(b"fixture executable")

    def test_complete_manifest_covers_untracked_sources_and_payload(self):
        """New source bytes, binary and shipped documents all receive matching hashes."""
        with (
            patch.object(BUILD, "git_metadata", return_value=("a" * 40, True)),
            patch.object(BUILD, "compile_binary", side_effect=self.compile_fixture),
        ):
            target = BUILD.build(self.root / "output", "fixture-v1")
        manifest = json.loads((target / "manifest.json").read_text())
        self.assertTrue(manifest["dirty"])
        self.assertIn(
            "backend/internal/keeneticdiagnostics/inventory.go",
            manifest["source_inputs"],
        )
        for name, digest in manifest["files"].items():
            self.assertEqual(BUILD.file_hash(target / name), digest)
        sums = (target / "SHA256SUMS").read_text()
        self.assertIn(
            BUILD.file_hash(target / "manifest.json") + "  manifest.json", sums
        )
        self.assertEqual(manifest["deployment"], "not-installed")

    def test_existing_version_is_never_overwritten(self):
        """An existing directory survives a repeated build request byte for byte."""
        target = self.root / "output/fixture-v1"
        target.mkdir(parents=True)
        (target / "marker").write_text("preserve")
        with (
            patch.object(BUILD, "git_metadata", return_value=("a" * 40, False)),
            patch.object(BUILD, "compile_binary") as compile_binary,
        ):
            with self.assertRaises(FileExistsError):
                BUILD.build(target.parent, "fixture-v1")
        compile_binary.assert_not_called()
        self.assertEqual((target / "marker").read_text(), "preserve")

    def test_source_drift_blocks_publication(self):
        """Editing an input during compilation fails instead of claiming old provenance."""

        def mutate(source, binary, version):
            """Simulate a concurrent edit after an otherwise successful compilation."""
            binary.write_bytes(b"fixture executable")
            (
                self.root / "backend/internal/keeneticdiagnostics/inventory.go"
            ).write_text("changed")

        with (
            patch.object(BUILD, "git_metadata", return_value=("a" * 40, False)),
            patch.object(BUILD, "compile_binary", side_effect=mutate),
        ):
            with self.assertRaisesRegex(RuntimeError, "changed"):
                BUILD.build(self.root / "output", "fixture-v1")
        self.assertFalse((self.root / "output/fixture-v1").exists())

    def test_compile_failure_does_not_publish(self):
        """Compiler errors leave no final version and release the version lock."""
        with (
            patch.object(BUILD, "git_metadata", return_value=("a" * 40, False)),
            patch.object(
                BUILD, "compile_binary", side_effect=RuntimeError("compiler failed")
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "compiler failed"):
                BUILD.build(self.root / "output", "fixture-v1")
        self.assertFalse((self.root / "output/fixture-v1").exists())
        self.assertFalse((self.root / "output/.fixture-v1.lock").exists())

    def test_invalid_version_cannot_escape_output(self):
        """User-provided versions cannot become paths outside the artifact directory."""
        with self.assertRaises(ValueError):
            BUILD.build(self.root / "output", "../escape")

    def test_compiler_is_offline_and_static_arm64(self):
        """Compiler arguments pin the intended target and disable automatic downloads."""
        with patch.object(BUILD.subprocess, "run") as run:
            BUILD.compile_binary(self.root, self.root / "binary", "fixture-v1")
        args, kwargs = run.call_args
        self.assertIn("main.buildVersion=fixture-v1", " ".join(args[0]))
        self.assertEqual(kwargs["env"]["CGO_ENABLED"], "0")
        self.assertEqual(kwargs["env"]["GOOS"], "linux")
        self.assertEqual(kwargs["env"]["GOARCH"], "arm64")
        self.assertEqual(kwargs["env"]["GOPROXY"], "off")
        self.assertEqual(kwargs["env"]["GOTOOLCHAIN"], "local")
        self.assertTrue(kwargs["check"])


if __name__ == "__main__":
    unittest.main()
