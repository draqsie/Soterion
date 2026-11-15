from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from soterion.runner import ToolOutcome, ToolRun, find_tool, run_tool


class TempDirTestCase(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name).resolve()


class RunTool(TempDirTestCase):
    def run_python(self, code: str, **overrides: object) -> ToolRun:
        options: dict[str, object] = {
            "cwd": self.tmp,
            "timeout_seconds": 30,
            "max_output_bytes": 1_000_000,
        }
        options.update(overrides)
        return run_tool([sys.executable, "-I", "-c", code], **options)  # type: ignore[arg-type]

    def test_returns_stdout_and_exit_code(self) -> None:
        run = self.run_python("import sys; print('hello'); sys.exit(3)")

        self.assertIs(run.outcome, ToolOutcome.EXITED)
        self.assertEqual(run.exit_code, 3)
        self.assertEqual(run.stdout.strip(), b"hello")

    def test_secrets_in_the_parent_environment_do_not_reach_the_tool(self) -> None:
        leaked = {"GITHUB_TOKEN": "not-a-real-token", "AWS_SECRET_ACCESS_KEY": "not-a-real-key"}
        with mock.patch.dict(os.environ, leaked):
            run = self.run_python("import os, json; print(json.dumps(sorted(os.environ)))")

        names = json.loads(run.stdout)
        self.assertNotIn("GITHUB_TOKEN", names)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", names)

    def test_explicitly_given_environment_reaches_the_tool(self) -> None:
        run = self.run_python(
            "import os; print(os.environ.get('SCANNER_OPTION'))", env={"SCANNER_OPTION": "off"}
        )

        self.assertEqual(run.stdout.strip(), b"off")

    def test_runs_in_the_given_working_directory(self) -> None:
        run = self.run_python("import os; print(os.path.realpath(os.getcwd()))")

        self.assertEqual(Path(run.stdout.decode().strip()), self.tmp)

    def test_standard_input_is_closed(self) -> None:
        run = self.run_python("import sys; print(len(sys.stdin.read()))")

        self.assertEqual(run.stdout.strip(), b"0")

    def test_timeout_stops_the_tool(self) -> None:
        started = time.monotonic()
        run = self.run_python("import time; time.sleep(120)", timeout_seconds=1)

        self.assertIs(run.outcome, ToolOutcome.TIMED_OUT)
        self.assertEqual(run.stdout, b"")
        self.assertLess(time.monotonic() - started, 30)

    def test_timeout_also_stops_processes_the_tool_started(self) -> None:
        heartbeat = self.tmp / "heartbeat.txt"
        child = (
            "import time\n"
            "while True:\n"
            f"    open({str(heartbeat)!r}, 'a').write('x')\n"
            "    time.sleep(0.05)\n"
        )
        parent = (
            "import subprocess, sys, time\n"
            f"subprocess.Popen([sys.executable, '-I', '-c', {child!r}])\n"
            "time.sleep(120)\n"
        )

        run = self.run_python(parent, timeout_seconds=3)
        time.sleep(0.5)
        size_after_kill = heartbeat.stat().st_size
        time.sleep(0.7)

        self.assertIs(run.outcome, ToolOutcome.TIMED_OUT)
        self.assertGreater(size_after_kill, 0)
        self.assertEqual(heartbeat.stat().st_size, size_after_kill)

    def test_output_over_the_cap_stops_the_tool_and_is_discarded(self) -> None:
        run = self.run_python(
            "import sys, time; sys.stdout.write('x' * 2_000_000); sys.stdout.flush(); time.sleep(120)",
            max_output_bytes=1000,
        )

        self.assertIs(run.outcome, ToolOutcome.OUTPUT_TOO_LARGE)
        self.assertEqual(run.stdout, b"")

    def test_executable_must_be_an_absolute_path(self) -> None:
        with self.assertRaises(ValueError):
            run_tool(["python", "-c", "pass"], cwd=self.tmp, timeout_seconds=5, max_output_bytes=10)

    def test_missing_executable_is_reported_not_raised(self) -> None:
        run = run_tool(
            [str(self.tmp / "no-such-tool.exe")],
            cwd=self.tmp,
            timeout_seconds=5,
            max_output_bytes=10,
        )

        self.assertIs(run.outcome, ToolOutcome.START_FAILED)


class FindTool(TempDirTestCase):
    def make_executable(self, directory: Path, name: str, suffix: str | None = None) -> Path:
        directory.mkdir(parents=True, exist_ok=True)
        if suffix is None:
            suffix = ".exe" if os.name == "nt" else ""
        path = directory / f"{name}{suffix}"
        path.write_bytes(b"MZ")
        path.chmod(0o755)
        return path

    def find(self, name: str, *path_entries: object, forbidden: tuple[Path, ...] = ()) -> Path | None:
        search_path = os.pathsep.join(str(entry) for entry in path_entries)
        with mock.patch.dict(os.environ, {"PATH": search_path}):
            return find_tool(name, forbidden_roots=forbidden)

    def chdir(self, directory: Path) -> None:
        previous = os.getcwd()
        self.addCleanup(os.chdir, previous)
        os.chdir(directory)

    def test_finds_an_executable_on_path(self) -> None:
        expected = self.make_executable(self.tmp / "bin", "scanner")

        self.assertEqual(self.find("scanner", self.tmp / "empty", self.tmp / "bin"), expected)

    def test_returns_none_when_not_on_path(self) -> None:
        self.make_executable(self.tmp / "elsewhere", "scanner")

        self.assertIsNone(self.find("scanner", self.tmp / "bin"))

    def test_current_directory_is_not_searched(self) -> None:
        self.make_executable(self.tmp / "cwd", "scanner")
        self.chdir(self.tmp / "cwd")

        self.assertIsNone(self.find("scanner", self.tmp / "bin"))

    def test_relative_path_entries_are_ignored(self) -> None:
        self.make_executable(self.tmp / "bin", "scanner")
        self.chdir(self.tmp)

        self.assertIsNone(self.find("scanner", "bin", "."))

    def test_tools_inside_a_forbidden_root_are_ignored(self) -> None:
        repo = self.tmp / "repo"
        self.make_executable(repo / "tools", "scanner")

        self.assertIsNone(self.find("scanner", repo / "tools", forbidden=(repo,)))

    def test_explicit_directories_are_searched_instead_of_path(self) -> None:
        expected = self.make_executable(self.tmp / "tools", "scanner")
        self.make_executable(self.tmp / "bin", "scanner")

        with mock.patch.dict(os.environ, {"PATH": str(self.tmp / "bin")}):
            found = find_tool("scanner", directories=[self.tmp / "tools"])

        self.assertEqual(found, expected)

    def test_explicit_directories_do_not_fall_back_to_path(self) -> None:
        self.make_executable(self.tmp / "bin", "scanner")
        (self.tmp / "tools").mkdir()

        with mock.patch.dict(os.environ, {"PATH": str(self.tmp / "bin")}):
            found = find_tool("scanner", directories=[self.tmp / "tools"])

        self.assertIsNone(found)

    def test_explicit_directory_inside_a_forbidden_root_is_ignored(self) -> None:
        repo = self.tmp / "repo"
        self.make_executable(repo / "tools", "scanner")

        found = find_tool("scanner", directories=[repo / "tools"], forbidden_roots=(repo,))

        self.assertIsNone(found)

    @unittest.skipUnless(os.name == "nt", "batch files are a Windows concept")
    def test_batch_files_are_not_accepted_as_tools(self) -> None:
        self.make_executable(self.tmp / "bin", "scanner", ".cmd")
        self.make_executable(self.tmp / "bin", "scanner", ".bat")

        self.assertIsNone(self.find("scanner", self.tmp / "bin"))

    def test_tool_name_must_be_a_bare_name(self) -> None:
        for name in ("../scanner", "sub/scanner", "", ".."):
            with self.subTest(name), self.assertRaises(ValueError):
                find_tool(name)


if __name__ == "__main__":
    unittest.main()
