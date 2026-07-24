from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import date
from pathlib import Path
from unittest import mock

from tools.conformance import baseline


_FIXTURES = Path(__file__).parent.parent / "testdata" / "release_verify"
_REFERENCE = _FIXTURES / "reference.json"


class BaselineDiffTest(unittest.TestCase):
    def test_persistent_failure_is_not_a_regression(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            result = baseline.cmd_baseline_diff(
                str(_REFERENCE),
                str(_FIXTURES / "candidate-persistent-fail.json"),
            )
        self.assertEqual(result, 0)
        self.assertIn("regressions: 0", stdout.getvalue())


class StrictReleaseVerifyTest(unittest.TestCase):
    def verify(
        self,
        candidate: str,
        exclusions: str = "exclusions-empty.json",
    ) -> tuple[int, str]:
        output = io.StringIO()
        with (
            mock.patch.object(baseline, "_ensure_checked_in") as guard,
            redirect_stdout(output),
            redirect_stderr(output),
        ):
            result = baseline.cmd_release_verify(
                str(_REFERENCE),
                str(_FIXTURES / candidate),
                str(_FIXTURES / exclusions),
                as_of=date(2026, 7, 24),
            )
        guard.assert_called_once_with(_FIXTURES / exclusions)
        return result, output.getvalue()

    def test_all_pass_is_accepted(self) -> None:
        result, output = self.verify("candidate-all-pass.json")
        self.assertEqual(result, 0, output)
        self.assertIn("release blockers: 0", output)

    def test_exact_current_exclusion_is_accepted(self) -> None:
        result, output = self.verify(
            "candidate-persistent-fail.json",
            "exclusions-current.json",
        )
        self.assertEqual(result, 0, output)

    def test_persistent_failure_is_rejected(self) -> None:
        result, output = self.verify("candidate-persistent-fail.json")
        self.assertEqual(result, 1)
        self.assertIn("unexcluded non-pass", output)

    def test_added_module_is_rejected(self) -> None:
        result, output = self.verify("candidate-added.json")
        self.assertEqual(result, 1)
        self.assertIn("added module", output)

    def test_dropped_module_is_rejected(self) -> None:
        result, output = self.verify("candidate-dropped.json")
        self.assertEqual(result, 1)
        self.assertIn("dropped module", output)

    def test_empty_result_is_rejected_even_when_excluded(self) -> None:
        result, output = self.verify(
            "candidate-empty-result.json",
            "exclusions-empty-result.json",
        )
        self.assertEqual(result, 1)
        self.assertIn("empty status/result", output)

    def test_expired_exclusion_is_rejected(self) -> None:
        result, output = self.verify(
            "candidate-persistent-fail.json",
            "exclusions-expired.json",
        )
        self.assertEqual(result, 1)
        self.assertIn("expired exclusion", output)

    def test_changed_non_pass_does_not_match_exclusion(self) -> None:
        result, output = self.verify(
            "candidate-persistent-fail.json",
            "exclusions-empty-result.json",
        )
        self.assertEqual(result, 1)
        self.assertIn("exclusion mismatch", output)

    def test_stale_exclusion_is_rejected(self) -> None:
        result, output = self.verify(
            "candidate-all-pass.json",
            "exclusions-current.json",
        )
        self.assertEqual(result, 1)
        self.assertIn("stale exclusion", output)


class ExclusionManifestGuardTest(unittest.TestCase):
    def test_unchecked_manifest_is_an_input_error(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(output):
            result = baseline.cmd_release_verify(
                str(_REFERENCE),
                str(_FIXTURES / "candidate-all-pass.json"),
                str(_FIXTURES / "does-not-exist.json"),
                as_of=date(2026, 7, 24),
            )
        self.assertEqual(result, 2)
        self.assertIn("exclusion manifest is not checked in", output.getvalue())


if __name__ == "__main__":
    unittest.main()
