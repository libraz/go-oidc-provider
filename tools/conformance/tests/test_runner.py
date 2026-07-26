from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout
from unittest import mock

from tools.conformance import runner


def _outcome(status: str, result: str) -> runner.ModuleOutcome:
    return runner.ModuleOutcome(runner_id="rid", status=status, result=result)


class RunOneInterruptRetryTest(unittest.TestCase):
    """INTERRUPTED is a suite-side transport failure, not a verdict.

    The suite reports it when its own call to the OP could not be made at
    all — the JWKS fetch or the PAR post failed to connect. Docker's host
    bridge produces one or two of those per 271-module baseline, so the
    runner retries them; what these tests pin is that the retry is exactly
    one attempt, that it applies to nothing else, and that it stays
    visible in the outcome.
    """

    def test_interrupt_is_retried_once_and_a_pass_is_kept(self) -> None:
        attempts = [_outcome("INTERRUPTED", "FAILED"), _outcome("FINISHED", "PASSED")]
        stdout = io.StringIO()
        with mock.patch.object(runner, "_run_once", side_effect=attempts) as run_once:
            with redirect_stdout(stdout):
                out = runner.run_one("plan", "some-module")

        self.assertEqual(run_once.call_count, 2)
        self.assertEqual((out.status, out.result), ("FINISHED", "PASSED"))
        self.assertEqual(out.attempts, 2)
        self.assertIn("retry 1/1", stdout.getvalue())

    def test_persistent_interrupt_is_reported_not_hidden(self) -> None:
        attempts = [_outcome("INTERRUPTED", "FAILED"), _outcome("INTERRUPTED", "FAILED")]
        stdout = io.StringIO()
        with mock.patch.object(runner, "_run_once", side_effect=attempts) as run_once:
            with redirect_stdout(stdout):
                out = runner.run_one("plan", "some-module")

        # Two attempts, not three: the retry budget is one, so a module
        # that is genuinely broken still surfaces as INTERRUPTED rather
        # than being retried until it happens to pass.
        self.assertEqual(run_once.call_count, 2)
        self.assertEqual((out.status, out.result), ("INTERRUPTED", "FAILED"))
        self.assertEqual(out.attempts, 2)

    def test_a_failure_is_not_retried(self) -> None:
        stdout = io.StringIO()
        with mock.patch.object(
            runner, "_run_once", return_value=_outcome("FINISHED", "FAILED")
        ) as run_once:
            with redirect_stdout(stdout):
                out = runner.run_one("plan", "some-module")

        # FINISHED/FAILED is the suite's judgement on this OP. Re-running
        # it would be asking the same question until a different answer
        # arrives, which is how a real defect gets papered over.
        self.assertEqual(run_once.call_count, 1)
        self.assertEqual(out.attempts, 1)
        self.assertEqual(stdout.getvalue(), "")

    def test_a_pass_is_not_retried(self) -> None:
        with mock.patch.object(
            runner, "_run_once", return_value=_outcome("FINISHED", "PASSED")
        ) as run_once:
            out = runner.run_one("plan", "some-module")

        self.assertEqual(run_once.call_count, 1)
        self.assertEqual(out.attempts, 1)


class BatchRetryReportingTest(unittest.TestCase):
    def test_summary_counts_and_names_retried_modules(self) -> None:
        retried = _outcome("FINISHED", "PASSED")
        retried.attempts = 2
        stdout = io.StringIO()
        with mock.patch.object(
            runner, "run_one", side_effect=[retried, _outcome("FINISHED", "PASSED")]
        ):
            with redirect_stdout(stdout):
                code = runner.cmd_batch("plan", ["flaky-module", "steady-module"])

        out = stdout.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("pass=2", out)
        self.assertIn("retried=1", out)
        self.assertIn("retried after an interrupt: flaky-module (2 attempts)", out)
        self.assertNotIn("steady-module (", out)


if __name__ == "__main__":
    unittest.main()
