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


class _VerifyHarness(unittest.TestCase):
    """Drives cmd_release_verify against the fixture pair.

    The checked-in guard is patched out because the fixtures live under
    testdata and are deliberately not the repository's own manifest; the
    guard itself has its own test below.
    """

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


class StrictReleaseVerifyTest(_VerifyHarness):
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
        self.assertIn("no verdict", output)

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


class AcceptedOutcomeTest(_VerifyHarness):
    """A class rule admits a REVIEW / SKIPPED family, and nothing else.

    The rules exist so a forty-module REVIEW family needs one owned,
    expiring justification instead of forty. Each test below pins one
    edge of that bargain: it must cover the family, it must not cover a
    failure, it must not survive its own expiry, and it must not linger
    once the family it named is gone.
    """

    def test_class_rule_admits_a_review_family(self) -> None:
        result, output = self.verify("candidate-review.json", "rules-review.json")
        self.assertEqual(result, 0, output)
        self.assertIn("1 outcome rules", output)

    def test_class_rule_cannot_admit_a_failure(self) -> None:
        result, output = self.verify("candidate-persistent-fail.json", "rules-failed.json")
        self.assertEqual(result, 2, output)
        self.assertIn("result must be one of", output)

    def test_review_family_without_a_rule_is_rejected(self) -> None:
        result, output = self.verify("candidate-review.json")
        self.assertEqual(result, 1, output)
        self.assertIn("unexcluded non-pass", output)

    def test_rule_matching_nothing_is_rejected(self) -> None:
        result, output = self.verify("candidate-review.json", "rules-stale.json")
        self.assertEqual(result, 1, output)
        self.assertIn("accepted outcome matches no module", output)

    def test_intermittent_rule_may_match_nothing(self) -> None:
        """An intermittent rule matching nothing is the run where the
        module behaved, not a leftover.

        Some modules raise their REVIEW step only sometimes, so the run
        that comes out PASSED would otherwise block the release for the
        rule that exists to cover the other run. The exemption is opt-in
        per rule; a rule without the marker is still rejected, which the
        test above pins.
        """
        result, output = self.verify("candidate-review.json", "rules-stale-intermittent.json")
        self.assertNotIn("accepted outcome matches no module", output)
        # candidate-review.json still holds a REVIEW this manifest does
        # not admit, so the run fails on that and not on the rule.
        self.assertEqual(result, 1, output)
        self.assertIn("unexcluded non-pass", output)

    def test_expired_rule_is_rejected(self) -> None:
        result, output = self.verify("candidate-review.json", "rules-expired.json")
        self.assertEqual(result, 1, output)
        self.assertIn("expired accepted outcome", output)

    def test_class_rule_cannot_admit_an_unfinished_module(self) -> None:
        """A rule covers a verdict, and an unfinished module has none.

        The suite hands out a REVIEW result on modules that stopped
        answering — WAITING and INTERRUPTED both occur — so a rule that
        looked only at the result would let a module that never
        responded ship as a member of an accounted-for REVIEW family,
        silently and on the one gate that exists to stop it.
        """
        result, output = self.verify("candidate-stalled-review.json", "rules-review.json")
        self.assertEqual(result, 1, output)
        self.assertIn("unfinished module [plan-a] module-persistent: WAITING/REVIEW", output)
        self.assertIn("unfinished module [plan-a] module-pass: INTERRUPTED/REVIEW", output)


class UnreachableVerdictTest(_VerifyHarness):
    """A module with no verdict is admissible only under its own section.

    The point of the separate section is that "the harness could not make
    this module answer" stays countable and re-argued on a schedule,
    instead of blending into the exclusion list. These tests pin that it
    cannot be reached by any other route, that it has to describe the
    shape it actually observed, and that it disappears the moment the
    module starts answering.
    """

    def test_no_verdict_without_an_entry_is_rejected(self) -> None:
        result, output = self.verify("candidate-no-verdict.json")
        self.assertEqual(result, 1, output)
        self.assertIn("no verdict", output)

    def test_ordinary_exclusion_cannot_cover_a_missing_verdict(self) -> None:
        result, output = self.verify(
            "candidate-no-verdict.json",
            "exclusions-empty-result.json",
        )
        self.assertEqual(result, 1, output)
        self.assertIn("no verdict", output)

    def test_matching_entry_is_accepted(self) -> None:
        result, output = self.verify(
            "candidate-no-verdict.json",
            "unreachable-current.json",
        )
        self.assertEqual(result, 0, output)
        self.assertIn("1 without a reachable verdict", output)

    def test_entry_must_match_the_observed_status(self) -> None:
        result, output = self.verify(
            "candidate-no-verdict.json",
            "unreachable-wrong-status.json",
        )
        self.assertEqual(result, 1, output)
        self.assertIn("unreachable verdict changed shape", output)

    def test_entry_is_rejected_once_the_module_answers(self) -> None:
        result, output = self.verify(
            "candidate-all-pass.json",
            "unreachable-current.json",
        )
        self.assertEqual(result, 1, output)
        self.assertIn("no longer applies", output)

    def test_evidence_is_mandatory(self) -> None:
        result, output = self.verify(
            "candidate-no-verdict.json",
            "unreachable-no-evidence.json",
        )
        self.assertEqual(result, 2, output)
        self.assertIn("is missing evidence", output)

    def test_expired_entry_is_rejected(self) -> None:
        result, output = self.verify(
            "candidate-no-verdict.json",
            "unreachable-expired.json",
        )
        self.assertEqual(result, 1, output)
        self.assertIn("expired unreachable verdict", output)


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
